package top

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const maxMonitorEvents = 12

// MonitorEvent is a bounded, privacy-safe state transition derived from two
// dashboard views. It is not a raw kernel event and contains no internal
// request, process, or cgroup identity.
type MonitorEvent struct {
	ObservedAtUTC time.Time
	Severity      string
	Subject       string
	Message       string
}

type eventTracker struct {
	previous    View
	initialized bool
	events      []MonitorEvent
}

// Update builds update from validated inputs.
func (tracker *eventTracker) Update(view View) []MonitorEvent {
	if !tracker.initialized {
		tracker.add(view.ObservedAtUTC, "info", "host", "monitoring window collected")
		for _, row := range rowsByName(view.Rows) {
			if row.Pressure == "high" {
				tracker.add(view.ObservedAtUTC, "warning", row.Name, "QEMU write pressure is high")
			}
		}
		tracker.addAttributionState(view)
		if dominant, ok := dominantAttributedVM(view); ok {
			tracker.add(view.ObservedAtUTC, "info", dominant.Name,
				fmt.Sprintf("dominant attributed I/O: %d operations, p95~%.3f ms", dominant.AttributedOps, dominant.LatencyP95MS))
		}
		tracker.previous = view
		tracker.initialized = true
		return tracker.snapshot()
	}

	previousRows := make(map[string]VMRow, len(tracker.previous.Rows))
	for _, row := range tracker.previous.Rows {
		previousRows[row.Name] = row
	}
	for _, row := range rowsByName(view.Rows) {
		previous, exists := previousRows[row.Name]
		if !exists {
			tracker.add(view.ObservedAtUTC, "info", row.Name, "VM became visible in the local monitor")
			continue
		}
		if previous.State != row.State {
			tracker.add(view.ObservedAtUTC, "info", row.Name,
				fmt.Sprintf("VM runtime state changed from %s to %s", safeVMState(previous.State), safeVMState(row.State)))
		}
		if !previous.Running || !row.Running {
			continue
		}
		if previous.Pressure == row.Pressure {
			continue
		}
		severity := "info"
		if row.Pressure == "high" {
			severity = "warning"
		}
		tracker.add(view.ObservedAtUTC, severity, row.Name,
			fmt.Sprintf("QEMU write pressure changed from %s to %s", safeEventState(previous.Pressure), safeEventState(row.Pressure)))
	}
	currentRows := make(map[string]struct{}, len(view.Rows))
	for _, row := range view.Rows {
		currentRows[row.Name] = struct{}{}
	}
	for _, row := range rowsByName(tracker.previous.Rows) {
		if _, exists := currentRows[row.Name]; !exists {
			tracker.add(view.ObservedAtUTC, "info", row.Name, "VM is no longer visible in the local monitor")
		}
	}

	if attributionState(tracker.previous.Attribution) != attributionState(view.Attribution) {
		tracker.addAttributionState(view)
	}
	previousDominant, previousOK := dominantAttributedVM(tracker.previous)
	dominant, dominantOK := dominantAttributedVM(view)
	if dominantOK && (!previousOK || dominant.Name != previousDominant.Name) {
		tracker.add(view.ObservedAtUTC, "info", dominant.Name,
			fmt.Sprintf("dominant attributed I/O: %d operations, p95~%.3f ms", dominant.AttributedOps, dominant.LatencyP95MS))
	}

	tracker.previous = view
	return tracker.snapshot()
}

// safeVMState derives stable operator-facing text for safe VM state.
func safeVMState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "running", "shut off", "shutoff", "stopped", "paused", "pmsuspended", "crashed", "blocked":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

// addAttributionState adds attribution state to the current aggregate.
func (tracker *eventTracker) addAttributionState(view View) {
	attribution := view.Attribution
	switch {
	case !attribution.Requested:
		tracker.add(view.ObservedAtUTC, "info", "eBPF", "VM attribution was not requested")
	case !attribution.CollectorAvailable:
		tracker.add(view.ObservedAtUTC, "warning", "eBPF",
			fmt.Sprintf("VM attribution collector is unavailable (%s)", safeEventState(attribution.Status)))
	case attribution.AttributionAvailable:
		tracker.add(view.ObservedAtUTC, "info", "eBPF",
			fmt.Sprintf("VM attribution is %s; %.2f%% unattributed", safeEventState(attribution.Quality), attribution.UnattributedPercent))
	default:
		tracker.add(view.ObservedAtUTC, "warning", "eBPF",
			fmt.Sprintf("VM attribution is unavailable (%s)", safeEventState(attribution.Quality)))
	}
}

// add performs add as part of the package workflow.
func (tracker *eventTracker) add(observed time.Time, severity, subject, message string) {
	tracker.events = append(tracker.events, MonitorEvent{
		ObservedAtUTC: observed.UTC(),
		Severity:      severity,
		Subject:       subject,
		Message:       message,
	})
	if len(tracker.events) > maxMonitorEvents {
		tracker.events = append([]MonitorEvent(nil), tracker.events[len(tracker.events)-maxMonitorEvents:]...)
	}
}

// snapshot builds snapshot from validated inputs.
func (tracker *eventTracker) snapshot() []MonitorEvent {
	return append([]MonitorEvent(nil), tracker.events...)
}

// attributionState derives stable operator-facing text for attribution state.
func attributionState(view AttributionView) string {
	return fmt.Sprintf("%t:%t:%s:%s", view.Requested, view.CollectorAvailable,
		safeEventState(view.Quality), safeEventState(view.Status))
}

// dominantAttributedVM builds dominant attributed VM from validated inputs.
func dominantAttributedVM(view View) (VMRow, bool) {
	if !view.Attribution.AttributionAvailable {
		return VMRow{}, false
	}
	var dominant VMRow
	found := false
	for _, row := range view.Rows {
		if !row.AttributionAvailable || row.AttributedOps == 0 {
			continue
		}
		if !found || row.AttributedOps > dominant.AttributedOps ||
			(row.AttributedOps == dominant.AttributedOps && row.Name < dominant.Name) {
			dominant = row
			found = true
		}
	}
	return dominant, found
}

// rowsByName builds rows by name from validated inputs.
func rowsByName(rows []VMRow) []VMRow {
	ordered := append([]VMRow(nil), rows...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	return ordered
}

// safeEventState derives stable operator-facing text for safe event state.
func safeEventState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "available", "degraded", "unavailable", "not_requested", "no_attributed_events",
		"permission_denied", "object_unavailable", "collector_error", "collection_error",
		"idle", "low", "high", "partial", "no_eligible_vms":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}
