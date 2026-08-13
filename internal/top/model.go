// Package top builds the read-only live Solis terminal dashboard.
package top

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/hostmetrics"
	statusview "github.com/safwen511/solis-io/internal/status"
)

const (
	AttributionNotRequested = "not_requested"
	AttributionUnavailable  = "unavailable"
)

// Options controls dashboard sampling and refresh behavior.
type Options struct {
	Duration           time.Duration
	Interval           time.Duration
	Every              time.Duration
	Iterations         int
	Clear              bool
	Sort               string
	IncludeEBPFLatency bool
}

// CollectRequest identifies one bounded dashboard observation window.
type CollectRequest struct {
	Duration           time.Duration
	Interval           time.Duration
	IncludeEBPFLatency bool
}

// Snapshot contains only the reports needed by the dashboard. The renderer
// deliberately excludes cgroup IDs, process metadata, raw diagnostics, and
// other internal collector details.
type Snapshot struct {
	ObservedAtUTC        time.Time
	Status               statusview.Report
	StatusAvailable      bool
	StatusState          string
	Host                 *hostmetrics.HostStatus
	HostUnavailableState string
	EBPFLatencyRequested bool
	EBPFLatency          *ebpf.VMBlockLatencyReport
	EBPFUnavailableState string
}

// View is the deterministic, privacy-safe dashboard projection.
type View struct {
	ObservedAtUTC time.Time
	Duration      string
	Interval      string
	Storage       []StorageView
	Pressures     statusview.PressureCounts
	StatusState   string
	Host          HostView
	Attribution   AttributionView
	Rows          []VMRow
}

// HostView contains a small provider-side host summary. Availability is kept
// per metric so missing procfs/PSI data is never rendered as a measured zero.
type HostView struct {
	Available              bool
	Status                 string
	CPUBusyPercent         float64
	CPUAvailable           bool
	IOWaitPercent          float64
	IOWaitAvailable        bool
	IOPSISomeAvg10         float64
	IOPSIAvailable         bool
	MemoryAvailablePercent float64
	MemoryAvailable        bool
}

// StorageView is one mapped physical device's host diskstats rate projection.
type StorageView struct {
	Device            string
	Available         bool
	ReadMiBPerSecond  float64
	WriteMiBPerSecond float64
	ReadOpsPerSecond  float64
	WriteOpsPerSecond float64
	IOInProgress      uint64
}

// AttributionView summarizes host collection and VM-attribution coverage.
type AttributionView struct {
	Requested              bool
	CollectorAvailable     bool
	AttributionAvailable   bool
	Status                 string
	Quality                string
	HostTotalOps           uint64
	HostP95MS              float64
	AttributedOps          uint64
	AttributedPercent      float64
	UnattributedOps        uint64
	UnattributedPercent    float64
	MatchedVMCount         int
	PercentilesApproximate bool
}

// VMRow is one compact dashboard row. Availability booleans distinguish a
// measured zero from missing evidence.
type VMRow struct {
	Name                 string
	Tenant               string
	Role                 string
	Pressure             string
	WriteMiBPerSecond    float64
	WriteAvailable       bool
	AttributedOps        uint64
	LatencyP95MS         float64
	AttributionAvailable bool
	AttributionState     string
}

// ValidSortField reports whether a dashboard sort key is supported.
func ValidSortField(field string) bool {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "name", "pressure", "write", "ops", "latency":
		return true
	default:
		return false
	}
}

// BuildView converts collector reports into a bounded public terminal view.
func BuildView(snapshot Snapshot, sortField string) (View, error) {
	if !ValidSortField(sortField) {
		return View{}, fmt.Errorf("invalid top sort field %q", sortField)
	}
	view := View{
		ObservedAtUTC: snapshot.ObservedAtUTC.UTC(),
		Duration:      snapshot.Status.Duration,
		Interval:      snapshot.Status.Interval,
		StatusState:   statusEvidenceState(snapshot),
		Attribution: AttributionView{
			Requested: snapshot.EBPFLatencyRequested,
			Status:    AttributionNotRequested,
			Quality:   AttributionUnavailable,
		},
	}
	if view.ObservedAtUTC.IsZero() {
		view.ObservedAtUTC = time.Now().UTC()
	}

	rows := make(map[string]VMRow, len(snapshot.Status.VMs))
	storage := make(map[string]struct{})
	for _, vm := range snapshot.Status.VMs {
		name := strings.TrimSpace(vm.Name)
		if name == "" {
			continue
		}
		pressure := strings.ToLower(strings.TrimSpace(vm.Pressure))
		if !vm.IOAvailable {
			pressure = AttributionUnavailable
		}
		rows[name] = VMRow{
			Name:              name,
			Tenant:            displayText(vm.Tenant),
			Role:              displayText(vm.Role),
			Pressure:          displayText(pressure),
			WriteMiBPerSecond: vm.AverageWriteMiBPerSecond,
			WriteAvailable:    vm.IOAvailable,
			AttributionState:  AttributionNotRequested,
		}
		device := strings.TrimSpace(vm.PhysicalDisk)
		if device != "" && device != "-" {
			storage[device] = struct{}{}
		}
	}
	for _, row := range rows {
		switch row.Pressure {
		case statusview.PressureHigh:
			view.Pressures.High++
		case statusview.PressureLow:
			view.Pressures.Low++
		case statusview.PressureIdle:
			view.Pressures.Idle++
		}
	}

	if snapshot.EBPFLatencyRequested {
		view.Attribution.Status = firstNonEmpty(snapshot.EBPFUnavailableState, AttributionUnavailable)
		for name, row := range rows {
			row.AttributionState = view.Attribution.Status
			rows[name] = row
		}
	}
	if report := snapshot.EBPFLatency; snapshot.EBPFLatencyRequested && report != nil {
		view.Attribution.CollectorAvailable = report.Availability.Available
		view.Attribution.Status = displayText(report.Availability.Status)
		view.Attribution.Quality = displayText(report.AttributionQuality)
		if report.Availability.Available {
			view.Attribution.HostTotalOps = report.HostSummary.TotalOps
			view.Attribution.HostP95MS = report.HostSummary.LatencyP95MS
			view.Attribution.AttributedOps = report.AttributionSummary.AttributedOps
			view.Attribution.AttributedPercent = report.AttributionSummary.AttributedPercent
			view.Attribution.UnattributedOps = report.AttributionSummary.UnattributedOps
			view.Attribution.UnattributedPercent = report.Unattributed.UnattributedPercent
			view.Attribution.MatchedVMCount = report.AttributionSummary.MatchedVMCount
			view.Attribution.PercentilesApproximate = report.HostSummary.PercentilesApproximate
		}
		view.Attribution.AttributionAvailable = report.Availability.Available &&
			report.VMAttributionPreflight.Available && report.VMAttributionPreflight.Status == "enabled" &&
			(report.AttributionQuality == "available" || report.AttributionQuality == "degraded")

		for _, vm := range report.VMs {
			name := strings.TrimSpace(vm.Name)
			if name == "" {
				continue
			}
			row, exists := rows[name]
			if !exists {
				row = VMRow{
					Name:             name,
					Tenant:           displayText(vm.Tenant),
					Role:             displayText(vm.Role),
					Pressure:         AttributionUnavailable,
					AttributionState: view.Attribution.Status,
				}
			}
			if view.Attribution.AttributionAvailable {
				row.AttributedOps = vm.TotalOps
				row.LatencyP95MS = vm.LatencyP95MS
				row.AttributionAvailable = true
				row.AttributionState = firstNonEmpty(vm.AttributionQuality, report.AttributionQuality)
			} else {
				row.AttributionState = firstNonEmpty(report.AttributionQuality, report.Availability.Status, AttributionUnavailable)
			}
			rows[name] = row
		}
	}

	view.Host = buildHostView(snapshot.Host, snapshot.HostUnavailableState)
	view.Storage = buildStorageViews(storage, snapshot.Host)
	view.Rows = make([]VMRow, 0, len(rows))
	for _, row := range rows {
		view.Rows = append(view.Rows, row)
	}
	sortRows(view.Rows, sortField)
	return view, nil
}

func statusEvidenceState(snapshot Snapshot) string {
	if !snapshot.StatusAvailable {
		return normalizedState(snapshot.StatusState, false)
	}
	if len(snapshot.Status.VMs) == 0 {
		return "no_eligible_vms"
	}
	available := 0
	for _, vm := range snapshot.Status.VMs {
		if vm.IOAvailable {
			available++
		}
	}
	switch {
	case available == len(snapshot.Status.VMs):
		return "available"
	case available > 0:
		return "partial"
	default:
		return AttributionUnavailable
	}
}

func buildHostView(report *hostmetrics.HostStatus, unavailableState string) HostView {
	view := HostView{Status: firstNonEmpty(unavailableState, AttributionUnavailable)}
	if report == nil {
		return view
	}
	view.Available = report.Availability.Available
	view.Status = firstNonEmpty(string(report.Availability.Quality), boolState(report.Availability.Available))
	if report.CPU.Availability.Available {
		view.CPUAvailable = true
		view.IOWaitAvailable = true
		view.CPUBusyPercent = report.CPU.TotalBusyPercent
		view.IOWaitPercent = report.CPU.IOWaitPercent
	}
	if report.PSI.IO.Some.Availability.Available {
		view.IOPSIAvailable = true
		view.IOPSISomeAvg10 = report.PSI.IO.Some.Avg10
	}
	if report.Memory.Availability.Available {
		view.MemoryAvailable = true
		view.MemoryAvailablePercent = report.Memory.MemAvailablePercent
	}
	return view
}

func buildStorageViews(devices map[string]struct{}, report *hostmetrics.HostStatus) []StorageView {
	byName := make(map[string]hostmetrics.DiskStatus)
	if report != nil {
		for _, device := range report.Disks.Devices {
			byName[device.Name] = device
		}
	}
	views := make([]StorageView, 0, len(devices))
	for path := range devices {
		view := StorageView{Device: path}
		if device, ok := byName[filepath.Base(path)]; ok && device.RateAvailability.Available {
			view.Available = true
			view.ReadMiBPerSecond = sectorsPerSecondToMiB(device.ReadSectorsPerSecond)
			view.WriteMiBPerSecond = sectorsPerSecondToMiB(device.WriteSectorsPerSecond)
			view.ReadOpsPerSecond = device.ReadsPerSecond
			view.WriteOpsPerSecond = device.WritesPerSecond
			view.IOInProgress = device.IOInProgress
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Device < views[j].Device })
	return views
}

func sectorsPerSecondToMiB(sectors float64) float64 {
	return sectors * 512 / (1024 * 1024)
}

func boolState(available bool) string {
	if available {
		return "available"
	}
	return AttributionUnavailable
}

func sortRows(rows []VMRow, field string) {
	sort.SliceStable(rows, func(i, j int) bool {
		left, right := rows[i], rows[j]
		switch strings.ToLower(strings.TrimSpace(field)) {
		case "pressure":
			if pressureRank(left.Pressure) != pressureRank(right.Pressure) {
				return pressureRank(left.Pressure) < pressureRank(right.Pressure)
			}
		case "write":
			if left.WriteAvailable != right.WriteAvailable {
				return left.WriteAvailable
			}
			if left.WriteMiBPerSecond != right.WriteMiBPerSecond {
				return left.WriteMiBPerSecond > right.WriteMiBPerSecond
			}
		case "ops":
			if left.AttributionAvailable != right.AttributionAvailable {
				return left.AttributionAvailable
			}
			if left.AttributedOps != right.AttributedOps {
				return left.AttributedOps > right.AttributedOps
			}
		case "latency":
			if left.AttributionAvailable != right.AttributionAvailable {
				return left.AttributionAvailable
			}
			if left.LatencyP95MS != right.LatencyP95MS {
				return left.LatencyP95MS > right.LatencyP95MS
			}
		}
		return strings.ToLower(left.Name) < strings.ToLower(right.Name)
	})
}

func normalizedState(state string, available bool) string {
	state = strings.TrimSpace(state)
	if state != "" {
		return state
	}
	if available {
		return "available"
	}
	return AttributionUnavailable
}

func displayText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func pressureRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case statusview.PressureHigh:
		return 0
	case statusview.PressureLow:
		return 1
	case statusview.PressureIdle:
		return 2
	default:
		return 3
	}
}
