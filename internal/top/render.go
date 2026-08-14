package top

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

const compactLayoutWidth = 140

// Frame identifies one refresh of the terminal dashboard.
type Frame struct {
	Iteration         int
	Every             time.Duration
	UIRefresh         time.Duration
	WindowDuration    time.Duration
	Now               time.Time
	CollectionStarted time.Time
	NextCollectionAt  time.Time
	Collecting        bool
	ShowBanner        bool
	SelectedVM        string
	Sort              string
	Interactive       bool
	ShowHelp          bool
	ActivePanel       dashboardPanel
	Events            []MonitorEvent
	History           []VMInvestigationSample
	SelectedWorkflow  int
	WorkflowRequest   LaunchRequest
	WorkflowRunning   bool
	WorkflowOutput    string
	WorkflowError     string
	WorkflowScroll    int
	WorkflowDetail    bool
	WorkflowSavedPath string
	WorkflowSaveError string
	ProcessResources  ProcessResources
	Application       bool
	Width             int
	Height            int
}

// WriteFrame renders one bounded dashboard frame.
func WriteFrame(dst io.Writer, view View, frame Frame) error {
	// Keep the Solis identity visible throughout an interactive application
	// session. Log-oriented application output still prints it only when asked.
	if frame.Application && (frame.Interactive || frame.ShowBanner) {
		if err := writeApplicationBanner(dst, frame.Width, frame.Height, frame.ProcessResources); err != nil {
			return err
		}
	}
	title := "Solis I/O Top (read-only)"
	if frame.Application {
		title = "LIVE PROVIDER CONSOLE  •  READ-ONLY"
	}
	observed := "-"
	completed := "-"
	age := "-"
	now := frame.Now
	if now.IsZero() {
		now = time.Now()
	}
	if frame.Iteration > 0 {
		observed = view.ObservedAtUTC.UTC().Format(time.RFC3339)
		completed = view.CompletedAtUTC.UTC().Format(time.RFC3339)
		elapsed := now.Sub(view.CompletedAtUTC)
		if elapsed < 0 {
			elapsed = 0
		}
		age = elapsed.Round(100 * time.Millisecond).String()
	}
	sampling := samplingStatus(frame, now)
	uiRefresh := "on-change"
	if frame.UIRefresh > 0 {
		uiRefresh = frame.UIRefresh.String()
	}
	var session strings.Builder
	if frame.Width > 0 && frame.Width < compactLayoutWidth {
		if _, err := fmt.Fprintf(&session,
			"%s\n"+
				"Window start: %s  Window: %s  Interval: %s\n"+
				"Cadence: %s  Iteration: %d  Sort: %s  UI refresh: %s\n"+
				"Sampling: %s\nLast complete: %s  Data age: %s\n",
			title, observed, displayText(view.Duration), displayText(view.Interval), frame.Every,
			frame.Iteration, displayText(frame.Sort), uiRefresh, sampling, completed, age); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(&session,
		"%s\n"+
			"Window start: %s  Window: %s  Interval: %s  Evidence cadence: %s  Iteration: %d  Sort: %s\n"+
			"Sampling: %s  Last complete: %s  Data age: %s  UI refresh: %s\n",
		title, observed, displayText(view.Duration), displayText(view.Interval), frame.Every,
		frame.Iteration, displayText(frame.Sort), sampling, completed, age, uiRefresh); err != nil {
		return err
	}
	if frame.Application && frame.Interactive {
		if err := writeBox(dst, "SESSION", session.String(), frame.Width); err != nil {
			return err
		}
	} else if _, err := io.WriteString(dst, session.String()); err != nil {
		return err
	}
	activePanel := frame.ActivePanel
	if activePanel == "" {
		activePanel = panelOverview
	}
	if frame.Interactive && frame.ActivePanel == panelWorkflowOutput {
		if _, err := fmt.Fprintln(dst); err != nil {
			return err
		}
		if err := writePanelTabs(dst, frame.ActivePanel, frame.Application, frame.Width); err != nil {
			return err
		}
		var workflowBody strings.Builder
		if err := writeWorkflowOutput(&workflowBody, frame); err != nil {
			return err
		}
		if err := writeBox(dst, workflowPanelTitle(frame), workflowBody.String(), frame.Width); err != nil {
			return err
		}
		if frame.ShowHelp {
			if err := writeHelp(dst, frame.Width); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintln(dst, "\n  ↑/k scroll up   ↓/j scroll down   b return when complete   ? help   q quit\n  Safety: bounded sanitized output • monitoring paused • no shell execution")
		return err
	}
	if frame.Iteration == 0 && frame.Collecting {
		if frame.Application && frame.Interactive {
			return writeBox(dst, "DISCOVERING", "Discovering configured VMs and collecting the first bounded evidence window…\n\nMeasurements appear only after collection completes.  ? help  •  q quit", frame.Width)
		}
		_, err := fmt.Fprintln(dst, "VM inventory: DISCOVERING  Live status: COLLECTING\n\nDiscovering configured VMs and collecting the first bounded evidence window…\n\nKeys: ? help, q quit. Measurements appear only after the collection window completes.")
		return err
	}
	var evidence strings.Builder
	evidenceTarget := io.Writer(dst)
	if frame.Application && frame.Interactive {
		evidenceTarget = &evidence
	}
	if frame.Width > 0 && frame.Width < compactLayoutWidth {
		if _, err := fmt.Fprintf(evidenceTarget,
			"VM inventory: total=%d running=%d not_running=%d unknown=%d\nLive status: %s  QEMU pressure: high=%d low=%d idle=%d\n",
			view.VMs.Total, view.VMs.Running, view.VMs.NotRunning, view.VMs.Unknown,
			strings.ToUpper(displayText(view.StatusState)), view.Pressures.High, view.Pressures.Low, view.Pressures.Idle); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(evidenceTarget,
		"VM inventory: total=%d running=%d not_running=%d unknown=%d  Live status: %s  QEMU pressure: high=%d low=%d idle=%d\n",
		view.VMs.Total, view.VMs.Running, view.VMs.NotRunning, view.VMs.Unknown,
		strings.ToUpper(displayText(view.StatusState)), view.Pressures.High, view.Pressures.Low, view.Pressures.Idle); err != nil {
		return err
	}
	if err := writeHostSummary(evidenceTarget, view.Host, frame.Width); err != nil {
		return err
	}
	if err := writeStorageSummary(evidenceTarget, view.Storage, frame.Width); err != nil {
		return err
	}
	if err := writeAttributionSummary(evidenceTarget, view.Attribution); err != nil {
		return err
	}
	if err := writeAttributionLoss(evidenceTarget, view.Attribution, frame.Width); err != nil {
		return err
	}
	if evidenceTarget == &evidence {
		if activePanel == panelOverview {
			if err := writeBox(dst, "LIVE EVIDENCE", evidence.String(), frame.Width); err != nil {
				return err
			}
		} else if err := writeEvidenceStrip(dst, view, frame.Width); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(dst); err != nil {
		return err
	}
	if frame.Interactive {
		if err := writePanelTabs(dst, frame.ActivePanel, frame.Application, frame.Width); err != nil {
			return err
		}
	}
	switch {
	case !frame.Interactive:
		if err := writeVMTable(dst, view, frame.SelectedVM, frame.Width); err != nil {
			return err
		}
		if frame.SelectedVM != "" {
			if err := writeSelectedVM(dst, view, frame.SelectedVM); err != nil {
				return err
			}
		}
	case activePanel == panelDetails:
		if frame.SelectedVM == "" {
			if _, err := fmt.Fprintln(dst, "No VM is selected."); err != nil {
				return err
			}
		} else if frame.Application {
			if err := writePanelBox(dst, "INVESTIGATE VM  •  "+displayText(frame.SelectedVM), frame.Width, func(body io.Writer) error {
				return writeVMInvestigation(body, view, frame.SelectedVM, frame.History)
			}); err != nil {
				return err
			}
		} else if err := writeSelectedVM(dst, view, frame.SelectedVM); err != nil {
			return err
		}
	case activePanel == panelEvents:
		limit := maxMonitorEvents
		if frame.Application {
			limit = 6
		}
		if frame.Application {
			if err := writePanelBox(dst, "DERIVED EVENTS  •  BOUNDED", frame.Width, func(body io.Writer) error {
				return writeEvents(body, frame.Events, limit)
			}); err != nil {
				return err
			}
		} else if err := writeEvents(dst, frame.Events, limit); err != nil {
			return err
		}
	case activePanel == panelWorkflows:
		if err := writePanelBox(dst, "COMMAND CENTER  •  FIXED WORKFLOWS", frame.Width, func(body io.Writer) error {
			return writeWorkflowPanel(body, frame.SelectedWorkflow, frame.SelectedVM, frame.Width)
		}); err != nil {
			return err
		}
	case activePanel == panelWorkflowOutput:
		if err := writeWorkflowOutput(dst, frame); err != nil {
			return err
		}
	default:
		if frame.Application {
			if err := writePanelBox(dst, "VIRTUAL MACHINES  •  ↑/↓ SELECT  •  ENTER INVESTIGATE", frame.Width, func(body io.Writer) error {
				return writeVMTable(body, view, frame.SelectedVM, frame.Width)
			}); err != nil {
				return err
			}
		} else if err := writeVMTable(dst, view, frame.SelectedVM, frame.Width); err != nil {
			return err
		}
	}
	if frame.ShowHelp {
		if err := writeHelp(dst, frame.Width); err != nil {
			return err
		}
	}
	footer := "Ctrl-C quits."
	if frame.Interactive {
		footer = "j/k select  •  Tab/←/→ panel  •  Enter investigate  •  b back  •  n/p/w/o/l sort  •  r refresh  •  ? help  •  q quit"
		if frame.Application {
			footer = "1 Home  •  2 VM  •  3 Events  •  4 Commands  •  ↑/k ↓/j select  •  Enter open  •  ? help  •  q quit"
			if frame.Width > 0 && frame.Width < 110 {
				footer = "1-4 panels  •  ↑/k ↓/j select  •  Enter open  •  Tab next  •  ? help  •  q quit"
			}
		}
	}
	if frame.Application && frame.Interactive {
		_, err := fmt.Fprintf(dst, "\n  KEYS  │ %s\n  NOTE  │ p95~ is a fixed-bucket estimate; evidence does not prove impact or root cause.\n", footer)
		return err
	}
	_, err := fmt.Fprintf(dst, "\n%s\nCaveat: p95~ is a fixed-bucket estimate; evidence does not prove impact or root cause.\n", footer)
	return err
}

func samplingStatus(frame Frame, now time.Time) string {
	if frame.ActivePanel == panelWorkflowOutput {
		if frame.WorkflowRunning {
			return "PAUSED  workflow running"
		}
		return "PAUSED  workflow complete"
	}
	if !frame.Collecting {
		if frame.NextCollectionAt.IsZero() {
			return "READY"
		}
		remaining := frame.NextCollectionAt.Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		return fmt.Sprintf("READY  next evidence window in %s", remaining.Round(100*time.Millisecond))
	}
	if frame.CollectionStarted.IsZero() || frame.WindowDuration <= 0 {
		return "COLLECTING"
	}
	elapsed := now.Sub(frame.CollectionStarted)
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed > frame.WindowDuration {
		elapsed = frame.WindowDuration
	}
	const width = 10
	filled := int(float64(elapsed) / float64(frame.WindowDuration) * width)
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", width-filled)
	return fmt.Sprintf("COLLECTING [%s] %s/%s", bar, elapsed.Round(100*time.Millisecond), frame.WindowDuration)
}

func writeVMTable(dst io.Writer, view View, selectedVM string, width int) error {
	table := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	compact := width > 0 && width < compactLayoutWidth
	if compact {
		if _, err := fmt.Fprintln(table, "\tVM\t│\tSTATE\t│\tQEMU\t│\tWRITE_MIB/S\t│\tATTR_OPS\t│\tP95_MS~\t│\tATTR_STATE"); err != nil {
			return err
		}
		for _, row := range view.Rows {
			marker := " "
			if row.Name == selectedVM {
				marker = "▶"
			}
			if _, err := fmt.Fprintf(table, "%s\t%s\t│\t%s\t│\t%s\t│\t%s\t│\t%s\t│\t%s\t│\t%s\n",
				marker, row.Name, strings.ToUpper(row.State), strings.ToUpper(row.Pressure),
				optionalFloat(row.WriteMiBPerSecond, row.WriteAvailable, 2),
				optionalUint(row.AttributedOps, row.AttributionAvailable),
				optionalFloat(row.LatencyP95MS, row.AttributionAvailable, 3), row.AttributionState); err != nil {
				return err
			}
		}
		if err := table.Flush(); err != nil {
			return err
		}
		if len(view.Rows) == 0 {
			_, err := fmt.Fprintln(dst, "No configured VMs are available in the resolved inventory.")
			return err
		}
		return nil
	}
	if _, err := fmt.Fprintln(table, "\tVM\t│\tSTATE\t│\tTENANT\t│\tROLE\t│\tQEMU_PRESSURE\t│\tWRITE_MIB/S\t│\tATTR_OPS\t│\tP95_MS~\t│\tATTR_STATE"); err != nil {
		return err
	}
	for _, row := range view.Rows {
		marker := " "
		if row.Name == selectedVM {
			marker = "▶"
		}
		if _, err := fmt.Fprintf(table, "%s\t%s\t│\t%s\t│\t%s\t│\t%s\t│\t%s\t│\t%s\t│\t%s\t│\t%s\t│\t%s\n",
			marker,
			row.Name,
			strings.ToUpper(row.State),
			row.Tenant,
			row.Role,
			strings.ToUpper(row.Pressure),
			optionalFloat(row.WriteMiBPerSecond, row.WriteAvailable, 2),
			optionalUint(row.AttributedOps, row.AttributionAvailable),
			optionalFloat(row.LatencyP95MS, row.AttributionAvailable, 3),
			row.AttributionState,
		); err != nil {
			return err
		}
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if len(view.Rows) == 0 {
		if _, err := fmt.Fprintln(dst, "No configured VMs are available in the resolved inventory."); err != nil {
			return err
		}
	}
	return nil
}

func writeHostSummary(dst io.Writer, view HostView, width int) error {
	if width > 0 && width < compactLayoutWidth {
		_, err := fmt.Fprintf(dst,
			"Host: %s  cpu_busy=%s%%  iowait=%s%%\nHost pressure: io_psi_some_avg10=%s%%  mem_available=%s%%\n",
			strings.ToUpper(displayText(view.Status)), optionalFloat(view.CPUBusyPercent, view.CPUAvailable, 2),
			optionalFloat(view.IOWaitPercent, view.IOWaitAvailable, 2), optionalFloat(view.IOPSISomeAvg10, view.IOPSIAvailable, 2),
			optionalFloat(view.MemoryAvailablePercent, view.MemoryAvailable, 2))
		return err
	}
	_, err := fmt.Fprintf(dst,
		"Host: %s  cpu_busy=%s%%  iowait=%s%%  io_psi_some_avg10=%s%%  mem_available=%s%%\n",
		strings.ToUpper(displayText(view.Status)),
		optionalFloat(view.CPUBusyPercent, view.CPUAvailable, 2),
		optionalFloat(view.IOWaitPercent, view.IOWaitAvailable, 2),
		optionalFloat(view.IOPSISomeAvg10, view.IOPSIAvailable, 2),
		optionalFloat(view.MemoryAvailablePercent, view.MemoryAvailable, 2),
	)
	return err
}

func writeStorageSummary(dst io.Writer, views []StorageView, width int) error {
	if len(views) == 0 {
		_, err := fmt.Fprintln(dst, "Storage: no mapped physical device is available")
		return err
	}
	for _, view := range views {
		if width > 0 && width < compactLayoutWidth {
			if _, err := fmt.Fprintf(dst,
				"Storage %s: read=%s MiB/s write=%s MiB/s\nStorage ops: read=%s/s write=%s/s inflight=%s\n",
				view.Device, optionalFloat(view.ReadMiBPerSecond, view.Available, 2),
				optionalFloat(view.WriteMiBPerSecond, view.Available, 2), optionalFloat(view.ReadOpsPerSecond, view.Available, 2),
				optionalFloat(view.WriteOpsPerSecond, view.Available, 2), optionalUint(view.IOInProgress, view.Available)); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(dst,
			"Storage %s: read=%s MiB/s write=%s MiB/s read_iops=%s write_iops=%s inflight=%s\n",
			view.Device,
			optionalFloat(view.ReadMiBPerSecond, view.Available, 2),
			optionalFloat(view.WriteMiBPerSecond, view.Available, 2),
			optionalFloat(view.ReadOpsPerSecond, view.Available, 2),
			optionalFloat(view.WriteOpsPerSecond, view.Available, 2),
			optionalUint(view.IOInProgress, view.Available),
		); err != nil {
			return err
		}
	}
	return nil
}

func writeAttributionSummary(dst io.Writer, view AttributionView) error {
	switch {
	case !view.Requested:
		_, err := fmt.Fprintln(dst, "eBPF collector: NOT REQUESTED\nVM attribution: NOT REQUESTED")
		return err
	case !view.CollectorAvailable:
		_, err := fmt.Fprintf(dst, "eBPF collector: UNAVAILABLE  status=%s\nVM attribution: UNAVAILABLE\n", displayText(view.Status))
		return err
	default:
		quality := strings.ToUpper(displayText(view.Quality))
		_, err := fmt.Fprintf(dst,
			"eBPF collector: AVAILABLE  host_ops=%d host_p95_ms~=%.3f\n"+
				"VM attribution: %s  attributed=%d (%.2f%%)  unattributed=%d (%.2f%%)  matched_vms=%d\n",
			view.HostTotalOps,
			view.HostP95MS,
			quality,
			view.AttributedOps,
			view.AttributedPercent,
			view.UnattributedOps,
			view.UnattributedPercent,
			view.MatchedVMCount,
		)
		return err
	}
}

func writeAttributionLoss(dst io.Writer, view AttributionView, width int) error {
	if !view.Requested || !view.CollectorAvailable {
		return nil
	}
	loss := view.Loss
	if width > 0 && width < compactLayoutWidth {
		_, err := fmt.Fprintf(dst,
			"Attribution loss: missing_bio=%d missing_blkcg=%d unmapped_cgroup=%d lookup_miss=%d\n"+
				"Instrumentation: incomplete=%d map_full=%d dropped=%d ring_lost=%d\n",
			loss.MissingBio, loss.MissingBlkcg, loss.UnmappedCgroup, loss.LookupMiss,
			loss.IncompleteAtWindowEnd, loss.MapFull, loss.DroppedEvents, loss.RingBufferLost)
		return err
	}
	_, err := fmt.Fprintf(dst,
		"Attribution loss: missing_bio=%d missing_blkcg=%d unmapped_cgroup=%d lookup_miss=%d incomplete=%d map_full=%d dropped=%d ring_lost=%d\n",
		loss.MissingBio,
		loss.MissingBlkcg,
		loss.UnmappedCgroup,
		loss.LookupMiss,
		loss.IncompleteAtWindowEnd,
		loss.MapFull,
		loss.DroppedEvents,
		loss.RingBufferLost,
	)
	return err
}

func writeEvidenceStrip(dst io.Writer, view View, width int) error {
	var body strings.Builder
	if _, err := fmt.Fprintf(&body,
		"VM inventory: total=%d running=%d not_running=%d unknown=%d  •  QEMU high=%d low=%d idle=%d  •  Host %s\n",
		view.VMs.Total, view.VMs.Running, view.VMs.NotRunning, view.VMs.Unknown,
		view.Pressures.High, view.Pressures.Low, view.Pressures.Idle,
		strings.ToUpper(displayText(view.Host.Status))); err != nil {
		return err
	}
	if len(view.Storage) == 0 {
		body.WriteString("Storage unavailable")
	} else {
		storage := view.Storage[0]
		_, _ = fmt.Fprintf(&body, "Storage %s  read=%s MiB/s  write=%s MiB/s  inflight=%s",
			displayText(storage.Device), optionalFloat(storage.ReadMiBPerSecond, storage.Available, 2),
			optionalFloat(storage.WriteMiBPerSecond, storage.Available, 2), optionalUint(storage.IOInProgress, storage.Available))
	}
	switch {
	case !view.Attribution.Requested:
		body.WriteString("  •  eBPF not requested")
	case !view.Attribution.CollectorAvailable:
		_, _ = fmt.Fprintf(&body, "  •  eBPF unavailable (%s)", displayText(view.Attribution.Status))
	default:
		_, _ = fmt.Fprintf(&body, "  •  VM attribution %s  %.2f%% attributed",
			strings.ToUpper(displayText(view.Attribution.Quality)), view.Attribution.AttributedPercent)
	}
	return writeBox(dst, "EVIDENCE STRIP", body.String(), width)
}

func writeSelectedVM(dst io.Writer, view View, name string) error {
	row, ok := findVMRow(view.Rows, name)
	if !ok {
		return nil
	}
	if _, err := fmt.Fprintf(dst,
		"\nVM PROFILE  %s\n"+
			"Identity: state=%s tenant=%s role=%s network=%s\n"+
			"Addressing: planned_ip=%s lease_ip=%s\n"+
			"Capacity: vcpus=%s memory_mb=%s disk_gb=%s\n"+
			"Disk backend: %s\n"+
			"Live pressure: %s (%s)\n",
		row.Name,
		strings.ToUpper(row.State),
		row.Tenant,
		row.Role,
		displayText(row.Network),
		displayText(row.PlannedIP),
		displayText(row.LeaseIP),
		displayText(row.VCPUs),
		displayText(row.MemoryMB),
		displayText(row.DiskGB),
		displayText(row.DiskPath),
		strings.ToUpper(row.Pressure),
		row.PressureReason,
	); err != nil {
		return err
	}
	if !row.Running {
		reason := "this VM is not running"
		if normalizedVMState(row.State) == "unknown" {
			reason = "the libvirt runtime state is unavailable"
		}
		_, err := fmt.Fprintf(dst, "Live metrics: unavailable because %s; no zero-I/O claim is made.\n", reason)
		return err
	}
	if _, err := fmt.Fprintf(dst,
		"QEMU writes: avg=%s MiB/s max=%s MiB/s syscw=%s/s\n",
		optionalFloat(row.WriteMiBPerSecond, row.WriteAvailable, 2),
		optionalFloat(row.MaxWriteMiBPerSecond, row.WriteAvailable, 2),
		optionalFloat(row.WriteSyscallsPerSecond, row.WriteAvailable, 2),
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst,
		"Attributed operations: total=%s read=%s write=%s flush=%s discard=%s unknown=%s\n",
		optionalUint(row.AttributedOps, row.AttributionAvailable),
		optionalUint(row.ReadOps, row.AttributionAvailable),
		optionalUint(row.WriteOps, row.AttributionAvailable),
		optionalUint(row.FlushOps, row.AttributionAvailable),
		optionalUint(row.DiscardOps, row.AttributionAvailable),
		optionalUint(row.UnknownOps, row.AttributionAvailable),
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst,
		"Latency ms~: p50=%s p95=%s p99=%s max=%s  attribution=%s mapping=%s\n",
		optionalFloat(row.LatencyP50MS, row.AttributionAvailable, 3),
		optionalFloat(row.LatencyP95MS, row.AttributionAvailable, 3),
		optionalFloat(row.LatencyP99MS, row.AttributionAvailable, 3),
		optionalFloat(row.LatencyMaxMS, row.AttributionAvailable, 3),
		row.AttributionState,
		detailText(row.MappingQuality, row.AttributionAvailable),
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst, "Devices: %s\n", detailList(row.Devices, row.AttributionAvailable)); err != nil {
		return err
	}
	if !row.AttributionAvailable || len(row.DeviceOperations) == 0 {
		_, err := fmt.Fprintln(dst, "Device operations: -")
		return err
	}
	if _, err := fmt.Fprintln(dst, "Device operations:"); err != nil {
		return err
	}
	const maxDeviceOperations = 8
	for index, operation := range row.DeviceOperations {
		if index >= maxDeviceOperations {
			if _, err := fmt.Fprintf(dst, "- ... %d additional bounded aggregate(s)\n", len(row.DeviceOperations)-maxDeviceOperations); err != nil {
				return err
			}
			break
		}
		if _, err := fmt.Fprintf(dst, "- %s %s: ops=%d p95_ms~=%.3f\n", operation.Device, operation.Operation, operation.Count, operation.LatencyP95MS); err != nil {
			return err
		}
	}
	return nil
}

func writeVMInvestigation(dst io.Writer, view View, name string, history []VMInvestigationSample) error {
	row, ok := findVMRow(view.Rows, name)
	if !ok {
		return nil
	}
	if _, err := fmt.Fprintf(dst,
		"INVESTIGATE  %s  •  %s  •  tenant=%s role=%s\n"+
			"Address: planned=%s lease=%s  Capacity: vcpus=%s memory_mb=%s disk_gb=%s\n"+
			"Pressure: %s (%s)  QEMU write=%s MiB/s syscw=%s/s\n",
		row.Name, strings.ToUpper(row.State), row.Tenant, row.Role,
		displayText(row.PlannedIP), displayText(row.LeaseIP), displayText(row.VCPUs), displayText(row.MemoryMB), displayText(row.DiskGB),
		strings.ToUpper(row.Pressure), row.PressureReason,
		optionalFloat(row.WriteMiBPerSecond, row.WriteAvailable, 2), optionalFloat(row.WriteSyscallsPerSecond, row.WriteAvailable, 2),
	); err != nil {
		return err
	}
	if !row.Running {
		reason := "this VM is not running"
		if normalizedVMState(row.State) == "unknown" {
			reason = "the libvirt runtime state is unavailable"
		}
		_, err := fmt.Fprintf(dst, "Live investigation is unavailable because %s; no zero-I/O claim is made.\n", reason)
		return err
	}
	shareAvailable := row.AttributionAvailable && view.Attribution.AttributedOps > 0
	share := 0.0
	if shareAvailable {
		share = float64(row.AttributedOps) / float64(view.Attribution.AttributedOps) * 100
	}
	if _, err := fmt.Fprintf(dst,
		"eBPF: state=%s ops=%s share=%s p50=%s p95=%s p99=%s max=%s ms~\n"+
			"Operations: read=%s write=%s flush=%s discard=%s unknown=%s\n"+
			"Storage: physical=%s devices=%s mapping=%s\n",
		row.AttributionState,
		optionalUint(row.AttributedOps, row.AttributionAvailable), optionalPercent(share, shareAvailable),
		optionalFloat(row.LatencyP50MS, row.AttributionAvailable, 3), optionalFloat(row.LatencyP95MS, row.AttributionAvailable, 3),
		optionalFloat(row.LatencyP99MS, row.AttributionAvailable, 3), optionalFloat(row.LatencyMaxMS, row.AttributionAvailable, 3),
		optionalUint(row.ReadOps, row.AttributionAvailable), optionalUint(row.WriteOps, row.AttributionAvailable),
		optionalUint(row.FlushOps, row.AttributionAvailable), optionalUint(row.DiscardOps, row.AttributionAvailable), optionalUint(row.UnknownOps, row.AttributionAvailable),
		displayText(row.PhysicalDisk), detailList(row.Devices, row.AttributionAvailable), detailText(row.MappingQuality, row.AttributionAvailable),
	); err != nil {
		return err
	}
	if err := writeVMHistory(dst, history); err != nil {
		return err
	}
	return writeStoragePeers(dst, view, row)
}

func writeVMHistory(dst io.Writer, history []VMInvestigationSample) error {
	if _, err := fmt.Fprintln(dst, "\nRecent completed evidence windows:"); err != nil {
		return err
	}
	if len(history) == 0 {
		_, err := fmt.Fprintln(dst, "- waiting for the first completed window")
		return err
	}
	const visible = 5
	start := 0
	if len(history) > visible {
		start = len(history) - visible
	}
	table := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "COMPLETED\t│\tQEMU_PRESSURE\t│\tWRITE_MIB/S\t│\tATTR_OPS\t│\tP95_MS~\t│\tATTR_STATE"); err != nil {
		return err
	}
	for _, sample := range history[start:] {
		if _, err := fmt.Fprintf(table, "%s\t│\t%s\t│\t%s\t│\t%s\t│\t%s\t│\t%s\n",
			sample.CompletedAtUTC.UTC().Format("15:04:05"), strings.ToUpper(sample.Pressure),
			optionalFloat(sample.WriteMiBPerSecond, sample.WriteAvailable, 2),
			optionalUint(sample.AttributedOps, sample.AttributionAvailable),
			optionalFloat(sample.LatencyP95MS, sample.AttributionAvailable, 3), sample.AttributionState,
		); err != nil {
			return err
		}
	}
	return table.Flush()
}

func writeStoragePeers(dst io.Writer, view View, selected VMRow) error {
	if selected.PhysicalDisk == "" || selected.PhysicalDisk == "-" {
		return nil
	}
	peers := make([]VMRow, 0)
	for _, row := range view.Rows {
		if row.Name != selected.Name && row.Running && row.PhysicalDisk == selected.PhysicalDisk {
			peers = append(peers, row)
		}
	}
	if len(peers) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(dst, "Storage peers on %s:\n", selected.PhysicalDisk); err != nil {
		return err
	}
	const visible = 4
	for index, peer := range peers {
		if index >= visible {
			_, err := fmt.Fprintf(dst, "- +%d more\n", len(peers)-visible)
			if err != nil {
				return err
			}
			break
		}
		if _, err := fmt.Fprintf(dst, "- %-12s pressure=%-5s write=%s MiB/s attr_ops=%s\n", peer.Name, strings.ToUpper(peer.Pressure),
			optionalFloat(peer.WriteMiBPerSecond, peer.WriteAvailable, 2), optionalUint(peer.AttributedOps, peer.AttributionAvailable)); err != nil {
			return err
		}
	}
	return nil
}

func writeHelp(dst io.Writer, width int) error {
	const body = `1 Home  •  2 Investigate VM  •  3 Events  •  4 Command Center
↑/k and ↓/j move the selected VM, command, or workflow output; Tab and ←/→ cycle panels
Enter investigates a VM or runs the selected fixed workflow; b returns after workflow completion
n name  •  p pressure  •  w write  •  o attributed operations  •  l latency  •  r refresh
? closes help  •  q or Ctrl-C exits

The live collector and its eBPF links are cleaned up before an embedded workflow starts.
Workflow output is bounded and sanitized. Events are derived state changes, not raw kernel events.
No arbitrary command execution or VM modification is available.`
	return writeBox(dst, "HELP  •  KEYBOARD REFERENCE", body, width)
}

func writePanelTabs(dst io.Writer, active dashboardPanel, application bool, width int) error {
	if active == "" {
		active = panelOverview
	}
	label := func(panel dashboardPanel, key, text string) string {
		value := strings.TrimSpace(key + " " + text)
		if panel == active {
			return "[" + value + "]"
		}
		return " " + value + " "
	}
	overview := "Overview"
	if application {
		overview = "Home"
	}
	if !application {
		_, err := fmt.Fprintf(dst, "Panels: %s  %s  %s\n\n",
			label(panelOverview, "", overview), label(panelDetails, "", "Investigate VM"), label(panelEvents, "", "Events"))
		return err
	}
	workflowLabel := label(panelWorkflows, "4", "COMMANDS")
	if active == panelWorkflowOutput {
		workflowLabel = label(panelWorkflowOutput, "4", "OUTPUT")
	}
	line := fmt.Sprintf("%s   %s   %s   %s",
		label(panelOverview, "1", strings.ToUpper(overview)), label(panelDetails, "2", "INVESTIGATE"),
		label(panelEvents, "3", "EVENTS"), workflowLabel)
	if err := writeBox(dst, "NAVIGATION", line, width); err != nil {
		return err
	}
	_, err := fmt.Fprintln(dst)
	return err
}

func writeApplicationBanner(dst io.Writer, width, _ int, resources ProcessResources) error {
	if width > 0 && width < compactLayoutWidth {
		body := "LIVE KVM STORAGE OBSERVABILITY  •  READ-ONLY PROVIDER CONSOLE\n" + compactProcessResourceLine(resources)
		if err := writeBox(dst, "SOLIS I/O", body, minPositive(width, 90)); err != nil {
			return err
		}
		_, err := fmt.Fprintln(dst)
		return err
	}
	const art = `███████╗ ██████╗ ██╗     ██╗███████╗
██╔════╝██╔═══██╗██║     ██║██╔════╝
███████╗██║   ██║██║     ██║███████╗
╚════██║██║   ██║██║     ██║╚════██║
███████║╚██████╔╝███████╗██║███████║
╚══════╝ ╚═════╝ ╚══════╝╚═╝╚══════╝  I/O

Single-host KVM storage observability  •  real VM-attributed block latency`
	body := wideApplicationBannerBody(art, resources, minPositive(width, 180)-4)
	if err := writeBox(dst, "SOLIS I/O", body, minPositive(width, 180)); err != nil {
		return err
	}
	_, err := fmt.Fprintln(dst)
	return err
}

func wideApplicationBannerBody(art string, resources ProcessResources, innerWidth int) string {
	leftLines := strings.Split(art, "\n")
	rightLines := processResourceLines(resources)
	lineCount := len(leftLines)
	if len(rightLines) > lineCount {
		lineCount = len(rightLines)
	}
	rightWidth := 56
	if innerWidth < 130 {
		rightWidth = 48
	}
	leftWidth := innerWidth - rightWidth - 3
	if leftWidth < 52 {
		return art + "\n\n" + strings.Join(rightLines, "\n")
	}
	lines := make([]string, 0, lineCount)
	for index := 0; index < lineCount; index++ {
		left := ""
		if index < len(leftLines) {
			left = leftLines[index]
		}
		right := ""
		if index < len(rightLines) {
			right = rightLines[index]
		}
		lines = append(lines, padRunes(left, leftWidth)+" │ "+right)
	}
	return strings.Join(lines, "\n")
}

func processResourceLines(resources ProcessResources) []string {
	cpu := "unavailable"
	if resources.CPUAvailable {
		cpu = fmt.Sprintf("%.1f%% of one core", resources.CPUPercent)
	}
	memory := "unavailable"
	if resources.MemoryAvailable {
		memory = formatResourceBytes(float64(resources.RSSBytes)) + " RSS"
	}
	readRate := "unavailable"
	writeRate := "unavailable"
	if resources.DiskIOAvailable {
		readRate = formatResourceRate(resources.ReadBytesPerSecond)
		writeRate = formatResourceRate(resources.WriteBytesPerSecond)
	}
	return []string{
		"SOLIS PROCESS",
		"CPU        " + cpu,
		"MEMORY     " + memory,
		"DISK READ  " + readRate,
		"DISK WRITE " + writeRate,
		fmt.Sprintf("RUNTIME    %d goroutines", resources.Goroutines),
		"UPTIME     " + compactDuration(resources.Uptime),
		"Scope: current Solis process only",
	}
}

func compactProcessResourceLine(resources ProcessResources) string {
	cpu := "-"
	if resources.CPUAvailable {
		cpu = fmt.Sprintf("%.1f%%", resources.CPUPercent)
	}
	memory := "-"
	if resources.MemoryAvailable {
		memory = formatResourceBytes(float64(resources.RSSBytes))
	}
	disk := "-"
	if resources.DiskIOAvailable {
		disk = "R " + formatResourceRate(resources.ReadBytesPerSecond) + " W " + formatResourceRate(resources.WriteBytesPerSecond)
	}
	return fmt.Sprintf("SOLIS PROCESS  cpu=%s/core  rss=%s  disk=%s  go=%d  up=%s",
		cpu, memory, disk, resources.Goroutines, compactDuration(resources.Uptime))
}

func formatResourceRate(bytesPerSecond float64) string {
	return formatResourceBytes(bytesPerSecond) + "/s"
}

func formatResourceBytes(value float64) string {
	if value < 0 {
		value = 0
	}
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
	)
	switch {
	case value >= gib:
		return fmt.Sprintf("%.1f GiB", value/gib)
	case value >= mib:
		return fmt.Sprintf("%.1f MiB", value/mib)
	case value >= kib:
		return fmt.Sprintf("%.1f KiB", value/kib)
	default:
		return fmt.Sprintf("%.0f B", value)
	}
}

func compactDuration(value time.Duration) string {
	if value < 0 {
		value = 0
	}
	value = value.Round(time.Second)
	if value < time.Minute {
		return value.String()
	}
	hours := int(value / time.Hour)
	minutes := int(value/time.Minute) % 60
	seconds := int(value/time.Second) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", hours, minutes, seconds)
	}
	return fmt.Sprintf("%dm%02ds", minutes, seconds)
}

func writeWorkflowPanel(dst io.Writer, selected int, selectedVM string, width int) error {
	if _, err := fmt.Fprintln(dst, "Allowlist: fixed Solis workflows only  •  no shell execution"); err != nil {
		return err
	}
	if selectedVM == "" {
		if _, err := fmt.Fprintln(dst, "Selected VM: waiting for inventory"); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(dst, "Selected VM: %s\n", displayText(selectedVM)); err != nil {
		return err
	}
	table := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	compact := width > 0 && width < compactLayoutWidth
	for index, workflow := range applicationWorkflows {
		marker := " "
		if index == normalizedWorkflowIndex(selected) {
			marker = "▶"
		}
		state := "READY"
		if workflow.RequiresVM && selectedVM == "" {
			state = "WAITING FOR VM"
		}
		format := "%s\t%-27s\t│\t%-14s\t│\t%s\n"
		arguments := []any{marker, workflow.Label, state, workflow.Description}
		if compact {
			format = "%s\t%s\t│\t%s\n"
			arguments = []any{marker, workflow.Label, state}
		}
		if _, err := fmt.Fprintf(table, format, arguments...); err != nil {
			return err
		}
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if compact && len(applicationWorkflows) > 0 {
		workflow := applicationWorkflows[normalizedWorkflowIndex(selected)]
		if _, err := fmt.Fprintf(dst, "Selected action: %s.\n", workflow.Description); err != nil {
			return err
		}
	}
	if compact {
		_, err := fmt.Fprintln(dst,
			"\nEnter: pause monitoring and run the selected workflow inside Solis.",
			"More CLI: host/storage/QEMU • guest/service/database • trace/reports",
			"Only Bundle writes output automatically; Observe detail saves only after explicit confirmation.")
		return err
	}
	_, err := fmt.Fprintln(dst,
		"\nEnter pauses the live collector, detaches its eBPF links, and opens bounded workflow output inside Solis.",
		"After completion, press b to return to Command Center and resume live evidence collection.",
		"Advanced CLI: host/storage/QEMU • guest/service/database status • trace planning • experiment summaries • incident explanation",
		"Safety: monitoring and diagnosis are read-only; Bundle uses the private capture writer, and Observe detail saves only after explicit confirmation.")
	return err
}

func writeWorkflowOutput(dst io.Writer, frame Frame) error {
	state := "✓ COMPLETE"
	if frame.WorkflowRunning {
		spinner := []string{"◐", "◓", "◑", "◒"}
		index := int(frame.Now.UnixNano()/int64(200*time.Millisecond)) % len(spinner)
		if index < 0 {
			index = 0
		}
		state = spinner[index] + " RUNNING"
	} else if frame.WorkflowError != "" {
		state = "! FAILED"
	}
	if _, err := fmt.Fprintf(dst, "State: %s  •  Live evidence collector: PAUSED\n", state); err != nil {
		return err
	}
	if frame.WorkflowRequest.VM != "" {
		if _, err := fmt.Fprintf(dst, "Selected VM: %s\n", displayText(frame.WorkflowRequest.VM)); err != nil {
			return err
		}
	}
	if frame.WorkflowRunning {
		_, err := fmt.Fprintln(dst, "\nThe selected bounded workflow is running inside Solis.\nOutput will appear here; q requests cancellation and b becomes available after completion.")
		return err
	}
	if frame.WorkflowError != "" {
		if _, err := fmt.Fprintf(dst, "Error: %s\n", sanitizedWorkflowLine(frame.WorkflowError, frame.Width)); err != nil {
			return err
		}
	}

	lines := workflowDisplayLines(frame.WorkflowOutput, frame.Width)
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	visible := 12
	if frame.Width > 0 && frame.Width < compactLayoutWidth {
		visible = 8
	}
	if frame.Height > 0 {
		candidate := frame.Height - 23
		if frame.Width > 0 && frame.Width < compactLayoutWidth {
			candidate = frame.Height - 16
		}
		if candidate < 4 {
			candidate = 4
		}
		if candidate < visible {
			visible = candidate
		}
	}
	maxScroll := len(lines) - visible
	if maxScroll < 0 {
		maxScroll = 0
	}
	scroll := frame.WorkflowScroll
	if scroll < 0 {
		scroll = 0
	}
	if scroll > maxScroll {
		scroll = maxScroll
	}
	end := scroll + visible
	if end > len(lines) {
		end = len(lines)
	}
	if len(lines) == 0 {
		if _, err := fmt.Fprintln(dst, "\n(no output)"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(dst); err != nil {
			return err
		}
		for _, line := range lines[scroll:end] {
			if _, err := fmt.Fprintln(dst, sanitizedWorkflowLine(line, frame.Width)); err != nil {
				return err
			}
		}
	}
	if len(lines) > 0 {
		position := fmt.Sprintf("lines %d-%d of %d", scroll+1, end, len(lines))
		if maxScroll == 0 {
			position = fmt.Sprintf("all %d lines visible", len(lines))
		}
		if _, err := fmt.Fprintf(dst, "\nSCROLL  ↑/k up  •  ↓/j down  •  %s\n", position); err != nil {
			return err
		}
	}
	if frame.WorkflowDetail {
		switch {
		case frame.WorkflowSavedPath != "":
			if _, err := fmt.Fprintf(dst, "DETAIL  SAVED privately (0600): %s\n", sanitizedWorkflowLine(frame.WorkflowSavedPath, frame.Width)); err != nil {
				return err
			}
		case frame.WorkflowSaveError != "":
			if _, err := fmt.Fprintf(dst, "DETAIL  SAVE FAILED: %s\n", sanitizedWorkflowLine(frame.WorkflowSaveError, frame.Width)); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(dst, "SAVE DETAILED OBSERVATION?  s retry  •  b no, discard and return"); err != nil {
				return err
			}
		default:
			if _, err := fmt.Fprintln(dst,
				"DETAIL  Full JSON is held in memory and has not been written.",
				"SAVE DETAILED OBSERVATION?  s yes (private 0600 file)  •  b no, discard and return"); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintln(dst, "RETURN  b resumes the live monitor  •  q quits Solis")
	return err
}

func workflowPanelTitle(frame Frame) string {
	workflow := strings.ToUpper(strings.ReplaceAll(string(frame.WorkflowRequest.Workflow), "_", " "))
	if workflow == "" {
		workflow = "WORKFLOW"
	}
	state := "COMPLETE"
	if frame.WorkflowRunning {
		state = "RUNNING"
	} else if frame.WorkflowError != "" {
		state = "FAILED"
	}
	if frame.WorkflowRequest.Workflow == WorkflowObserve {
		return "OBSERVATION SUMMARY  •  " + state
	}
	return "WORKFLOW OUTPUT  •  " + workflow + "  •  " + state
}

func sanitizedWorkflowLine(value string, width int) string {
	limit := workflowLineWidth(width)
	filtered := make([]rune, 0, len(value))
	for _, character := range value {
		switch {
		case character == '\t':
			filtered = append(filtered, ' ', ' ')
		case character < 0x20 || character == 0x7f:
			filtered = append(filtered, '?')
		default:
			filtered = append(filtered, character)
		}
		if len(filtered) >= limit {
			break
		}
	}
	return string(filtered)
}

func workflowDisplayLines(value string, width int) []string {
	return wrappedDisplayLines(value, workflowLineWidth(width))
}

func wrappedDisplayLines(value string, limit int) []string {
	if limit < 1 {
		limit = 1
	}
	rawLines := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	lines := make([]string, 0, len(rawLines))
	for _, rawLine := range rawLines {
		filtered := make([]rune, 0, len(rawLine))
		for _, character := range rawLine {
			switch {
			case character == '\t':
				filtered = append(filtered, ' ', ' ')
			case character < 0x20 || character == 0x7f:
				filtered = append(filtered, '?')
			default:
				filtered = append(filtered, character)
			}
		}
		if len(filtered) == 0 {
			lines = append(lines, "")
			continue
		}
		for len(filtered) > limit {
			lines = append(lines, string(filtered[:limit]))
			filtered = filtered[limit:]
		}
		lines = append(lines, string(filtered))
	}
	return lines
}

func workflowLineWidth(width int) int {
	limit := 180
	if width > 0 {
		limit = width - 2
		if limit < 24 {
			limit = 24
		}
	}
	return limit
}

func writeEvents(dst io.Writer, events []MonitorEvent, limit int) error {
	if _, err := fmt.Fprintln(dst, "Derived state changes only; these are not raw kernel events or causal alerts."); err != nil {
		return err
	}
	if len(events) == 0 {
		_, err := fmt.Fprintln(dst, "- no state changes recorded yet")
		return err
	}
	if limit <= 0 || limit > len(events) {
		limit = len(events)
	}
	start := len(events) - limit
	table := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "TIME\t│\tLEVEL\t│\tSUBJECT\t│\tEVENT"); err != nil {
		return err
	}
	for _, event := range events[start:] {
		if _, err := fmt.Fprintf(table, "%s\t│\t%s\t│\t%s\t│\t%s\n",
			event.ObservedAtUTC.UTC().Format("15:04:05"), strings.ToUpper(displayText(event.Severity)),
			displayText(event.Subject), displayText(event.Message)); err != nil {
			return err
		}
	}
	return table.Flush()
}

func writePanelBox(dst io.Writer, title string, width int, render func(io.Writer) error) error {
	var body strings.Builder
	if err := render(&body); err != nil {
		return err
	}
	return writeBox(dst, title, body.String(), width)
}

func writeBox(dst io.Writer, title, body string, width int) error {
	boxWidth := minPositive(width, 180)
	if boxWidth < 32 {
		boxWidth = 32
	}
	innerWidth := boxWidth - 4
	title = strings.ToUpper(displayText(title))
	titleRunes := []rune(title)
	maxTitle := boxWidth - 6
	if maxTitle < 1 {
		maxTitle = 1
	}
	if len(titleRunes) > maxTitle {
		titleRunes = titleRunes[:maxTitle]
	}
	prefix := "╭─ " + string(titleRunes) + " "
	fill := boxWidth - len([]rune(prefix)) - 1
	if fill < 0 {
		fill = 0
	}
	if _, err := fmt.Fprintf(dst, "%s%s╮\n", prefix, strings.Repeat("─", fill)); err != nil {
		return err
	}
	trimmed := strings.Trim(body, "\n")
	lines := []string{""}
	if trimmed != "" {
		lines = wrappedDisplayLines(trimmed, innerWidth)
	}
	for _, line := range lines {
		line = strings.TrimRight(line, " ")
		if _, err := fmt.Fprintf(dst, "│ %s │\n", padRunes(line, innerWidth)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(dst, "╰%s╯\n", strings.Repeat("─", boxWidth-2))
	return err
}

func padRunes(value string, width int) string {
	runes := []rune(value)
	if len(runes) > width {
		runes = runes[:width]
	}
	return string(runes) + strings.Repeat(" ", width-len(runes))
}

func minPositive(value, maximum int) int {
	if value <= 0 || value > maximum {
		return maximum
	}
	return value
}

func findVMRow(rows []VMRow, name string) (VMRow, bool) {
	for _, row := range rows {
		if row.Name == name {
			return row, true
		}
	}
	return VMRow{}, false
}

func detailText(value string, available bool) string {
	if !available {
		return "-"
	}
	return displayText(value)
}

func detailList(values []string, available bool) string {
	if !available || len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ",")
}

func optionalFloat(value float64, available bool, precision int) string {
	if !available {
		return "-"
	}
	return fmt.Sprintf("%.*f", precision, value)
}

func optionalUint(value uint64, available bool) string {
	if !available {
		return "-"
	}
	return fmt.Sprintf("%d", value)
}

func optionalPercent(value float64, available bool) string {
	if !available {
		return "-"
	}
	return fmt.Sprintf("%.2f%%", value)
}
