package top

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// Frame identifies one refresh of the terminal dashboard.
type Frame struct {
	Iteration   int
	Every       time.Duration
	SelectedVM  string
	Sort        string
	Interactive bool
	ShowHelp    bool
}

// WriteFrame renders one bounded dashboard frame.
func WriteFrame(dst io.Writer, view View, frame Frame) error {
	if _, err := fmt.Fprintf(dst,
		"Solis I/O Top (read-only)\n"+
			"Observed: %s  Window: %s  Interval: %s  Refresh: %s  Iteration: %d  Sort: %s\n"+
			"VM status: %s  Pressure: high=%d low=%d idle=%d\n",
		view.ObservedAtUTC.UTC().Format(time.RFC3339),
		displayText(view.Duration),
		displayText(view.Interval),
		frame.Every,
		frame.Iteration,
		displayText(frame.Sort),
		strings.ToUpper(displayText(view.StatusState)),
		view.Pressures.High,
		view.Pressures.Low,
		view.Pressures.Idle,
	); err != nil {
		return err
	}
	if err := writeHostSummary(dst, view.Host); err != nil {
		return err
	}
	if err := writeStorageSummary(dst, view.Storage); err != nil {
		return err
	}
	if err := writeAttributionSummary(dst, view.Attribution); err != nil {
		return err
	}
	if err := writeAttributionLoss(dst, view.Attribution); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(dst); err != nil {
		return err
	}

	table := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "\tVM\tTENANT\tROLE\tPRESSURE\tWRITE_MIB/S\tATTR_OPS\tP95_MS~\tATTR_STATE"); err != nil {
		return err
	}
	for _, row := range view.Rows {
		marker := " "
		if row.Name == frame.SelectedVM {
			marker = ">"
		}
		if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			marker,
			row.Name,
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
		if _, err := fmt.Fprintln(dst, "No running VMs with provider-visible status are available."); err != nil {
			return err
		}
	}
	if frame.SelectedVM != "" {
		if err := writeSelectedVM(dst, view, frame.SelectedVM); err != nil {
			return err
		}
	}
	if frame.ShowHelp {
		if err := writeHelp(dst); err != nil {
			return err
		}
	}
	footer := "Ctrl-C quits."
	if frame.Interactive {
		footer = "Keys: j/k or arrows select, n/p/w/o/l sort, r refresh, ? help, q quit."
	}
	_, err := fmt.Fprintf(dst, "\n%s P95 values marked ~ are fixed-bucket estimates; evidence does not prove customer impact or root cause.\n", footer)
	return err
}

func writeHostSummary(dst io.Writer, view HostView) error {
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

func writeStorageSummary(dst io.Writer, views []StorageView) error {
	if len(views) == 0 {
		_, err := fmt.Fprintln(dst, "Storage: no mapped physical device is available")
		return err
	}
	for _, view := range views {
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
		_, err := fmt.Fprintln(dst, "eBPF VM attribution: NOT REQUESTED (use --include-ebpf-latency; privileged access is normally required)")
		return err
	case !view.CollectorAvailable:
		_, err := fmt.Fprintf(dst, "eBPF VM attribution: UNAVAILABLE  status=%s\n", displayText(view.Status))
		return err
	default:
		quality := strings.ToUpper(displayText(view.Quality))
		_, err := fmt.Fprintf(dst,
			"eBPF VM attribution: %s  host_ops=%d  host_p95_ms~=%.3f  attributed=%d (%.2f%%)  unattributed=%d (%.2f%%)  matched_vms=%d\n",
			quality,
			view.HostTotalOps,
			view.HostP95MS,
			view.AttributedOps,
			view.AttributedPercent,
			view.UnattributedOps,
			view.UnattributedPercent,
			view.MatchedVMCount,
		)
		return err
	}
}

func writeAttributionLoss(dst io.Writer, view AttributionView) error {
	if !view.Requested || !view.CollectorAvailable {
		return nil
	}
	loss := view.Loss
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

func writeSelectedVM(dst io.Writer, view View, name string) error {
	row, ok := findVMRow(view.Rows, name)
	if !ok {
		return nil
	}
	if _, err := fmt.Fprintf(dst,
		"\nSelected VM: %s  tenant=%s role=%s  pressure=%s (%s)\n",
		row.Name,
		row.Tenant,
		row.Role,
		strings.ToUpper(row.Pressure),
		row.PressureReason,
	); err != nil {
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

func writeHelp(dst io.Writer) error {
	_, err := fmt.Fprintln(dst, "\nHelp:\n- j/down and k/up move the selected VM\n- n=name p=pressure w=write o=attributed operations l=latency\n- r starts the next bounded refresh; q or Ctrl-C exits\n- selection and sorting are display-only and never modify a VM")
	return err
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
