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
	Iteration int
	Every     time.Duration
}

// WriteFrame renders one bounded dashboard frame.
func WriteFrame(dst io.Writer, view View, frame Frame) error {
	if _, err := fmt.Fprintf(dst,
		"Solis I/O Top (read-only)\n"+
			"Observed: %s  Window: %s  Interval: %s  Refresh: %s  Iteration: %d\n"+
			"VM status: %s  Pressure: high=%d low=%d idle=%d\n",
		view.ObservedAtUTC.UTC().Format(time.RFC3339),
		displayText(view.Duration),
		displayText(view.Interval),
		frame.Every,
		frame.Iteration,
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
	if _, err := fmt.Fprintln(dst); err != nil {
		return err
	}

	table := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "VM\tTENANT\tROLE\tPRESSURE\tWRITE_MIB/S\tATTR_OPS\tP95_MS~\tATTR_STATE"); err != nil {
		return err
	}
	for _, row := range view.Rows {
		if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
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
	_, err := fmt.Fprintln(dst, "\nCtrl-C quits. P95 values marked ~ are fixed-bucket estimates; evidence does not prove customer impact or root cause.")
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
