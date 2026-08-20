package watch

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// WriteIteration writes one compact, deterministic observation summary.
func WriteIteration(dst io.Writer, summary IterationSummary) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Noisy-neighbor watch iteration")
	fmt.Fprintf(w, "Timestamp:\t%s\n", summary.Timestamp.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(w, "Victim:\t%s\n", dash(summary.Victim))
	fmt.Fprintf(w, "Selected suspect:\t%s\n", dash(summary.Suspect))
	fmt.Fprintf(w, "Suspect score:\t%s\n", dash(summary.Score))
	fmt.Fprintf(w, "Reason:\t%s\n", dash(summary.Reason))
	fmt.Fprintf(w, "Avg write MiB/s:\t%s\n", metric(summary.AverageWriteMiBPerSec, summary.SuspectMetricsAvailable))
	fmt.Fprintf(w, "Avg syscw/s:\t%s\n", metric(summary.AverageSyscwPerSec, summary.SuspectMetricsAvailable))
	fmt.Fprintf(w, "eBPF VM attribution quality:\t%s\n", dash(summary.EBPFVMAttributionQuality))
	fmt.Fprintf(w, "eBPF unattributed percent:\t%s\n", metric(summary.EBPFVMUnattributedPercent, summary.EBPFVMAttributionAvailable))
	fmt.Fprintf(w, "Verdict:\t%s\n", dash(summary.Verdict))
	return w.Flush()
}

// WriteAlert writes the compact alert banner for an alerting iteration.
func WriteAlert(dst io.Writer, summary IterationSummary) error {
	if _, err := fmt.Fprintln(dst, "ALERT: likely storage-neighbor pressure detected"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst, "victim: %s\n", dash(summary.Victim)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst, "suspect: %s\n", dash(summary.Suspect)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(dst, "reason: %s\n", dash(summary.Reason))
	return err
}

// WriteFinal writes watch lifetime counters.
func WriteFinal(dst io.Writer, summary FinalSummary) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Noisy-neighbor watch summary")
	fmt.Fprintf(w, "Iterations run:\t%d\n", summary.Iterations)
	fmt.Fprintf(w, "Alerts observed:\t%d\n", summary.Alerts)
	fmt.Fprintf(w, "Captures written:\t%d\n", summary.Captures)
	return w.Flush()
}

// metric formats an available measurement or an explicit unavailable marker.
func metric(value float64, available bool) string {
	if !available {
		return "-"
	}
	return fmt.Sprintf("%.2f", value)
}

// dash uses a dash to represent a value that was not observed.
func dash(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return "-"
	}
	return value
}
