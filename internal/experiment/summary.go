package experiment

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// WriteSummary writes a deterministic, human-readable experiment diagnosis.
func WriteSummary(dst io.Writer, report Report) error {
	impact, err := CalculateImpact(report)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Solis I/O Experiment Summary")
	fmt.Fprintf(w, "Report directory:\t%s\n", report.Directory)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "HTTP workload")
	fmt.Fprintln(w, "PHASE\tREQ/S\tLATENCY_MS\tFAILED\tTRANSFER_RATE")
	writeHTTPRow(w, "Baseline", report.Baseline)
	writeHTTPRow(w, "During noise", report.DuringNoise)
	writeHTTPRow(w, "Post noise", report.PostNoise)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Impact")
	fmt.Fprintf(w, "Throughput drop:\t%.2f%%\n", impact.ThroughputDropPct)
	fmt.Fprintf(w, "Latency increase:\t%.2f%%\n", impact.LatencyIncreasePct)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "fio noise")
	fmt.Fprintf(w, "IOPS:\t%s\n", report.FIO.IOPS)
	fmt.Fprintf(w, "Bandwidth:\t%s\n", report.FIO.Bandwidth)
	fmt.Fprintf(w, "Disk util:\t%.2f%%\n", report.FIO.DiskUtilPct)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Conclusion:\t%s\n", conclusion(impact.ThroughputDropPct, impact.LatencyIncreasePct))

	return w.Flush()
}

func writeHTTPRow(w io.Writer, phase string, metrics HTTPMetrics) {
	fmt.Fprintf(
		w,
		"%s\t%.2f\t%.3f\t%d\t%.2f %s\n",
		phase,
		metrics.RequestsPerSecond,
		metrics.TimePerRequestMS,
		metrics.FailedRequests,
		metrics.TransferRate,
		metrics.TransferRateUnit,
	)
}

func conclusion(throughputDrop, latencyIncrease float64) string {
	switch {
	case throughputDrop > 0 && latencyIncrease > 0:
		return "Noisy-neighbor impact observed: throughput decreased and latency increased during fio noise."
	case throughputDrop > 0:
		return "Possible noisy-neighbor impact: throughput decreased during fio noise."
	case latencyIncrease > 0:
		return "Possible noisy-neighbor impact: latency increased during fio noise."
	default:
		return "No HTTP slowdown was observed during fio noise."
	}
}
