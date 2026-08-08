package incident

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// WriteExplanation writes a deterministic, table-like incident explanation.
func WriteExplanation(dst io.Writer, explanation Explanation) error {
	report := explanation.Report
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Solis I/O Incident Explanation")
	fmt.Fprintf(w, "Report directory:\t%s\n", report.Directory)
	fmt.Fprintf(w, "Victim:\t%s\n", explanation.Victim)
	fmt.Fprintf(w, "Suspect:\t%s\n", explanation.Suspect)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "HTTP evidence")
	fmt.Fprintln(w, "METRIC\tBASELINE\tDURING_NOISE\tPOST_NOISE")
	fmt.Fprintf(
		w,
		"Requests/sec\t%.2f\t%.2f\t%.2f\n",
		report.Baseline.RequestsPerSecond,
		report.DuringNoise.RequestsPerSecond,
		report.PostNoise.RequestsPerSecond,
	)
	fmt.Fprintf(
		w,
		"Latency (ms)\t%.3f\t%.3f\t%.3f\n",
		report.Baseline.TimePerRequestMS,
		report.DuringNoise.TimePerRequestMS,
		report.PostNoise.TimePerRequestMS,
	)
	fmt.Fprintf(
		w,
		"Failed requests\t%d\t%d\t%d\n",
		report.Baseline.FailedRequests,
		report.DuringNoise.FailedRequests,
		report.PostNoise.FailedRequests,
	)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Throughput drop:\t%.2f%%\n", explanation.Impact.ThroughputDropPct)
	fmt.Fprintf(w, "Latency increase:\t%.2f%%\n", explanation.Impact.LatencyIncreasePct)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "fio evidence")
	fmt.Fprintf(w, "IOPS:\t%s\n", report.FIO.IOPS)
	fmt.Fprintf(w, "Bandwidth:\t%s\n", report.FIO.Bandwidth)
	fmt.Fprintf(w, "Disk util:\t%.2f%%\n", report.FIO.DiskUtilPct)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Assessment:\t%s\n", explanation.Assessment)
	fmt.Fprintf(w, "Recommendation:\t%s\n", explanation.Recommendation)

	return w.Flush()
}
