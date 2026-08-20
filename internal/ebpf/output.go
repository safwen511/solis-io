package ebpf

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// WriteBlockLatency writes a host-wide block request latency summary.
func WriteBlockLatency(dst io.Writer, result BlockLatencyResult) error {
	return writeBlockLatency(dst, result, nil)
}

// WriteVMBlockLatency writes VM storage context followed by the host-wide
// block request latency summary.
func WriteVMBlockLatency(dst io.Writer, result BlockLatencyResult, context BlockLatencyVMContext) error {
	return writeBlockLatency(dst, result, &context)
}

// writeBlockLatency renders block latency in the package's stable operator-facing format.
func writeBlockLatency(dst io.Writer, result BlockLatencyResult, context *BlockLatencyVMContext) error {
	if _, err := fmt.Fprintln(dst, "Solis eBPF Block Latency (experimental)"); err != nil {
		return err
	}
	if context != nil {
		if err := writeBlockLatencyVMContext(dst, *context); err != nil {
			return err
		}
	}
	return writeBlockLatencyResult(dst, result)
}

// writeBlockLatencyResult renders block latency result in the package's stable operator-facing
// format.
func writeBlockLatencyResult(dst io.Writer, result BlockLatencyResult) error {
	if _, err := fmt.Fprintf(
		dst,
		"\nDuration:                 %s\nCorrelation key:           dev + sector (best effort)\nTotal completed requests:  %d\nAverage latency:           %.2f us\nMax latency:               %.2f us\n\nLatency histogram:\n",
		result.Duration,
		result.CompletedRequests,
		AverageLatencyMicroseconds(result),
		float64(result.MaxLatencyNS)/1000,
	); err != nil {
		return err
	}
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "LATENCY RANGE\tREQUESTS\tPERCENT"); err != nil {
		return err
	}
	for _, bucket := range LatencyHistogram(result) {
		if _, err := fmt.Fprintf(w, "%s\t%d\t%.2f%%\n", bucket.Range, bucket.Requests, bucket.Percent); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(dst, "\nSafety: temporary tracepoint programs detached; no payloads or process memory inspected")
	return err
}

// LatencyHistogramBucket is one stable, human-readable latency bucket.
type LatencyHistogramBucket struct {
	Range    string
	Requests uint64
	Percent  float64
}

// AverageLatencyMicroseconds returns the aggregate request latency average.
func AverageLatencyMicroseconds(result BlockLatencyResult) float64 {
	if result.CompletedRequests == 0 {
		return 0
	}
	return float64(result.TotalLatencyNS) / float64(result.CompletedRequests) / 1000
}

// LatencyHistogram returns the same buckets used by the text renderer. This
// keeps structured evidence and operator-facing output in lockstep.
func LatencyHistogram(result BlockLatencyResult) []LatencyHistogramBucket {
	buckets := make([]LatencyHistogramBucket, 0, len(latencyBucketLabels))
	for index, label := range latencyBucketLabels {
		percent := float64(0)
		if result.CompletedRequests > 0 {
			percent = float64(result.Histogram[index]) / float64(result.CompletedRequests) * 100
		}
		buckets = append(buckets, LatencyHistogramBucket{
			Range:    label,
			Requests: result.Histogram[index],
			Percent:  percent,
		})
	}
	return buckets
}

// writeBlockLatencyVMContext renders block latency VM context in the package's stable
// operator-facing format.
func writeBlockLatencyVMContext(dst io.Writer, context BlockLatencyVMContext) error {
	if _, err := fmt.Fprintf(dst, "\nVM-aware context:\nVictim:  %s\nSuspect: %s\n\nVM storage topology:\n", valueOrDash(context.Victim.Name), valueOrDash(context.Suspect.Name)); err != nil {
		return err
	}
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "TARGET\tVM\tQEMU_PID\tQCOW2_DISK\tMOUNTPOINT\tSOURCE_DEVICE\tFILESYSTEM\tPARENT_DEVICE\tPHYSICAL_DEVICE"); err != nil {
		return err
	}
	for _, target := range []struct {
		kind string
		vm   BlockLatencyVMTarget
	}{
		{"victim", context.Victim},
		{"suspect", context.Suspect},
	} {
		if _, err := fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			target.kind,
			valueOrDash(target.vm.Name),
			valueOrDash(target.vm.QEMUPID),
			valueOrDash(target.vm.Disk),
			valueOrDash(target.vm.Mountpoint),
			valueOrDash(target.vm.SourceDevice),
			valueOrDash(target.vm.Filesystem),
			valueOrDash(target.vm.ParentDevice),
			valueOrDash(target.vm.PhysicalDevice),
		); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if context.SharesPhysicalStorage {
		if _, err := fmt.Fprintf(
			dst,
			"\nShared storage path:\nSource device:   %s\nParent device:   %s\nPhysical device: %s\n",
			valueOrDash(context.SharedSourceDevice),
			valueOrDash(context.SharedParentDevice),
			valueOrDash(context.SharedPhysicalDevice),
		); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(dst, "\nWARNING: victim and suspect do not share a resolved physical storage device; continuing with host-wide latency collection."); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(
		dst,
		"Attribution scope: eBPF block latency is host/storage-path level; it is not precise per-VM block latency attribution.\nVM writer attribution: use solis qemu io-summary to compare victim and suspect QEMU write activity.",
	)
	return err
}

// valueOrDash trims a value and substitutes a dash when no value is available.
func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return "-"
	}
	return value
}

// WriteBlockEvents writes parsed block tracepoint formats.
func WriteBlockEvents(dst io.Writer, duration time.Duration, formats []TracepointFormat) error {
	if _, err := fmt.Fprintln(dst, "Solis eBPF Block Events (experimental)"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst, "\nMode:               read-only tracepoint format inspection\nRequested duration: %s\nAttachment:         none\n", duration); err != nil {
		return err
	}
	for _, format := range formats {
		name := format.Name
		if !strings.Contains(name, ":") {
			name = "block:" + name
		}
		if _, err := fmt.Fprintf(dst, "\nTracepoint: %s\nEvent ID:   %d\n", name, format.ID); err != nil {
			return err
		}
		w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
		if _, err := fmt.Fprintln(w, "USEFUL\tFIELD\tTYPE\tOFFSET\tSIZE\tSIGNED"); err != nil {
			return err
		}
		for _, field := range format.Fields {
			useful := "-"
			if isUsefulBlockField(field.Name) {
				useful = "yes"
			}
			signed := 0
			if field.Signed {
				signed = 1
			}
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\n", useful, field.Name, field.Type, field.Offset, field.Size, signed); err != nil {
				return err
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(dst, "\nSafety: no eBPF programs were loaded or attached")
	return err
}

// WriteBlockCount writes count-only eBPF tracepoint results.
func WriteBlockCount(dst io.Writer, result BlockCountResult) error {
	if _, err := fmt.Fprintln(dst, "Solis eBPF Block Count (experimental)"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst, "\nDuration:   %s\nCollection: event counts only; no tracepoint payloads\n\n", result.Duration); err != nil {
		return err
	}
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "TRACEPOINT\tEVENT COUNT\tEVENTS/SEC"); err != nil {
		return err
	}
	seconds := result.Duration.Seconds()
	if _, err := fmt.Fprintf(w, "block:block_rq_issue\t%d\t%.2f\n", result.IssueCount, float64(result.IssueCount)/seconds); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "block:block_rq_complete\t%d\t%.2f\n", result.CompleteCount, float64(result.CompleteCount)/seconds); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(dst, "\nSafety: temporary count-only programs detached; no payloads collected")
	return err
}

// WriteDoctor writes a deterministic eBPF readiness report.
func WriteDoctor(dst io.Writer, report Report) error {
	if _, err := fmt.Fprintln(dst, "Solis eBPF Doctor"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(dst); err != nil {
		return err
	}
	if err := writeChecks(dst, report); err != nil {
		return err
	}
	_, err := fmt.Fprintf(dst, "\nOverall readiness: %s\nAttach validation: NOT ATTEMPTED; readiness checks do not prove typed-BTF load/attach permission\nSafety: no eBPF programs were loaded or attached\n", readinessText(report))
	return err
}

// WriteBlockWatch writes the readiness-only experimental block-watch output.
func WriteBlockWatch(dst io.Writer, duration time.Duration, report Report) error {
	if _, err := fmt.Fprintln(dst, "Solis eBPF Block Watch (experimental)"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(dst); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst, "Mode:               readiness only\nRequested duration: %s\nAttachment:         none\n\n", duration); err != nil {
		return err
	}
	if err := writeChecks(dst, report); err != nil {
		return err
	}
	if Ready(report) {
		_, err := fmt.Fprintln(dst, "\nResult: READY; block tracepoints are available. No watch was started and no program was attached.")
		return err
	}
	_, err := fmt.Fprintln(dst, "\nResult: NOT READY; prerequisites or permissions are missing. No watch was started and no program was attached.")
	return err
}

// writeChecks renders checks in the package's stable operator-facing format.
func writeChecks(dst io.Writer, report Report) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "STATUS\tCHECK\tDETAIL"); err != nil {
		return err
	}
	for _, check := range report.Checks {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", check.Status, check.Name, check.Detail); err != nil {
			return err
		}
	}
	return w.Flush()
}

// readinessText reads iness text from its configured source.
func readinessText(report Report) string {
	if Ready(report) {
		return "READY"
	}
	return "NOT READY"
}
