package ebpf

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

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
	_, err := fmt.Fprintf(dst, "\nOverall readiness: %s\nSafety: no eBPF programs were loaded or attached\n", readinessText(report))
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

func readinessText(report Report) string {
	if Ready(report) {
		return "READY"
	}
	return "NOT READY"
}
