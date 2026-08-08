package ebpf

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"
)

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
