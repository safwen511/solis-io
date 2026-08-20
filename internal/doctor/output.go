package doctor

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Write emits a deterministic, table-like readiness report.
func Write(dst io.Writer, report Report) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Solis Doctor")
	fmt.Fprintln(w)
	if len(report.Config) > 0 {
		writeSection(w, "Product configuration:", report.Config)
	}
	writeSection(w, "Host checks:", report.Host)
	if len(report.Lab) > 0 {
		writeSection(w, "Lab checks:", report.Lab)
	}
	writeSection(w, "VM inventory checks:", report.Inventory)
	writeSection(w, "Storage checks:", report.Storage)
	writeSection(w, "QEMU I/O permission check:", report.QEMU)
	if len(report.Observability) > 0 {
		writeSection(w, "Optional observability:", report.Observability)
	}
	if len(report.Privacy) > 0 {
		writeSection(w, "Privacy and safety:", report.Privacy)
	}
	fmt.Fprintf(w, "Overall result:\t%s\n", OverallResult(report))
	return w.Flush()
}

// writeSection renders section in the package's stable operator-facing format.
func writeSection(dst io.Writer, title string, checks []Check) {
	fmt.Fprintln(dst, title)
	fmt.Fprintln(dst, "STATUS\tCHECK\tDETAIL\tREMEDIATION")
	for _, check := range checks {
		fmt.Fprintf(
			dst,
			"%s\t%s\t%s\t%s\n",
			check.Status,
			valueOrDash(check.Name),
			valueOrDash(check.Detail),
			valueOrDash(check.Remediation),
		)
	}
	fmt.Fprintln(dst)
}

// valueOrDash trims a value and substitutes a dash when no value is available.
func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}
