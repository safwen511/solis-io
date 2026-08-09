package discovery

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Write emits a deterministic suspect-discovery table.
func Write(dst io.Writer, report Report) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Suspect discovery")
	fmt.Fprintf(w, "Victim:\t%s\n", emptyDash(report.Victim.Name))
	fmt.Fprintf(w, "Victim physical disk:\t%s\n\n", emptyDash(report.VictimStorage.PhysicalDisk))
	fmt.Fprintln(w, "CANDIDATE\tTENANT\tROLE\tSHARED_DISK\tAVG_WRITE_MIB/S\tMAX_WRITE_MIB/S\tAVG_SYSCW/S\tMAX_SYSCW/S\tSCORE\tREASON")
	if len(report.Candidates) == 0 {
		fmt.Fprintln(w, "-\t-\t-\t-\t-\t-\t-\t-\tLOW\tno shared-storage candidates")
	}
	for _, candidate := range report.Candidates {
		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			emptyDash(candidate.VM.Name),
			emptyDash(candidate.VM.Tenant),
			emptyDash(candidate.VM.Role),
			yesNo(candidate.SharedDisk),
			metric(candidate.Summary.AverageWriteMiBPerSecond, candidate.Summary.Available),
			metric(candidate.Summary.MaxWriteMiBPerSecond, candidate.Summary.Available),
			metric(candidate.Summary.AverageSyscwPerSecond, candidate.Summary.Available),
			metric(candidate.Summary.MaxSyscwPerSecond, candidate.Summary.Available),
			emptyDash(candidate.Score),
			emptyDash(candidate.Reason),
		)
	}
	selected := "-"
	if report.Selected != nil {
		selected = report.Selected.VM.Name
	}
	fmt.Fprintf(w, "\nSelected suspect:\t%s\n", selected)
	fmt.Fprintf(w, "Reason:\t%s\n", emptyDash(report.SelectionReason))
	return w.Flush()
}

func metric(value float64, available bool) string {
	if !available {
		return "-"
	}
	return fmt.Sprintf("%.2f", value)
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func emptyDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}
