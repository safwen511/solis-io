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

// WriteVictimTopology writes the victim-only topology artifact used when no
// suspect is selected.
func WriteVictimTopology(dst io.Writer, report Report) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Victim Storage Topology")
	fmt.Fprintln(w, "VM\tTENANT\tROLE\tQEMU_PID\tDISK\tMOUNTPOINT\tSOURCE_DEVICE\tPARENT_DEVICE\tPHYSICAL_DISK")
	fmt.Fprintf(
		w,
		"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		emptyDash(report.Victim.Name),
		emptyDash(report.Victim.Tenant),
		emptyDash(report.Victim.Role),
		emptyDash(report.Victim.QEMUPID),
		emptyDash(report.Victim.Disk),
		emptyDash(report.VictimStorage.Mountpoint),
		emptyDash(report.VictimStorage.SourceDevice),
		emptyDash(report.VictimStorage.ParentDevice),
		emptyDash(report.VictimStorage.PhysicalDisk),
	)
	fmt.Fprintln(w, "\nSelected suspect:\t-")
	fmt.Fprintln(w, "Reason:\tno dominant writer observed")
	return w.Flush()
}

// metric formats an available measurement or an explicit unavailable marker.
func metric(value float64, available bool) string {
	if !available {
		return "-"
	}
	return fmt.Sprintf("%.2f", value)
}

// yesNo formats a boolean as yes or no for human-readable reports.
func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

// emptyDash replaces empty text with a dash so table columns remain explicit.
func emptyDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}
