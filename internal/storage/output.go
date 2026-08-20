package storage

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
)

// Write emits a deterministic, table-like storage snapshot.
func Write(dst io.Writer, snapshot Snapshot) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Storage Snapshot")
	fmt.Fprintf(w, "Victim selector:\t%s\n", snapshot.VictimSelector)
	fmt.Fprintf(w, "Suspect selector:\t%s\n", snapshot.SuspectSelector)
	fmt.Fprintln(w)

	writeVMTargetRows(w, snapshot.Targets)

	fmt.Fprintln(w, "Host device snapshot")
	fmt.Fprintln(w, "PHYSICAL_DISK\tREADS_COMPLETED\tWRITES_COMPLETED\tSECTORS_READ\tSECTORS_WRITTEN\tIO_IN_PROGRESS\tWEIGHTED_IO_TIME_MS")
	for _, device := range snapshot.Devices {
		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			emptyDash(device.PhysicalDisk),
			counterText(device.ReadsCompleted),
			counterText(device.WritesCompleted),
			counterText(device.SectorsRead),
			counterText(device.SectorsWritten),
			counterText(device.IOInProgress),
			counterText(device.WeightedIOTimeMS),
		)
	}

	return w.Flush()
}

// writeVMTargets renders VM targets in the package's stable operator-facing format.
func writeVMTargets(dst io.Writer, targets []VMTarget) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	writeVMTargetRows(w, targets)
	return w.Flush()
}

// writeVMTargetRows renders VM target rows in the package's stable operator-facing format.
func writeVMTargetRows(w io.Writer, targets []VMTarget) {
	fmt.Fprintln(w, "VM storage targets")
	fmt.Fprintln(w, "TARGET\tVM\tTENANT\tROLE\tQEMU_PID\tDISK\tSOURCE_DEVICE\tPARENT_DEVICE\tPHYSICAL_DISK")
	for _, target := range targets {
		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			emptyDash(target.TargetType),
			emptyDash(target.VM.Name),
			emptyDash(target.VM.Tenant),
			emptyDash(target.VM.Role),
			emptyDash(target.VM.QEMUPID),
			emptyDash(target.VM.Disk),
			emptyDash(target.Storage.SourceDevice),
			emptyDash(target.Storage.ParentDevice),
			emptyDash(target.Storage.PhysicalDisk),
		)
	}
	fmt.Fprintln(w)
}

// counterText formats a counter value or a dash when its source is unavailable.
func counterText(counter Counter) string {
	if !counter.Available {
		return "-"
	}
	return strconv.FormatUint(counter.Value, 10)
}

// emptyDash replaces empty text with a dash so table columns remain explicit.
func emptyDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}
