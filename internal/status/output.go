package status

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// WriteHuman renders a compact terminal table and any procfs warnings.
func WriteHuman(dst io.Writer, report Report) error {
	if _, err := fmt.Fprintf(dst, "Solis VM Status\nDuration: %s\nInterval: %s\n\n", report.Duration, report.Interval); err != nil {
		return err
	}
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "VM\tTENANT\tROLE\tSTATE\tIP\tQEMU_PID\tQCOW2_DISK\tPHYSICAL_DISK\tAVG_WRITE_MIB/S\tAVG_SYSCW/S\tPRESSURE"); err != nil {
		return err
	}
	for _, vm := range report.VMs {
		if _, err := fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			vm.Name,
			vm.Tenant,
			vm.Role,
			vm.State,
			vm.IP,
			vm.QEMUPID,
			vm.Disk,
			vm.PhysicalDisk,
			metric(vm.AverageWriteMiBPerSecond, vm.IOAvailable),
			metric(vm.AverageSyscwPerSecond, vm.IOAvailable),
			strings.ToUpper(vm.Pressure),
		); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	var warnings []VMStatus
	for _, vm := range report.VMs {
		if !vm.IOAvailable {
			warnings = append(warnings, vm)
		}
	}
	if len(warnings) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(dst, "\nWarnings:"); err != nil {
		return err
	}
	for _, vm := range warnings {
		if _, err := fmt.Fprintf(dst, "- %s: %s\n", vm.Name, vm.Reason); err != nil {
			return err
		}
	}
	return nil
}

// WriteJSON renders one deterministic JSON document.
func WriteJSON(dst io.Writer, report Report) error {
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func metric(value float64, available bool) string {
	if !available {
		return "-"
	}
	return fmt.Sprintf("%.2f", value)
}
