package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/safwen511/solis-io/internal/inventory"
)

// InventoryTable writes the inventory summary in a tabular format.
func InventoryTable(dst io.Writer, vms []inventory.VM) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTENANT\tROLE\tSTATE\tPLAN_IP\tLEASE_IP\tQEMU_PID\tDISK")
	for _, vm := range vms {
		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			vm.Name,
			vm.Tenant,
			vm.Role,
			emptyDash(vm.State),
			emptyDash(vm.IPPlan),
			emptyDash(vm.IPLease),
			emptyDash(vm.QEMUPID),
			emptyDash(vm.Disk),
		)
	}

	return w.Flush()
}

// VMDetail writes a readable detail view of one VM.
func VMDetail(dst io.Writer, vm inventory.VM, verbose bool) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	rows := [][2]string{
		{"Name", vm.Name},
		{"Tenant", vm.Tenant},
		{"Role", vm.Role},
		{"Network", vm.Network},
		{"Planned IP", vm.IPPlan},
		{"Lease IP", vm.IPLease},
		{"State", vm.State},
		{"Memory MB", vm.Memory},
		{"VCPUs", vm.VCPUs},
		{"Disk GB", vm.DiskGB},
		{"Disk path", vm.Disk},
		{"QEMU PID", vm.QEMUPID},
		{"QEMU executable", qemuExecutable(vm.QEMUCmdline)},
		{"QEMU disk backend path", qemuDiskBackend(vm)},
		{"Guest agent channel", yesNo(strings.Contains(vm.QEMUCmdline, "org.qemu.guest_agent.0"))},
	}
	if verbose {
		rows = append(rows, [2]string{"QEMU command line", vm.QEMUCmdline})
	}

	for _, row := range rows {
		fmt.Fprintf(w, "%s:\t%s\n", row[0], emptyDash(row[1]))
	}

	return w.Flush()
}

// qemuExecutable derives stable operator-facing text for QEMU executable.
func qemuExecutable(cmdline string) string {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return ""
	}

	return fields[0]
}

// qemuDiskBackend derives stable operator-facing text for QEMU disk backend.
func qemuDiskBackend(vm inventory.VM) string {
	if strings.TrimSpace(vm.Disk) != "" {
		return vm.Disk
	}

	var backend string
	remaining := vm.QEMUCmdline
	const marker = `"filename":"`
	for {
		start := strings.Index(remaining, marker)
		if start == -1 {
			break
		}

		remaining = remaining[start+len(marker):]
		end := strings.IndexByte(remaining, '"')
		if end == -1 {
			break
		}

		candidate := remaining[:end]
		if isDiskImage(candidate) {
			backend = candidate
		}
		remaining = remaining[end+1:]
	}

	return backend
}

// isDiskImage reports whether disk image.
func isDiskImage(path string) bool {
	path = strings.ToLower(path)
	return strings.HasSuffix(path, ".qcow2") ||
		strings.HasSuffix(path, ".raw") ||
		strings.HasSuffix(path, ".img")
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
