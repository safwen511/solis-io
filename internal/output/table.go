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
func VMDetail(dst io.Writer, vm inventory.VM) error {
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
		{"QEMU command line", vm.QEMUCmdline},
	}

	for _, row := range rows {
		fmt.Fprintf(w, "%s:\t%s\n", row[0], emptyDash(row[1]))
	}

	return w.Flush()
}

func emptyDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}

	return value
}
