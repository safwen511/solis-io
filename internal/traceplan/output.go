package traceplan

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/safwen511/solis-io/internal/inventory"
)

// Write emits a deterministic, human-readable trace plan.
func Write(dst io.Writer, plan Plan) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Trace Plan")
	fmt.Fprintf(w, "Victim selector:\t%s\n", plan.VictimSelector)
	fmt.Fprintf(w, "Suspect selector:\t%s\n", plan.SuspectSelector)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Victim targets")
	writeTargetHeader(w)
	for _, vm := range plan.VictimTargets {
		writeTarget(w, vm, victimNote(vm, plan.VictimIsTenant))
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Suspect target")
	writeTargetHeader(w)
	writeTarget(w, plan.SuspectTarget, "suspect VM")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Host storage mapping")
	fmt.Fprintln(w, "VM\tDISK\tMOUNTPOINT\tSOURCE_DEVICE\tFILESYSTEM\tPARENT_DEVICE\tPHYSICAL_DISK")
	for _, vm := range storageTargets(plan) {
		mapping := plan.HostStorage[vm.Name]
		diskPath := mapping.DiskPath
		if diskPath == "" {
			diskPath = vm.Disk
		}
		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			vm.Name,
			emptyDash(diskPath),
			emptyDash(mapping.Mountpoint),
			emptyDash(mapping.SourceDevice),
			emptyDash(mapping.Filesystem),
			emptyDash(mapping.ParentDevice),
			emptyDash(mapping.PhysicalDisk),
		)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Host evidence to collect")
	writeRows(w, [][2]string{
		{"QEMU PID per target VM", "Attribute host I/O to each victim and suspect process."},
		{"Disk path per target VM", "Map each VM to its qcow2 backing file."},
		{"Host block device backing qcow2 files", "Resolve qcow2 files to the shared physical or logical device."},
		{"Per-VM read/write rate", "Compare victim I/O demand with suspect write pressure."},
		{"Per-VM latency histogram", "Measure latency distribution and tail amplification by VM."},
		{"Host disk utilization", "Identify saturation during the incident window."},
		{"Queue depth / await / svctm equivalents", "Collect available host queueing and service-time metrics."},
		{"Application latency correlation", "Correlate storage evidence with application latency over time."},
	})
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Future eBPF probes")
	writeRows(w, [][2]string{
		{"block:block_rq_issue", "Record block request issue timestamps."},
		{"block:block_rq_complete", "Record completions and calculate request latency."},
		{"QEMU process PID filters", "Restrict attribution to victim and suspect QEMU processes."},
		{"Latency histogram per VM", "Aggregate completion latency into per-VM buckets."},
		{"Bytes per VM", "Aggregate transferred bytes for each VM."},
		{"Operation type read/write", "Separate read traffic from write traffic."},
		{"Timestamp correlation", "Align block events with application-latency timestamps."},
	})
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Interpretation logic")
	writeRows(w, [][2]string{
		{
			"Victim latency rises; suspect write rate and host block latency rise",
			"Classify as probable noisy-neighbor storage interference.",
		},
		{
			"Victim app latency rises; host block latency does not",
			"Classify as likely guest/app/internal bottleneck.",
		},
		{
			"Host block latency rises; no single suspect dominates",
			"Classify as shared infrastructure pressure.",
		},
	})

	return w.Flush()
}

func storageTargets(plan Plan) []inventory.VM {
	targets := append([]inventory.VM(nil), plan.VictimTargets...)
	for _, vm := range targets {
		if vm.Name == plan.SuspectTarget.Name {
			return targets
		}
	}
	return append(targets, plan.SuspectTarget)
}

func writeTargetHeader(w io.Writer) {
	fmt.Fprintln(w, "NAME\tTENANT\tROLE\tPLAN_IP\tLEASE_IP\tQEMU_PID\tDISK\tNOTE")
}

func writeTarget(w io.Writer, vm inventory.VM, note string) {
	fmt.Fprintf(
		w,
		"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		vm.Name,
		vm.Tenant,
		vm.Role,
		emptyDash(vm.IPPlan),
		emptyDash(vm.IPLease),
		emptyDash(vm.QEMUPID),
		emptyDash(vm.Disk),
		emptyDash(note),
	)
}

func writeRows(w io.Writer, rows [][2]string) {
	fmt.Fprintln(w, "ITEM / SIGNAL\tPURPOSE / CLASSIFICATION")
	for _, row := range rows {
		fmt.Fprintf(w, "%s\t%s\n", row[0], row[1])
	}
}

func victimNote(vm inventory.VM, victimIsTenant bool) string {
	if !victimIsTenant {
		return "selected victim VM"
	}

	switch vm.Role {
	case "db":
		return "likely victim DB VM"
	case "web":
		return "likely victim web VM"
	default:
		return "tenant VM"
	}
}

func emptyDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}
