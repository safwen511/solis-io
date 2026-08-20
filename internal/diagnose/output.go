package diagnose

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/qemuio"
	"github.com/safwen511/solis-io/internal/storage"
)

// Write emits the combined diagnosis in deterministic, table-like form.
func Write(dst io.Writer, report Report) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Solis Noisy Neighbor Diagnosis")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Inputs")
	fmt.Fprintf(w, "Report directory:\t%s\n", valueOrDash(report.Inputs.ReportDirectory))
	fmt.Fprintf(w, "Victim:\t%s\n", valueOrDash(report.Inputs.Victim))
	fmt.Fprintf(w, "Suspect:\t%s\n", valueOrDash(report.Inputs.Suspect))
	fmt.Fprintf(w, "Duration:\t%s\n", report.Inputs.Duration)
	fmt.Fprintf(w, "Interval:\t%s\n", report.Inputs.Interval)
	fmt.Fprintf(w, "Config source:\t%s\n", valueOrDash(report.Inputs.ConfigSource))
	thresholds := qemuio.EffectiveThresholds(report.Inputs.Thresholds)
	fmt.Fprintf(w, "Write threshold MiB/s:\t%.2f\n", thresholds.WriteMiBPerSecond)
	fmt.Fprintf(w, "Write syscall threshold/s:\t%.2f\n", thresholds.WriteSyscallsPerSecond)
	fmt.Fprintf(w, "Dominance ratio:\t%.2f\n\n", thresholds.DominanceRatio)

	fmt.Fprintln(w, "Experiment evidence")
	if !report.ExperimentAvailable {
		fmt.Fprintln(w, "No report directory supplied.")
		fmt.Fprintln(w, "Application-level slowdown evidence unavailable in this live-only run.")
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w, "METRIC\tBASELINE\tDURING_NOISE\tPOST_NOISE")
		fmt.Fprintf(
			w,
			"Requests/sec\t%.2f\t%.2f\t%.2f\n",
			report.Experiment.Baseline.RequestsPerSecond,
			report.Experiment.DuringNoise.RequestsPerSecond,
			report.Experiment.PostNoise.RequestsPerSecond,
		)
		fmt.Fprintf(
			w,
			"Latency (ms)\t%.3f\t%.3f\t%.3f\n",
			report.Experiment.Baseline.TimePerRequestMS,
			report.Experiment.DuringNoise.TimePerRequestMS,
			report.Experiment.PostNoise.TimePerRequestMS,
		)
		fmt.Fprintf(
			w,
			"Failed requests\t%d\t%d\t%d\n",
			report.Experiment.Baseline.FailedRequests,
			report.Experiment.DuringNoise.FailedRequests,
			report.Experiment.PostNoise.FailedRequests,
		)
		fmt.Fprintf(w, "Throughput drop:\t%.2f%%\n", report.Impact.ThroughputDropPct)
		fmt.Fprintf(w, "Latency increase:\t%.2f%%\n\n", report.Impact.LatencyIncreasePct)
	}

	fmt.Fprintln(w, "Storage topology")
	fmt.Fprintln(w, "TARGET\tVM\tTENANT\tROLE\tQEMU_PID\tDISK\tSOURCE_DEVICE\tPARENT_DEVICE\tPHYSICAL_DISK")
	for _, target := range report.Storage.Targets {
		writeStorageTarget(w, target)
	}
	fmt.Fprintf(w, "Shared physical disk:\t%s\n\n", sharedDiskText(report.StorageTopologyAvailable, report.SharedPhysicalDisk))
	if report.Discovery != nil {
		if err := discovery.Write(w, *report.Discovery); err != nil {
			return err
		}
		fmt.Fprintln(w)
	}

	if report.Discovery == nil || report.Discovery.Selected != nil {
		fmt.Fprintln(w, "QEMU I/O evidence")
		fmt.Fprintf(w, "Victim average write MiB/s:\t%s\n", qemuValue(report.QEMU.VictimAverageWriteMiBPerSecond, report.QEMU.VictimDataAvailable))
		fmt.Fprintf(w, "Suspect average write MiB/s:\t%s\n", qemuValue(report.QEMU.SuspectAverageWriteMiBPerSecond, report.QEMU.SuspectDataAvailable))
		fmt.Fprintf(w, "Suspect/victim write ratio:\t%s\n", valueOrDash(report.QEMU.WriteRatio))
		fmt.Fprintf(w, "Dominant writer:\t%s\n", valueOrDash(report.QEMU.DominantWriter))
		fmt.Fprintf(w, "Victim average syscw/s:\t%s\n", qemuValue(report.QEMU.VictimAverageSyscwPerSecond, report.QEMU.VictimDataAvailable))
		fmt.Fprintf(w, "Suspect average syscw/s:\t%s\n", qemuValue(report.QEMU.SuspectAverageSyscwPerSecond, report.QEMU.SuspectDataAvailable))
		fmt.Fprintf(w, "Suspect/victim syscw ratio:\t%s\n", valueOrDash(report.QEMU.SyscwRatio))
		fmt.Fprintf(w, "Suspect write syscall pressure:\t%s\n", valueOrDash(report.QEMU.WriteSyscallPressure))
		fmt.Fprintf(w, "Dominant write syscall source:\t%s\n", valueOrDash(report.QEMU.DominantWriteSyscallSource))
		fmt.Fprintf(w, "QEMU I/O conclusion:\t%s\n", valueOrDash(report.QEMU.Conclusion))
		writeQEMUErrors(w, report)
		fmt.Fprintln(w)
	}
	if report.EBPFLatency != nil {
		fmt.Fprintln(w, "eBPF block latency evidence")
		if err := ebpf.WriteBlockLatencyEvidence(w, *report.EBPFLatency); err != nil {
			return err
		}
		fmt.Fprintln(w)
	}
	if report.EBPFVMAttribution != nil {
		writeEBPFVMAttribution(w, report)
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Verdict")
	fmt.Fprintln(w, report.Verdict)
	return w.Flush()
}

// writeEBPFVMAttribution renders eBPF VM attribution in the package's stable operator-facing
// format.
func writeEBPFVMAttribution(dst io.Writer, report Report) {
	evidence := report.EBPFVMAttribution
	assessment := AssessEBPFVMAttribution(report)
	fmt.Fprintln(dst, "eBPF VM-attributed block latency")
	fmt.Fprintf(dst, "Available:\t%s\n", yesNo(assessment.Available))
	fmt.Fprintf(dst, "Collector available:\t%s\n", yesNo(evidence.Availability.Available))
	fmt.Fprintf(dst, "Status:\t%s\n", valueOrDash(evidence.Availability.Status))
	fmt.Fprintf(dst, "Attribution quality:\t%s\n", valueOrDash(evidence.AttributionQuality))
	fmt.Fprintf(dst, "Attributed operations:\t%d\n", evidence.AttributionSummary.AttributedOps)
	fmt.Fprintf(dst, "Unattributed operations:\t%d\n", evidence.AttributionSummary.UnattributedOps)
	fmt.Fprintf(dst, "Attributed percent:\t%.2f%%\n", evidence.AttributionSummary.AttributedPercent)
	fmt.Fprintf(dst, "Unattributed percent:\t%.2f%%\n", evidence.Unattributed.UnattributedPercent)
	fmt.Fprintf(dst, "Matched VM count:\t%d\n", evidence.AttributionSummary.MatchedVMCount)
	fmt.Fprintf(dst, "Victim attributed operations:\t%d\n", assessment.VictimTotalOps)
	fmt.Fprintf(dst, "Victim p95 latency ms:\t%.3f\n", assessment.VictimP95MS)
	fmt.Fprintf(dst, "Suspect attributed operations:\t%d\n", assessment.SuspectTotalOps)
	fmt.Fprintf(dst, "Suspect p95 latency ms:\t%.3f\n", assessment.SuspectP95MS)
	fmt.Fprintln(dst, "TARGET\tVM\tTOTAL_OPS\tREAD_OPS\tWRITE_OPS\tP95_MS\tATTRIBUTION_QUALITY")
	for _, vm := range evidence.VMs {
		fmt.Fprintf(dst, "%s\t%s\t%d\t%d\t%d\t%.3f\t%s\n",
			ebpfVMTargetType(report, vm.Name), valueOrDash(vm.Name), vm.TotalOps, vm.ReadOps, vm.WriteOps,
			vm.LatencyP95MS, valueOrDash(vm.AttributionQuality))
	}
	if !evidence.Availability.Available && strings.TrimSpace(evidence.Availability.Error) != "" {
		fmt.Fprintf(dst, "Unavailable reason:\t%s\n", strings.Join(strings.Fields(evidence.Availability.Error), " "))
	}
	fmt.Fprintln(dst, "Scope:\texperimental blkcg/cgroup-ID correlation to validated local libvirt VM mappings")
	fmt.Fprintln(dst, "Privacy:\tno guest payloads, guest files, process arguments, environments, SQL text, table data, request bodies, response bodies, or secrets were collected")
}

// ebpfVMTargetType derives stable operator-facing text for eBPF VM target type.
func ebpfVMTargetType(report Report, name string) string {
	var roles []string
	for _, target := range report.Storage.Targets {
		if target.VM.Name != name {
			continue
		}
		for _, role := range strings.Split(target.TargetType, ",") {
			role = strings.TrimSpace(role)
			if role != "" {
				roles = append(roles, role)
			}
		}
	}
	if len(roles) == 0 {
		return "other"
	}
	return strings.Join(roles, ",")
}

// writeStorageTarget renders storage target in the package's stable operator-facing format.
func writeStorageTarget(dst io.Writer, target storage.VMTarget) {
	fmt.Fprintf(
		dst,
		"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		valueOrDash(target.TargetType),
		valueOrDash(target.VM.Name),
		valueOrDash(target.VM.Tenant),
		valueOrDash(target.VM.Role),
		valueOrDash(target.VM.QEMUPID),
		valueOrDash(target.VM.Disk),
		valueOrDash(target.Storage.SourceDevice),
		valueOrDash(target.Storage.ParentDevice),
		valueOrDash(target.Storage.PhysicalDisk),
	)
}

// writeQEMUErrors renders QEMU errors in the package's stable operator-facing format.
func writeQEMUErrors(dst io.Writer, report Report) {
	var wroteHeader bool
	for _, vm := range report.QEMU.VMs {
		if strings.TrimSpace(vm.Error) == "" {
			continue
		}
		if !wroteHeader {
			fmt.Fprintln(dst, "VM\tPROCESS_IO_ERROR")
			wroteHeader = true
		}
		fmt.Fprintf(dst, "%s\t%s\n", valueOrDash(vm.Target.VM.Name), valueOrDash(vm.Error))
	}
}

// sharedDiskText formats shared-disk evidence as yes, no, or unavailable.
func sharedDiskText(available, shared bool) string {
	if !available {
		return "-"
	}
	if shared {
		return "yes"
	}
	return "no"
}

// qemuValue formats a QEMU measurement only when its source was available.
func qemuValue(value float64, available bool) string {
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

// valueOrDash trims a value and substitutes a dash when no value is available.
func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}
