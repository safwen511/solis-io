package capture

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/safwen511/solis-io/internal/diagnose"
	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/experiment"
	"github.com/safwen511/solis-io/internal/qemuio"
	"github.com/safwen511/solis-io/internal/version"
)

// WriteIncidentReport renders a human-readable summary of an existing capture
// evidence bundle. It performs no additional host sampling.
func WriteIncidentReport(dst io.Writer, inputs Inputs, evidence Evidence, timestamp string, generatedFiles []string) error {
	impact := evidence.Diagnosis.Impact
	if calculated, err := experiment.CalculateImpact(evidence.Experiment); err == nil {
		impact = calculated
	}
	mode := captureMode(inputs)
	evidenceMode := captureEvidenceMode(inputs)
	suspect := selectedSuspect(inputs, evidence)
	thresholds := qemuio.EffectiveThresholds(inputs.Thresholds)
	build := version.BuildInfo()

	if _, err := fmt.Fprintln(dst, "# Solis Noisy Neighbor Incident Report"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		dst,
		"\n## Executive summary\n\n"+
			"- Victim VM: %s\n"+
			"- Selected suspect: %s\n"+
			"- Verdict: %s\n"+
			"- Capture timestamp: %s\n"+
			"- Capture mode: %s\n"+
			"- Evidence mode: %s\n",
		markdownText(inputs.Victim),
		markdownText(suspect),
		markdownText(evidence.Diagnosis.Verdict),
		markdownText(timestamp),
		markdownText(mode),
		markdownText(evidenceMode),
	); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(dst, "\n## Evidence chain\n\n### Experiment slowdown evidence"); err != nil {
		return err
	}
	if !evidence.Diagnosis.ExperimentAvailable {
		if _, err := fmt.Fprintln(dst, "\nApplication slowdown evidence: unavailable; no --report-dir supplied."); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(
		dst,
		"\n"+
			"| Metric | Baseline | During noise | Post-noise |\n"+
			"|---|---:|---:|---:|\n"+
			"| Requests/sec | %.2f | %.2f | %.2f |\n"+
			"| Latency (ms) | %.3f | %.3f | %.3f |\n"+
			"| Failed requests | %d | %d | %d |\n\n"+
			"- Throughput drop: %.2f%%\n"+
			"- Latency increase: %.2f%%\n",
		evidence.Experiment.Baseline.RequestsPerSecond,
		evidence.Experiment.DuringNoise.RequestsPerSecond,
		evidence.Experiment.PostNoise.RequestsPerSecond,
		evidence.Experiment.Baseline.TimePerRequestMS,
		evidence.Experiment.DuringNoise.TimePerRequestMS,
		evidence.Experiment.PostNoise.TimePerRequestMS,
		evidence.Experiment.Baseline.FailedRequests,
		evidence.Experiment.DuringNoise.FailedRequests,
		evidence.Experiment.PostNoise.FailedRequests,
		impact.ThroughputDropPct,
		impact.LatencyIncreasePct,
	); err != nil {
		return err
	}

	if err := writeStorageEvidence(dst, evidence); err != nil {
		return err
	}
	if mode == "discover-suspects" {
		if err := writeDiscoveryEvidence(dst, evidence.Discovery); err != nil {
			return err
		}
	}
	if err := writeQEMUEvidence(dst, evidence, suspect); err != nil {
		return err
	}
	if evidence.EBPFLatency != nil {
		if err := writeEBPFEvidence(dst, *evidence.EBPFLatency); err != nil {
			return err
		}
	}
	if inputs.IncludeEBPFLatency {
		if err := writeEBPFVMAttributionEvidence(dst, evidence); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(
		dst,
		"\n## Important caveats\n\n"+
			"- eBPF block latency is host/storage-path level, not exact per-VM attribution.\n"+
			"- Experimental VM attribution requires exact blkcg cgroup-ID matches and must be interpreted with its quality and unattributed percentage.\n"+
			"- QEMU io-summary is used for VM writer attribution.\n"+
			"- No guest payloads, guest files, process memory, or application contents were inspected.",
	); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(dst, "\n## Recommended operator action\n\n%s\n", recommendation(evidence.Diagnosis.Verdict, suspect)); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(
		dst,
		"\n## Metadata\n\n"+
			"- Report directory: %s\n"+
			"- Evidence mode: %s\n"+
			"- Duration: %s\n"+
			"- Interval: %s\n"+
			"- Config source: %s\n"+
			"- Solis version: %s\n"+
			"- Git commit: %s\n"+
			"- Build time: %s\n"+
			"- Go version: %s\n"+
			"- Platform: %s\n"+
			"- Write threshold MiB/s: %.2f\n"+
			"- Write syscall threshold/s: %.2f\n"+
			"- Dominance ratio: %.2f\n"+
			"- Generated files:\n",
		markdownText(inputs.ReportDirectory),
		markdownText(evidenceMode),
		inputs.Duration,
		inputs.Interval,
		markdownText(inputs.ConfigSource),
		markdownText(build.Version),
		markdownText(build.GitCommit),
		markdownText(build.BuildTime),
		markdownText(build.GoVersion),
		markdownText(build.Platform),
		thresholds.WriteMiBPerSecond,
		thresholds.WriteSyscallsPerSecond,
		thresholds.DominanceRatio,
	); err != nil {
		return err
	}
	for _, name := range generatedFiles {
		if _, err := fmt.Fprintf(dst, "  - %s\n", markdownText(name)); err != nil {
			return err
		}
	}
	return nil
}

func writeEBPFVMAttributionEvidence(dst io.Writer, evidence Evidence) error {
	report := evidence.Diagnosis
	if report.EBPFVMAttribution == nil {
		report.EBPFVMAttribution = evidence.EBPFVMAttribution
	}
	assessment := diagnose.AssessEBPFVMAttribution(report)
	if _, err := fmt.Fprintln(dst, "\n### eBPF VM-attributed block latency"); err != nil {
		return err
	}
	if report.EBPFVMAttribution == nil {
		_, err := fmt.Fprintln(dst,
			"\n- Available: no\n"+
				"- Attribution quality: unavailable\n"+
				"- Caveat: collector did not return VM-attributed evidence.\n"+
				"- Privacy: no guest payloads, guest files, process arguments, environments, SQL text, table data, request bodies, response bodies, or secrets were collected.")
		return err
	}
	vmReport := report.EBPFVMAttribution
	if _, err := fmt.Fprintf(dst,
		"\n- Available: %s\n"+
			"- Attribution quality: %s\n"+
			"- Attributed operations: %d (%.2f%%)\n"+
			"- Unattributed operations: %d (%.2f%%)\n"+
			"- Victim attributed operations / p95: %d / %.3f ms\n"+
			"- Suspect attributed operations / p95: %d / %.3f ms\n",
		yesNo(assessment.Available), markdownText(vmReport.AttributionQuality),
		vmReport.AttributionSummary.AttributedOps, vmReport.AttributionSummary.AttributedPercent,
		vmReport.AttributionSummary.UnattributedOps, vmReport.Unattributed.UnattributedPercent,
		assessment.VictimTotalOps, assessment.VictimP95MS,
		assessment.SuspectTotalOps, assessment.SuspectP95MS,
	); err != nil {
		return err
	}
	if vmReport.Availability.Available {
		if _, err := fmt.Fprintln(dst, "\n| VM | Attributed operations | Read | Write | p95 ms | Quality |\n|---|---:|---:|---:|---:|---|"); err != nil {
			return err
		}
		for _, vm := range vmReport.VMs {
			if _, err := fmt.Fprintf(dst, "| %s | %d | %d | %d | %.3f | %s |\n",
				markdownCell(vm.Name), vm.TotalOps, vm.ReadOps, vm.WriteOps, vm.LatencyP95MS, markdownCell(vm.AttributionQuality)); err != nil {
				return err
			}
		}
	} else if strings.TrimSpace(vmReport.Availability.Error) != "" {
		if _, err := fmt.Fprintf(dst, "- Unavailable reason: %s\n", markdownText(vmReport.Availability.Error)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(dst,
		"- Caveat: attribution is experimental; unmatched ownership, request merging/requeues, and stacked storage can reduce confidence.\n"+
			"- Privacy: no guest payloads, guest files, process arguments, environments, SQL text, table data, request bodies, response bodies, or secrets were collected.")
	return err
}

func writeStorageEvidence(dst io.Writer, evidence Evidence) error {
	shared := "-"
	if evidence.Diagnosis.StorageTopologyAvailable {
		shared = yesNo(evidence.Diagnosis.SharedPhysicalDisk)
	}
	if _, err := fmt.Fprintf(
		dst,
		"\n### Shared storage topology\n\n"+
			"- Victim and selected suspect share a physical disk: %s\n\n"+
			"| Target | VM | Source device | Parent device | Physical disk |\n"+
			"|---|---|---|---|---|\n",
		shared,
	); err != nil {
		return err
	}
	if len(evidence.Storage.Targets) == 0 {
		_, err := fmt.Fprintln(dst, "| - | - | - | - | - |")
		return err
	}
	for _, target := range evidence.Storage.Targets {
		if _, err := fmt.Fprintf(
			dst,
			"| %s | %s | %s | %s | %s |\n",
			markdownCell(target.TargetType),
			markdownCell(target.VM.Name),
			markdownCell(target.Storage.SourceDevice),
			markdownCell(target.Storage.ParentDevice),
			markdownCell(target.Storage.PhysicalDisk),
		); err != nil {
			return err
		}
	}
	return nil
}

func writeDiscoveryEvidence(dst io.Writer, report *discovery.Report) error {
	if _, err := fmt.Fprintln(dst, "\n### Suspect discovery result"); err != nil {
		return err
	}
	if report == nil {
		_, err := fmt.Fprintln(dst, "\nDiscovery evidence unavailable.")
		return err
	}
	selected := "-"
	if report.Selected != nil {
		selected = report.Selected.VM.Name
	}
	if _, err := fmt.Fprintf(
		dst,
		"\n- Selected suspect: %s\n"+
			"- Reason: %s\n\n"+
			"| Candidate | Shared disk | Avg write MiB/s | Max write MiB/s | Avg syscw/s | Max syscw/s | Score | Reason |\n"+
			"|---|---|---:|---:|---:|---:|---|---|\n",
		markdownText(selected),
		markdownText(report.SelectionReason),
	); err != nil {
		return err
	}
	if len(report.Candidates) == 0 {
		_, err := fmt.Fprintln(dst, "| - | - | - | - | - | - | LOW | no shared-storage candidates |")
		return err
	}
	for _, candidate := range report.Candidates {
		if _, err := fmt.Fprintf(
			dst,
			"| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			markdownCell(candidate.VM.Name),
			yesNo(candidate.SharedDisk),
			availableMetric(candidate.Summary.AverageWriteMiBPerSecond, candidate.Summary.Available),
			availableMetric(candidate.Summary.MaxWriteMiBPerSecond, candidate.Summary.Available),
			availableMetric(candidate.Summary.AverageSyscwPerSecond, candidate.Summary.Available),
			availableMetric(candidate.Summary.MaxSyscwPerSecond, candidate.Summary.Available),
			markdownCell(candidate.Score),
			markdownCell(candidate.Reason),
		); err != nil {
			return err
		}
	}
	return nil
}

func writeQEMUEvidence(dst io.Writer, evidence Evidence, suspect string) error {
	if _, err := fmt.Fprintln(dst, "\n### QEMU writer/syscall attribution"); err != nil {
		return err
	}
	if suspect == "-" {
		_, err := fmt.Fprintln(dst, "\nNo suspect was selected; candidate process-I/O counters are summarized in the discovery evidence.")
		return err
	}
	qemu := evidence.QEMU
	if _, err := fmt.Fprintf(
		dst,
		"\n| Signal | Victim | Suspect |\n"+
			"|---|---:|---:|\n"+
			"| Average write MiB/s | %s | %s |\n"+
			"| Average syscw/s | %s | %s |\n\n"+
			"- Write ratio: %s\n"+
			"- Syscall ratio: %s\n"+
			"- Dominant writer: %s\n"+
			"- Dominant write syscall source: %s\n"+
			"- Conclusion: %s\n",
		availableMetric(qemu.VictimAverageWriteMiBPerSecond, qemu.VictimDataAvailable),
		availableMetric(qemu.SuspectAverageWriteMiBPerSecond, qemu.SuspectDataAvailable),
		availableMetric(qemu.VictimAverageSyscwPerSecond, qemu.VictimDataAvailable),
		availableMetric(qemu.SuspectAverageSyscwPerSecond, qemu.SuspectDataAvailable),
		markdownText(qemu.WriteRatio),
		markdownText(qemu.SyscwRatio),
		markdownText(qemu.DominantWriter),
		markdownText(qemu.DominantWriteSyscallSource),
		markdownText(qemu.Conclusion),
	); err != nil {
		return err
	}
	return nil
}

func writeEBPFEvidence(dst io.Writer, evidence ebpf.BlockLatencyEvidence) error {
	var rendered bytes.Buffer
	if err := ebpf.WriteBlockLatencyEvidence(&rendered, evidence); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(dst, "\n### eBPF block latency evidence\n\n```text"); err != nil {
		return err
	}
	if _, err := io.Copy(dst, &rendered); err != nil {
		return err
	}
	_, err := fmt.Fprintln(dst, "```")
	return err
}

func recommendation(verdict, suspect string) string {
	if verdict == diagnose.ProbableVerdict || verdict == diagnose.LikelyLiveVerdict {
		return fmt.Sprintf("Consider throttling, migrating, or investigating the selected suspect VM workload (%s).", markdownText(suspect))
	}
	if suspect == "-" {
		return "Continue monitoring or expand the observation window."
	}
	return "Continue monitoring and review the detailed evidence files before taking action."
}

func selectedSuspect(inputs Inputs, evidence Evidence) string {
	if evidence.Discovery != nil {
		if evidence.Discovery.Selected == nil {
			return "-"
		}
		return valueOrDash(evidence.Discovery.Selected.VM.Name)
	}
	return valueOrDash(inputs.Suspect)
}

func availableMetric(value float64, available bool) string {
	if !available {
		return "-"
	}
	return fmt.Sprintf("%.2f", value)
}

func markdownCell(value string) string {
	return strings.ReplaceAll(markdownText(value), "|", `\|`)
}

func markdownText(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return "-"
	}
	return value
}
