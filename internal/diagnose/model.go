// Package diagnose combines experiment, storage, and QEMU evidence into a verdict.
package diagnose

import (
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/config"
	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/experiment"
	"github.com/safwen511/solis-io/internal/qemuio"
	"github.com/safwen511/solis-io/internal/storage"
)

const (
	ProbableVerdict                = "Probable noisy-neighbor storage interference."
	LowPressureVerdict             = "Slowdown observed, but no meaningful suspect QEMU write pressure was observed during live sampling."
	TopologyMismatchVerdict        = "Slowdown observed, but storage topology does not support this suspect as the cause."
	InsufficientVerdict            = "Insufficient evidence for noisy-neighbor storage interference."
	NoDominantCandidateVerdict     = "Slowdown observed, but no dominant storage-neighbor candidate was detected during live sampling."
	LikelyLiveVerdict              = "Likely storage-neighbor pressure observed during live sampling."
	LowPressureLiveVerdict         = "No meaningful QEMU write pressure observed during live sampling."
	TopologyMismatchLiveVerdict    = "Live storage topology does not support this suspect as the source of storage-neighbor pressure."
	InsufficientLiveVerdict        = "Insufficient live infrastructure evidence for storage-neighbor pressure."
	NoDominantLiveCandidateVerdict = "No dominant storage-neighbor candidate was detected during live sampling."
)

// Inputs contains the selectors and live-sampling window supplied by the user.
type Inputs struct {
	ReportDirectory string
	Victim          string
	Suspect         string
	Duration        time.Duration
	Interval        time.Duration
	ConfigSource    string
	Thresholds      config.Thresholds
}

// Evidence captures the boolean conditions used by the verdict rules.
type Evidence struct {
	SlowdownObserved               bool
	StorageTopologyAvailable       bool
	SharedPhysicalDisk             bool
	QEMUDataAvailable              bool
	MeaningfulSuspectWritePressure bool
	SuspectDominant                bool
	MeaningfulSuspectSyscwPressure bool
	SuspectSyscwDominant           bool
}

// Report contains all evidence required for deterministic output.
type Report struct {
	Inputs                   Inputs
	ExperimentAvailable      bool
	Experiment               experiment.Report
	Impact                   experiment.Impact
	Storage                  storage.Snapshot
	QEMU                     qemuio.SummaryReport
	EBPFLatency              *ebpf.BlockLatencyEvidence
	EBPFVMAttribution        *ebpf.VMBlockLatencyReport
	Discovery                *discovery.Report
	StorageTopologyAvailable bool
	SharedPhysicalDisk       bool
	Verdict                  string
}

// EBPFVMAttributionAssessment is the small, verdict-safe subset of the
// experimental VM-attributed latency report. Victim values are aggregated
// across every VM selected as a victim; p95 is the highest selected-VM p95.
type EBPFVMAttributionAssessment struct {
	Available           bool
	Quality             string
	AttributedPercent   float64
	UnattributedPercent float64
	VictimTotalOps      uint64
	SuspectTotalOps     uint64
	VictimP95MS         float64
	SuspectP95MS        float64
	SuspectDominant     bool
}

// ApplyEBPFVMAttribution applies VM-attributed latency only as a conservative
// corroboration/veto layer. It never promotes a non-eBPF result to a positive
// verdict and ignores degraded or unavailable attribution for verdicts.
func ApplyEBPFVMAttribution(report Report) Report {
	assessment := AssessEBPFVMAttribution(report)
	if !assessment.Available || assessment.Quality != "available" {
		return report
	}
	if assessment.SuspectDominant {
		return report
	}
	switch report.Verdict {
	case ProbableVerdict:
		report.Verdict = InsufficientVerdict
	case LikelyLiveVerdict:
		report.Verdict = InsufficientLiveVerdict
	}
	return report
}

// AssessEBPFVMAttribution matches report VM names against the already-resolved
// diagnosis target roles. It performs no host reads.
func AssessEBPFVMAttribution(report Report) EBPFVMAttributionAssessment {
	result := EBPFVMAttributionAssessment{Quality: "unavailable"}
	if report.EBPFVMAttribution == nil {
		return result
	}
	evidence := report.EBPFVMAttribution
	result.Quality = valueOrUnavailable(evidence.AttributionQuality)
	result.AttributedPercent = evidence.AttributionSummary.AttributedPercent
	result.UnattributedPercent = evidence.Unattributed.UnattributedPercent
	result.Available = evidence.Availability.Available && evidence.AttributionSummary.AttributedOps > 0 &&
		(result.Quality == "available" || result.Quality == "degraded")

	victims := make(map[string]bool)
	suspects := make(map[string]bool)
	for _, target := range report.Storage.Targets {
		if hasTargetType(target.TargetType, "victim") {
			victims[target.VM.Name] = true
		}
		if hasTargetType(target.TargetType, "suspect") {
			suspects[target.VM.Name] = true
		}
	}
	if len(suspects) == 0 && strings.TrimSpace(report.Inputs.Suspect) != "" && report.Inputs.Suspect != "-" {
		suspects[report.Inputs.Suspect] = true
	}
	for _, vm := range evidence.VMs {
		if victims[vm.Name] {
			result.VictimTotalOps += vm.TotalOps
			if vm.LatencyP95MS > result.VictimP95MS {
				result.VictimP95MS = vm.LatencyP95MS
			}
		}
		if suspects[vm.Name] {
			result.SuspectTotalOps += vm.TotalOps
			if vm.LatencyP95MS > result.SuspectP95MS {
				result.SuspectP95MS = vm.LatencyP95MS
			}
		}
	}
	thresholds := qemuio.EffectiveThresholds(report.Inputs.Thresholds)
	if result.SuspectTotalOps > 0 {
		if result.VictimTotalOps == 0 {
			result.SuspectDominant = true
		} else {
			result.SuspectDominant = float64(result.SuspectTotalOps) >= float64(result.VictimTotalOps)*thresholds.DominanceRatio
		}
	}
	return result
}

// valueOrUnavailable returns the value or an explicit unavailable marker.
func valueOrUnavailable(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unavailable"
	}
	return value
}

// NewReport combines already parsed and sampled evidence without re-reading it.
func NewReport(inputs Inputs, experimentReport experiment.Report, storageSnapshot storage.Snapshot, qemuReport qemuio.SummaryReport) (Report, error) {
	impact, err := experiment.CalculateImpact(experimentReport)
	if err != nil {
		return Report{}, err
	}

	shared, topologyAvailable := sharedPhysicalDisk(storageSnapshot.Targets)
	evidence := Evidence{
		SlowdownObserved:               impact.ThroughputDropPct > 0 && impact.LatencyIncreasePct > 0,
		StorageTopologyAvailable:       topologyAvailable,
		SharedPhysicalDisk:             shared,
		QEMUDataAvailable:              qemuReport.VictimDataAvailable && qemuReport.SuspectDataAvailable,
		MeaningfulSuspectWritePressure: qemuReport.MeaningfulSuspectWritePressure,
		SuspectDominant:                qemuReport.SuspectDominant,
		MeaningfulSuspectSyscwPressure: qemuReport.MeaningfulSuspectSyscwPressure,
		SuspectSyscwDominant:           qemuReport.SuspectSyscwDominant,
	}

	return Report{
		Inputs:                   inputs,
		ExperimentAvailable:      true,
		Experiment:               experimentReport,
		Impact:                   impact,
		Storage:                  storageSnapshot,
		QEMU:                     qemuReport,
		StorageTopologyAvailable: topologyAvailable,
		SharedPhysicalDisk:       shared,
		Verdict:                  Verdict(evidence),
	}, nil
}

// NewLiveReport combines live provider-side evidence without claiming that an
// application slowdown was observed.
func NewLiveReport(inputs Inputs, storageSnapshot storage.Snapshot, qemuReport qemuio.SummaryReport) Report {
	shared, topologyAvailable := sharedPhysicalDisk(storageSnapshot.Targets)
	evidence := Evidence{
		StorageTopologyAvailable:       topologyAvailable,
		SharedPhysicalDisk:             shared,
		QEMUDataAvailable:              qemuReport.VictimDataAvailable && qemuReport.SuspectDataAvailable,
		MeaningfulSuspectWritePressure: qemuReport.MeaningfulSuspectWritePressure,
		SuspectDominant:                qemuReport.SuspectDominant,
		MeaningfulSuspectSyscwPressure: qemuReport.MeaningfulSuspectSyscwPressure,
		SuspectSyscwDominant:           qemuReport.SuspectSyscwDominant,
	}

	return Report{
		Inputs:                   inputs,
		Storage:                  storageSnapshot,
		QEMU:                     qemuReport,
		StorageTopologyAvailable: topologyAvailable,
		SharedPhysicalDisk:       shared,
		Verdict:                  LiveVerdict(evidence),
	}
}

// Verdict applies the noisy-neighbor evidence rules in deterministic order.
func Verdict(evidence Evidence) string {
	if !evidence.SlowdownObserved {
		return InsufficientVerdict
	}
	if evidence.QEMUDataAvailable && !evidence.MeaningfulSuspectWritePressure && !evidence.MeaningfulSuspectSyscwPressure {
		return LowPressureVerdict
	}
	if evidence.StorageTopologyAvailable && !evidence.SharedPhysicalDisk {
		return TopologyMismatchVerdict
	}
	dominant := evidence.SuspectDominant
	if !evidence.MeaningfulSuspectWritePressure {
		dominant = evidence.MeaningfulSuspectSyscwPressure && evidence.SuspectSyscwDominant
	}
	if evidence.SharedPhysicalDisk && evidence.QEMUDataAvailable && dominant {
		return ProbableVerdict
	}
	return InsufficientVerdict
}

// LiveVerdict applies infrastructure-only rules without claiming an
// application-level slowdown.
func LiveVerdict(evidence Evidence) string {
	if evidence.StorageTopologyAvailable && !evidence.SharedPhysicalDisk {
		return TopologyMismatchLiveVerdict
	}
	if evidence.QEMUDataAvailable && !evidence.MeaningfulSuspectWritePressure && !evidence.MeaningfulSuspectSyscwPressure {
		return LowPressureLiveVerdict
	}
	dominant := evidence.SuspectDominant
	if !evidence.MeaningfulSuspectWritePressure {
		dominant = evidence.MeaningfulSuspectSyscwPressure && evidence.SuspectSyscwDominant
	}
	if evidence.SharedPhysicalDisk && evidence.QEMUDataAvailable && dominant {
		return LikelyLiveVerdict
	}
	return InsufficientLiveVerdict
}

// sharedPhysicalDisk builds shared physical disk from validated inputs.
func sharedPhysicalDisk(targets []storage.VMTarget) (bool, bool) {
	victimDisks := make(map[string]bool)
	suspectDisks := make(map[string]bool)
	for _, target := range targets {
		if hasTargetType(target.TargetType, "victim") {
			addDevices(victimDisks, target.Storage.PhysicalDisk)
		}
		if hasTargetType(target.TargetType, "suspect") {
			addDevices(suspectDisks, target.Storage.PhysicalDisk)
		}
	}

	if len(victimDisks) == 0 || len(suspectDisks) == 0 {
		return false, false
	}
	for disk := range victimDisks {
		if suspectDisks[disk] {
			return true, true
		}
	}
	return false, true
}

// hasTargetType reports whether the value has target type.
func hasTargetType(value, targetType string) bool {
	for _, candidate := range strings.Split(value, ",") {
		if strings.TrimSpace(candidate) == targetType {
			return true
		}
	}
	return false
}

// addDevices adds devices to the current aggregate.
func addDevices(devices map[string]bool, value string) {
	for _, device := range strings.Split(value, ",") {
		device = strings.TrimSpace(device)
		if device != "" && device != "-" {
			devices[device] = true
		}
	}
}
