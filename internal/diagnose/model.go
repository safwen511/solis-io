// Package diagnose combines experiment, storage, and QEMU evidence into a verdict.
package diagnose

import (
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/experiment"
	"github.com/safwen511/solis-io/internal/qemuio"
	"github.com/safwen511/solis-io/internal/storage"
)

const (
	ProbableVerdict            = "Probable noisy-neighbor storage interference."
	LowPressureVerdict         = "Slowdown observed, but no meaningful suspect QEMU write pressure was observed during live sampling."
	TopologyMismatchVerdict    = "Slowdown observed, but storage topology does not support this suspect as the cause."
	InsufficientVerdict        = "Insufficient evidence for noisy-neighbor storage interference."
	NoDominantCandidateVerdict = "Slowdown observed, but no dominant storage-neighbor candidate was detected during live sampling."
)

// Inputs contains the selectors and live-sampling window supplied by the user.
type Inputs struct {
	ReportDirectory string
	Victim          string
	Suspect         string
	Duration        time.Duration
	Interval        time.Duration
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
	Experiment               experiment.Report
	Impact                   experiment.Impact
	Storage                  storage.Snapshot
	QEMU                     qemuio.SummaryReport
	EBPFLatency              *ebpf.BlockLatencyEvidence
	Discovery                *discovery.Report
	StorageTopologyAvailable bool
	SharedPhysicalDisk       bool
	Verdict                  string
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
		Experiment:               experimentReport,
		Impact:                   impact,
		Storage:                  storageSnapshot,
		QEMU:                     qemuReport,
		StorageTopologyAvailable: topologyAvailable,
		SharedPhysicalDisk:       shared,
		Verdict:                  Verdict(evidence),
	}, nil
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

func hasTargetType(value, targetType string) bool {
	for _, candidate := range strings.Split(value, ",") {
		if strings.TrimSpace(candidate) == targetType {
			return true
		}
	}
	return false
}

func addDevices(devices map[string]bool, value string) {
	for _, device := range strings.Split(value, ",") {
		device = strings.TrimSpace(device)
		if device != "" && device != "-" {
			devices[device] = true
		}
	}
}
