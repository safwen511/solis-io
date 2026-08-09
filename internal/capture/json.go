package capture

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/safwen511/solis-io/internal/diagnose"
	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/experiment"
	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/storage"
)

// EvidenceSummary is the versioned machine-readable capture schema.
type EvidenceSummary struct {
	SchemaVersion      string                  `json:"schema_version"`
	Capture            CaptureSummary          `json:"capture"`
	Victim             VMEvidence              `json:"victim"`
	SelectedSuspect    SuspectEvidence         `json:"selected_suspect"`
	ExperimentEvidence ExperimentEvidence      `json:"experiment_evidence"`
	StorageTopology    StorageTopologyEvidence `json:"storage_topology"`
	QEMUEvidence       QEMUEvidence            `json:"qemu_evidence"`
	Discovery          DiscoveryEvidence       `json:"discovery"`
	EBPFLatency        EBPFLatencyEvidence     `json:"ebpf_latency"`
	Verdict            VerdictEvidence         `json:"verdict"`
	Safety             SafetyEvidence          `json:"safety"`
	Files              EvidenceFiles           `json:"files"`
}

type CaptureSummary struct {
	TimestampUTC string `json:"timestamp_utc"`
	Mode         string `json:"mode"`
	EvidenceMode string `json:"evidence_mode"`
	ReportDir    string `json:"report_dir"`
	Duration     string `json:"duration"`
	Interval     string `json:"interval"`
}

type VMEvidence struct {
	Name         string `json:"name"`
	Tenant       string `json:"tenant"`
	Role         string `json:"role"`
	QEMUPID      *int   `json:"qemu_pid"`
	Disk         string `json:"disk"`
	SourceDevice string `json:"source_device"`
	ParentDevice string `json:"parent_device"`
	PhysicalDisk string `json:"physical_disk"`
}

type SuspectEvidence struct {
	Name    string `json:"name"`
	Tenant  string `json:"tenant"`
	Role    string `json:"role"`
	QEMUPID *int   `json:"qemu_pid"`
	Reason  string `json:"reason"`
	Score   string `json:"score"`
}

type ExperimentEvidence struct {
	Available                 bool    `json:"available"`
	ThroughputDropPercent     float64 `json:"throughput_drop_percent"`
	LatencyIncreasePercent    float64 `json:"latency_increase_percent"`
	FailedRequestsDuringNoise int     `json:"failed_requests_during_noise"`
}

type StorageTopologyEvidence struct {
	SharedPhysicalDisk bool   `json:"shared_physical_disk"`
	PhysicalDisk       string `json:"physical_disk"`
}

type QEMUEvidence struct {
	VictimAverageWriteMiBPerSecond  float64 `json:"victim_avg_write_mib_s"`
	SuspectAverageWriteMiBPerSecond float64 `json:"suspect_avg_write_mib_s"`
	VictimAverageSyscwPerSecond     float64 `json:"victim_avg_syscw_s"`
	SuspectAverageSyscwPerSecond    float64 `json:"suspect_avg_syscw_s"`
	DominantWriter                  string  `json:"dominant_writer"`
	DominantSyscallSource           string  `json:"dominant_syscall_source"`
	Conclusion                      string  `json:"conclusion"`
}

type DiscoveryEvidence struct {
	Enabled         bool                         `json:"enabled"`
	SelectedSuspect string                       `json:"selected_suspect"`
	Reason          string                       `json:"reason"`
	Candidates      []DiscoveryCandidateEvidence `json:"candidates"`
}

type DiscoveryCandidateEvidence struct {
	Name                     string  `json:"name"`
	Tenant                   string  `json:"tenant"`
	Role                     string  `json:"role"`
	SharedDisk               bool    `json:"shared_disk"`
	AverageWriteMiBPerSecond float64 `json:"avg_write_mib_s"`
	MaxWriteMiBPerSecond     float64 `json:"max_write_mib_s"`
	AverageSyscwPerSecond    float64 `json:"avg_syscw_s"`
	MaxSyscwPerSecond        float64 `json:"max_syscw_s"`
	Score                    string  `json:"score"`
	Reason                   string  `json:"reason"`
}

type EBPFLatencyEvidence struct {
	Requested         bool                    `json:"requested"`
	Available         bool                    `json:"available"`
	CompletedRequests uint64                  `json:"completed_requests"`
	AverageLatencyUS  float64                 `json:"average_latency_us"`
	MaxLatencyUS      float64                 `json:"max_latency_us"`
	Histogram         []EBPFHistogramEvidence `json:"histogram"`
	Scope             string                  `json:"scope"`
	UnavailableReason string                  `json:"unavailable_reason,omitempty"`
}

type EBPFHistogramEvidence struct {
	Range    string  `json:"range"`
	Requests uint64  `json:"requests"`
	Percent  float64 `json:"percent"`
}

type VerdictEvidence struct {
	Text     string `json:"text"`
	Severity string `json:"severity"`
}

type SafetyEvidence struct {
	GuestPayloadsInspected bool `json:"guest_payloads_inspected"`
	GuestFilesInspected    bool `json:"guest_files_inspected"`
	ProcessMemoryInspected bool `json:"process_memory_inspected"`
}

type EvidenceFiles struct {
	IncidentReport  string `json:"incident_report"`
	Diagnosis       string `json:"diagnosis"`
	Metadata        string `json:"metadata"`
	EvidenceSummary string `json:"evidence_summary"`
}

// WriteEvidenceSummary writes the deterministic JSON representation of an
// already-collected capture. It performs no host reads or sampling.
func WriteEvidenceSummary(dst io.Writer, inputs Inputs, evidence Evidence, timestamp string) error {
	summary := buildEvidenceSummary(inputs, evidence, timestamp)
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func buildEvidenceSummary(inputs Inputs, evidence Evidence, timestamp string) EvidenceSummary {
	victimVM, victimStorage := resolvedTarget(inputs.Victim, "victim", evidence)
	suspectVM, suspectStorage := resolvedTarget(inputs.Suspect, "suspect", evidence)
	suspectReason, suspectScore := suspectClassification(inputs, evidence)
	if evidence.Discovery != nil {
		victimVM = evidence.Discovery.Victim
		victimStorage = evidence.Discovery.VictimStorage
		if evidence.Discovery.Selected != nil {
			suspectVM = evidence.Discovery.Selected.VM
			suspectStorage = evidence.Discovery.Selected.Storage
		}
	}

	return EvidenceSummary{
		SchemaVersion: "1",
		Capture: CaptureSummary{
			TimestampUTC: timestamp,
			Mode:         captureMode(inputs),
			EvidenceMode: captureEvidenceMode(inputs),
			ReportDir:    valueOrDash(inputs.ReportDirectory),
			Duration:     inputs.Duration.String(),
			Interval:     inputs.Interval.String(),
		},
		Victim:             vmEvidence(victimVM, victimStorage, inputs.Victim),
		SelectedSuspect:    selectedSuspectEvidence(inputs, evidence, suspectVM, suspectReason, suspectScore),
		ExperimentEvidence: experimentEvidence(evidence),
		StorageTopology: StorageTopologyEvidence{
			SharedPhysicalDisk: evidence.Diagnosis.StorageTopologyAvailable && evidence.Diagnosis.SharedPhysicalDisk,
			PhysicalDisk:       topologyPhysicalDisk(victimStorage, suspectStorage, evidence.Diagnosis.SharedPhysicalDisk),
		},
		QEMUEvidence: qemuEvidence(evidence),
		Discovery:    discoveryEvidence(inputs, evidence.Discovery),
		EBPFLatency:  ebpfLatencyEvidence(inputs, evidence.EBPFLatency),
		Verdict: VerdictEvidence{
			Text:     valueOrDash(evidence.Diagnosis.Verdict),
			Severity: verdictSeverity(evidence.Diagnosis.Verdict),
		},
		Safety: SafetyEvidence{},
		Files: EvidenceFiles{
			IncidentReport:  "incident-report.md",
			Diagnosis:       "diagnosis.txt",
			Metadata:        "metadata.txt",
			EvidenceSummary: "evidence-summary.json",
		},
	}
}

func resolvedTarget(selector, targetType string, evidence Evidence) (inventory.VM, hoststorage.Mapping) {
	var fallback *storage.VMTarget
	for index := range evidence.Storage.Targets {
		target := &evidence.Storage.Targets[index]
		if !hasTargetType(target.TargetType, targetType) {
			continue
		}
		if target.VM.Name == selector {
			return target.VM, target.Storage
		}
		if fallback == nil {
			fallback = target
		}
	}
	if fallback != nil {
		return fallback.VM, fallback.Storage
	}
	return inventory.VM{Name: valueOrDash(selector)}, hoststorage.Mapping{}
}

func hasTargetType(value, targetType string) bool {
	for _, candidate := range strings.Split(value, ",") {
		if strings.TrimSpace(candidate) == targetType {
			return true
		}
	}
	return false
}

func vmEvidence(vm inventory.VM, mapping hoststorage.Mapping, fallbackName string) VMEvidence {
	name := valueOrDash(vm.Name)
	if name == "-" {
		name = valueOrDash(fallbackName)
	}
	disk := mapping.DiskPath
	if strings.TrimSpace(disk) == "" {
		disk = vm.Disk
	}
	return VMEvidence{
		Name:         name,
		Tenant:       valueOrDash(vm.Tenant),
		Role:         valueOrDash(vm.Role),
		QEMUPID:      parsePID(vm.QEMUPID),
		Disk:         valueOrDash(disk),
		SourceDevice: valueOrDash(mapping.SourceDevice),
		ParentDevice: valueOrDash(mapping.ParentDevice),
		PhysicalDisk: valueOrDash(mapping.PhysicalDisk),
	}
}

func selectedSuspectEvidence(inputs Inputs, evidence Evidence, vm inventory.VM, reason, score string) SuspectEvidence {
	if evidence.Discovery != nil && evidence.Discovery.Selected == nil {
		return SuspectEvidence{
			Name:    "-",
			Tenant:  "-",
			Role:    "-",
			QEMUPID: nil,
			Reason:  valueOrDash(evidence.Discovery.SelectionReason),
			Score:   "-",
		}
	}
	name := valueOrDash(vm.Name)
	if name == "-" {
		name = valueOrDash(inputs.Suspect)
	}
	return SuspectEvidence{
		Name:    name,
		Tenant:  valueOrDash(vm.Tenant),
		Role:    valueOrDash(vm.Role),
		QEMUPID: parsePID(vm.QEMUPID),
		Reason:  valueOrDash(reason),
		Score:   valueOrDash(score),
	}
}

func suspectClassification(inputs Inputs, evidence Evidence) (string, string) {
	if evidence.Discovery != nil {
		if evidence.Discovery.Selected == nil {
			return evidence.Discovery.SelectionReason, "-"
		}
		return evidence.Discovery.Selected.Reason, evidence.Discovery.Selected.Score
	}
	qemu := evidence.QEMU
	switch {
	case qemu.SuspectDominant && qemu.MeaningfulSuspectWritePressure:
		return "dominant byte write rate", "HIGH"
	case qemu.SuspectSyscwDominant && qemu.MeaningfulSuspectSyscwPressure:
		return "dominant syscall pressure", "HIGH"
	case qemu.SuspectDataAvailable:
		return "no dominant writer observed", "LOW"
	default:
		return qemu.Conclusion, "-"
	}
}

func experimentEvidence(evidence Evidence) ExperimentEvidence {
	result := ExperimentEvidence{Available: evidence.Diagnosis.ExperimentAvailable}
	if !result.Available {
		return result
	}
	impact := evidence.Diagnosis.Impact
	if calculated, err := experiment.CalculateImpact(evidence.Experiment); err == nil {
		impact = calculated
	}
	result.ThroughputDropPercent = impact.ThroughputDropPct
	result.LatencyIncreasePercent = impact.LatencyIncreasePct
	result.FailedRequestsDuringNoise = evidence.Experiment.DuringNoise.FailedRequests
	return result
}

func qemuEvidence(evidence Evidence) QEMUEvidence {
	qemu := evidence.QEMU
	return QEMUEvidence{
		VictimAverageWriteMiBPerSecond:  qemu.VictimAverageWriteMiBPerSecond,
		SuspectAverageWriteMiBPerSecond: qemu.SuspectAverageWriteMiBPerSecond,
		VictimAverageSyscwPerSecond:     qemu.VictimAverageSyscwPerSecond,
		SuspectAverageSyscwPerSecond:    qemu.SuspectAverageSyscwPerSecond,
		DominantWriter:                  valueOrDash(qemu.DominantWriter),
		DominantSyscallSource:           valueOrDash(qemu.DominantWriteSyscallSource),
		Conclusion:                      valueOrDash(qemu.Conclusion),
	}
}

func discoveryEvidence(inputs Inputs, report *discovery.Report) DiscoveryEvidence {
	result := DiscoveryEvidence{
		Enabled:         captureMode(inputs) == "discover-suspects",
		SelectedSuspect: "-",
		Reason:          "-",
		Candidates:      []DiscoveryCandidateEvidence{},
	}
	if report == nil {
		return result
	}
	result.Reason = valueOrDash(report.SelectionReason)
	if report.Selected != nil {
		result.SelectedSuspect = valueOrDash(report.Selected.VM.Name)
	}
	for _, candidate := range report.Candidates {
		result.Candidates = append(result.Candidates, DiscoveryCandidateEvidence{
			Name:                     valueOrDash(candidate.VM.Name),
			Tenant:                   valueOrDash(candidate.VM.Tenant),
			Role:                     valueOrDash(candidate.VM.Role),
			SharedDisk:               candidate.SharedDisk,
			AverageWriteMiBPerSecond: candidate.Summary.AverageWriteMiBPerSecond,
			MaxWriteMiBPerSecond:     candidate.Summary.MaxWriteMiBPerSecond,
			AverageSyscwPerSecond:    candidate.Summary.AverageSyscwPerSecond,
			MaxSyscwPerSecond:        candidate.Summary.MaxSyscwPerSecond,
			Score:                    valueOrDash(candidate.Score),
			Reason:                   valueOrDash(candidate.Reason),
		})
	}
	return result
}

func ebpfLatencyEvidence(inputs Inputs, evidence *ebpf.BlockLatencyEvidence) EBPFLatencyEvidence {
	result := EBPFLatencyEvidence{
		Requested: inputs.IncludeEBPFLatency,
		Histogram: []EBPFHistogramEvidence{},
		Scope:     "host/storage-path level",
	}
	if !result.Requested {
		return result
	}
	if evidence == nil {
		result.UnavailableReason = "collector did not return eBPF block latency evidence"
		return result
	}
	if reason := strings.Join(strings.Fields(evidence.UnavailableReason), " "); reason != "" {
		result.UnavailableReason = reason
		return result
	}
	result.Available = true
	result.CompletedRequests = evidence.Result.CompletedRequests
	result.AverageLatencyUS = ebpf.AverageLatencyMicroseconds(evidence.Result)
	result.MaxLatencyUS = float64(evidence.Result.MaxLatencyNS) / 1000
	for _, bucket := range ebpf.LatencyHistogram(evidence.Result) {
		result.Histogram = append(result.Histogram, EBPFHistogramEvidence{
			Range:    bucket.Range,
			Requests: bucket.Requests,
			Percent:  bucket.Percent,
		})
	}
	return result
}

func topologyPhysicalDisk(victim, suspect hoststorage.Mapping, shared bool) string {
	if !shared {
		return "-"
	}
	victimDisk := valueOrDash(victim.PhysicalDisk)
	if victimDisk != "-" {
		return victimDisk
	}
	return valueOrDash(suspect.PhysicalDisk)
}

func verdictSeverity(verdict string) string {
	switch verdict {
	case diagnose.ProbableVerdict:
		return "probable"
	case diagnose.LikelyLiveVerdict:
		return "likely"
	case diagnose.LowPressureVerdict,
		diagnose.TopologyMismatchVerdict,
		diagnose.NoDominantCandidateVerdict,
		diagnose.LowPressureLiveVerdict,
		diagnose.TopologyMismatchLiveVerdict,
		diagnose.NoDominantLiveCandidateVerdict:
		return "warning"
	default:
		return "none"
	}
}

func parsePID(value string) *int {
	pid, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || pid <= 0 {
		return nil
	}
	return &pid
}
