package diagnose

import (
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/safwen511/solis-io/internal/config"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/observability"
)

// JSONReport is the versioned, privacy-safe machine representation of a
// noisy-neighbor diagnosis. It intentionally projects inventory and process
// evidence instead of serializing internal structs that may carry fields not
// present in the human diagnosis.
type JSONReport struct {
	SchemaVersion      string                     `json:"schema_version"`
	Inputs             JSONInputs                 `json:"inputs"`
	ExperimentEvidence JSONExperimentEvidence     `json:"experiment_evidence"`
	StorageTopology    JSONStorageTopology        `json:"storage_topology"`
	QEMUEvidence       JSONQEMUEvidence           `json:"qemu_evidence"`
	EBPFLatency        *JSONEBPFLatencyEvidence   `json:"ebpf_latency"`
	EBPFVMAttribution  *JSONEBPFVMAttribution     `json:"ebpf_vm_attribution"`
	Discovery          *JSONDiscoveryEvidence     `json:"discovery"`
	Verdict            string                     `json:"verdict"`
	Privacy            observability.PrivacyFlags `json:"privacy"`
}

type JSONInputs struct {
	ReportDirectory string            `json:"report_directory"`
	Victim          string            `json:"victim"`
	Suspect         string            `json:"suspect"`
	Duration        string            `json:"duration"`
	Interval        string            `json:"interval"`
	ConfigSource    string            `json:"config_source"`
	Thresholds      config.Thresholds `json:"thresholds"`
}

type JSONExperimentEvidence struct {
	Available              bool            `json:"available"`
	Baseline               JSONHTTPMetrics `json:"baseline"`
	DuringNoise            JSONHTTPMetrics `json:"during_noise"`
	PostNoise              JSONHTTPMetrics `json:"post_noise"`
	FIO                    JSONFIOMetrics  `json:"fio"`
	ThroughputDropPercent  float64         `json:"throughput_drop_percent"`
	LatencyIncreasePercent float64         `json:"latency_increase_percent"`
}

type JSONHTTPMetrics struct {
	FailedRequests    int     `json:"failed_requests"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	TimePerRequestMS  float64 `json:"time_per_request_ms"`
}

type JSONFIOMetrics struct {
	IOPS        string  `json:"iops"`
	Bandwidth   string  `json:"bandwidth"`
	DiskUtilPct float64 `json:"disk_util_percent"`
}

type JSONStorageTopology struct {
	Available          bool                `json:"available"`
	SharedPhysicalDisk bool                `json:"shared_physical_disk"`
	Targets            []JSONStorageTarget `json:"targets"`
}

type JSONStorageTarget struct {
	TargetType   string `json:"target_type"`
	VM           string `json:"vm"`
	Tenant       string `json:"tenant"`
	Role         string `json:"role"`
	State        string `json:"state"`
	QEMUPID      string `json:"qemu_pid"`
	Disk         string `json:"disk"`
	SourceDevice string `json:"source_device"`
	ParentDevice string `json:"parent_device"`
	PhysicalDisk string `json:"physical_disk"`
}

type JSONQEMUEvidence struct {
	VictimDataAvailable             bool         `json:"victim_data_available"`
	SuspectDataAvailable            bool         `json:"suspect_data_available"`
	VictimAverageWriteMiBPerSecond  float64      `json:"victim_avg_write_mib_s"`
	SuspectAverageWriteMiBPerSecond float64      `json:"suspect_avg_write_mib_s"`
	VictimAverageSyscwPerSecond     float64      `json:"victim_avg_syscw_s"`
	SuspectAverageSyscwPerSecond    float64      `json:"suspect_avg_syscw_s"`
	DominantWriter                  string       `json:"dominant_writer"`
	DominantWriteSyscallSource      string       `json:"dominant_write_syscall_source"`
	WriteRatio                      string       `json:"write_ratio"`
	SyscwRatio                      string       `json:"syscw_ratio"`
	Conclusion                      string       `json:"conclusion"`
	VMs                             []JSONQEMUVM `json:"vms"`
}

type JSONQEMUVM struct {
	TargetType               string  `json:"target_type"`
	VM                       string  `json:"vm"`
	Tenant                   string  `json:"tenant"`
	Role                     string  `json:"role"`
	Available                bool    `json:"available"`
	AverageReadMiBPerSecond  float64 `json:"avg_read_mib_s"`
	AverageWriteMiBPerSecond float64 `json:"avg_write_mib_s"`
	MaxWriteMiBPerSecond     float64 `json:"max_write_mib_s"`
	AverageSyscwPerSecond    float64 `json:"avg_syscw_s"`
	MaxSyscwPerSecond        float64 `json:"max_syscw_s"`
}

type JSONEBPFLatencyEvidence struct {
	Available         bool    `json:"available"`
	CompletedRequests uint64  `json:"completed_requests"`
	AverageLatencyUS  float64 `json:"average_latency_us"`
	MaxLatencyUS      float64 `json:"max_latency_us"`
	Scope             string  `json:"scope"`
}

type JSONEBPFVMAttribution struct {
	Available           bool                       `json:"available"`
	CollectorAvailable  bool                       `json:"collector_available"`
	Status              string                     `json:"status"`
	CollectionMode      string                     `json:"collection_mode"`
	AttributionMethod   string                     `json:"attribution_method"`
	Quality             string                     `json:"quality"`
	AttributedOps       uint64                     `json:"attributed_ops"`
	UnattributedOps     uint64                     `json:"unattributed_ops"`
	AttributedPercent   float64                    `json:"attributed_percent"`
	UnattributedPercent float64                    `json:"unattributed_percent"`
	MatchedVMCount      int                        `json:"matched_vm_count"`
	VictimTotalOps      uint64                     `json:"victim_total_ops"`
	SuspectTotalOps     uint64                     `json:"suspect_total_ops"`
	VictimP95MS         float64                    `json:"victim_p95_ms"`
	SuspectP95MS        float64                    `json:"suspect_p95_ms"`
	VMs                 []JSONEBPFVM               `json:"vms"`
	Privacy             observability.PrivacyFlags `json:"privacy"`
}

type JSONEBPFVM struct {
	Name               string                               `json:"name"`
	Tenant             string                               `json:"tenant"`
	Role               string                               `json:"role"`
	ReadOps            uint64                               `json:"read_ops"`
	WriteOps           uint64                               `json:"write_ops"`
	FlushOps           uint64                               `json:"flush_ops"`
	DiscardOps         uint64                               `json:"discard_ops"`
	UnknownOps         uint64                               `json:"unknown_ops"`
	TotalOps           uint64                               `json:"total_ops"`
	LatencyMinMS       float64                              `json:"latency_min_ms"`
	LatencyAvgMS       float64                              `json:"latency_avg_ms"`
	LatencyP50MS       float64                              `json:"latency_p50_ms"`
	LatencyP95MS       float64                              `json:"latency_p95_ms"`
	LatencyP99MS       float64                              `json:"latency_p99_ms"`
	LatencyMaxMS       float64                              `json:"latency_max_ms"`
	AttributionQuality string                               `json:"attribution_quality"`
	Devices            []string                             `json:"devices"`
	DeviceOperations   []ebpf.VMBlockLatencyDeviceOperation `json:"device_operations"`
}

type JSONDiscoveryEvidence struct {
	Enabled         bool                     `json:"enabled"`
	Victim          string                   `json:"victim"`
	SelectedSuspect string                   `json:"selected_suspect"`
	SelectionReason string                   `json:"selection_reason"`
	Candidates      []JSONDiscoveryCandidate `json:"candidates"`
}

type JSONDiscoveryCandidate struct {
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

// WriteJSON emits one deterministic JSON diagnosis and performs no host reads.
func WriteJSON(dst io.Writer, report Report) error {
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(buildJSONReport(report))
}

// buildJSONReport builds json report from validated inputs.
func buildJSONReport(report Report) JSONReport {
	result := JSONReport{
		SchemaVersion: "1",
		Inputs: JSONInputs{
			ReportDirectory: valueOrDash(report.Inputs.ReportDirectory),
			Victim:          valueOrDash(report.Inputs.Victim),
			Suspect:         valueOrDash(report.Inputs.Suspect),
			Duration:        report.Inputs.Duration.String(),
			Interval:        report.Inputs.Interval.String(),
			ConfigSource:    valueOrDash(report.Inputs.ConfigSource),
			Thresholds:      report.Inputs.Thresholds,
		},
		ExperimentEvidence: JSONExperimentEvidence{
			Available: report.ExperimentAvailable,
			Baseline: JSONHTTPMetrics{
				FailedRequests: report.Experiment.Baseline.FailedRequests, RequestsPerSecond: report.Experiment.Baseline.RequestsPerSecond,
				TimePerRequestMS: report.Experiment.Baseline.TimePerRequestMS,
			},
			DuringNoise: JSONHTTPMetrics{
				FailedRequests: report.Experiment.DuringNoise.FailedRequests, RequestsPerSecond: report.Experiment.DuringNoise.RequestsPerSecond,
				TimePerRequestMS: report.Experiment.DuringNoise.TimePerRequestMS,
			},
			PostNoise: JSONHTTPMetrics{
				FailedRequests: report.Experiment.PostNoise.FailedRequests, RequestsPerSecond: report.Experiment.PostNoise.RequestsPerSecond,
				TimePerRequestMS: report.Experiment.PostNoise.TimePerRequestMS,
			},
			FIO:                   JSONFIOMetrics{IOPS: report.Experiment.FIO.IOPS, Bandwidth: report.Experiment.FIO.Bandwidth, DiskUtilPct: report.Experiment.FIO.DiskUtilPct},
			ThroughputDropPercent: report.Impact.ThroughputDropPct, LatencyIncreasePercent: report.Impact.LatencyIncreasePct,
		},
		StorageTopology: JSONStorageTopology{
			Available: report.StorageTopologyAvailable, SharedPhysicalDisk: report.SharedPhysicalDisk,
		},
		QEMUEvidence: JSONQEMUEvidence{
			VictimDataAvailable: report.QEMU.VictimDataAvailable, SuspectDataAvailable: report.QEMU.SuspectDataAvailable,
			VictimAverageWriteMiBPerSecond:  report.QEMU.VictimAverageWriteMiBPerSecond,
			SuspectAverageWriteMiBPerSecond: report.QEMU.SuspectAverageWriteMiBPerSecond,
			VictimAverageSyscwPerSecond:     report.QEMU.VictimAverageSyscwPerSecond,
			SuspectAverageSyscwPerSecond:    report.QEMU.SuspectAverageSyscwPerSecond,
			DominantWriter:                  valueOrDash(report.QEMU.DominantWriter), DominantWriteSyscallSource: valueOrDash(report.QEMU.DominantWriteSyscallSource),
			WriteRatio: valueOrDash(report.QEMU.WriteRatio), SyscwRatio: valueOrDash(report.QEMU.SyscwRatio), Conclusion: valueOrDash(report.QEMU.Conclusion),
		},
		Verdict: report.Verdict,
		Privacy: observability.PrivacyFlags{},
	}
	for _, target := range report.Storage.Targets {
		result.StorageTopology.Targets = append(result.StorageTopology.Targets, JSONStorageTarget{
			TargetType: target.TargetType, VM: target.VM.Name, Tenant: target.VM.Tenant, Role: target.VM.Role,
			State: target.VM.State, QEMUPID: target.VM.QEMUPID, Disk: target.VM.Disk,
			SourceDevice: target.Storage.SourceDevice, ParentDevice: target.Storage.ParentDevice, PhysicalDisk: target.Storage.PhysicalDisk,
		})
	}
	for _, vm := range report.QEMU.VMs {
		result.QEMUEvidence.VMs = append(result.QEMUEvidence.VMs, JSONQEMUVM{
			TargetType: vm.Target.TargetType, VM: vm.Target.VM.Name, Tenant: vm.Target.VM.Tenant, Role: vm.Target.VM.Role,
			Available: vm.Available, AverageReadMiBPerSecond: vm.AverageReadMiBPerSecond,
			AverageWriteMiBPerSecond: vm.AverageWriteMiBPerSecond, MaxWriteMiBPerSecond: vm.MaxWriteMiBPerSecond,
			AverageSyscwPerSecond: vm.AverageSyscwPerSecond, MaxSyscwPerSecond: vm.MaxSyscwPerSecond,
		})
	}
	result.EBPFLatency = jsonEBPFLatency(report.EBPFLatency)
	result.EBPFVMAttribution = jsonEBPFVMAttribution(report)
	result.Discovery = jsonDiscovery(report)
	return result
}

// jsonEBPFLatency builds JSON eBPF latency from validated inputs.
func jsonEBPFLatency(evidence *ebpf.BlockLatencyEvidence) *JSONEBPFLatencyEvidence {
	if evidence == nil {
		return nil
	}
	averageUS := float64(0)
	if evidence.Result.CompletedRequests > 0 {
		averageUS = float64(evidence.Result.TotalLatencyNS) / float64(evidence.Result.CompletedRequests) / 1000
	}
	return &JSONEBPFLatencyEvidence{
		Available: strings.TrimSpace(evidence.UnavailableReason) == "", CompletedRequests: evidence.Result.CompletedRequests,
		AverageLatencyUS: averageUS, MaxLatencyUS: float64(evidence.Result.MaxLatencyNS) / 1000,
		Scope: "host/storage-path level",
	}
}

// jsonEBPFVMAttribution builds JSON eBPF VM attribution from validated inputs.
func jsonEBPFVMAttribution(report Report) *JSONEBPFVMAttribution {
	evidence := report.EBPFVMAttribution
	if evidence == nil {
		return nil
	}
	assessment := AssessEBPFVMAttribution(report)
	result := &JSONEBPFVMAttribution{
		Available: assessment.Available, CollectorAvailable: evidence.Availability.Available,
		Status: evidence.Availability.Status, CollectionMode: evidence.CollectionMode, AttributionMethod: evidence.AttributionMethod,
		Quality: assessment.Quality, AttributedOps: evidence.AttributionSummary.AttributedOps,
		UnattributedOps: evidence.AttributionSummary.UnattributedOps, AttributedPercent: assessment.AttributedPercent,
		UnattributedPercent: assessment.UnattributedPercent, MatchedVMCount: evidence.AttributionSummary.MatchedVMCount,
		VictimTotalOps: assessment.VictimTotalOps, SuspectTotalOps: assessment.SuspectTotalOps,
		VictimP95MS: assessment.VictimP95MS, SuspectP95MS: assessment.SuspectP95MS,
		Privacy: evidence.Privacy,
	}
	for _, vm := range evidence.VMs {
		devices := append([]string(nil), vm.Devices...)
		sort.Strings(devices)
		result.VMs = append(result.VMs, JSONEBPFVM{
			Name: vm.Name, Tenant: vm.Tenant, Role: vm.Role, ReadOps: vm.ReadOps, WriteOps: vm.WriteOps,
			FlushOps: vm.FlushOps, DiscardOps: vm.DiscardOps, UnknownOps: vm.UnknownOps, TotalOps: vm.TotalOps,
			LatencyMinMS: vm.LatencyMinMS, LatencyAvgMS: vm.LatencyAvgMS, LatencyP50MS: vm.LatencyP50MS,
			LatencyP95MS: vm.LatencyP95MS, LatencyP99MS: vm.LatencyP99MS, LatencyMaxMS: vm.LatencyMaxMS,
			AttributionQuality: vm.AttributionQuality, Devices: devices,
			DeviceOperations: append([]ebpf.VMBlockLatencyDeviceOperation(nil), vm.DeviceOperations...),
		})
	}
	return result
}

// jsonDiscovery builds JSON discovery from validated inputs.
func jsonDiscovery(report Report) *JSONDiscoveryEvidence {
	if report.Discovery == nil {
		return nil
	}
	result := &JSONDiscoveryEvidence{
		Enabled: true, Victim: report.Discovery.Victim.Name, SelectedSuspect: "-",
		SelectionReason: report.Discovery.SelectionReason,
	}
	if report.Discovery.Selected != nil {
		result.SelectedSuspect = report.Discovery.Selected.VM.Name
	}
	for _, candidate := range report.Discovery.Candidates {
		result.Candidates = append(result.Candidates, JSONDiscoveryCandidate{
			Name: candidate.VM.Name, Tenant: candidate.VM.Tenant, Role: candidate.VM.Role, SharedDisk: candidate.SharedDisk,
			AverageWriteMiBPerSecond: candidate.Summary.AverageWriteMiBPerSecond,
			MaxWriteMiBPerSecond:     candidate.Summary.MaxWriteMiBPerSecond,
			AverageSyscwPerSecond:    candidate.Summary.AverageSyscwPerSecond,
			MaxSyscwPerSecond:        candidate.Summary.MaxSyscwPerSecond,
			Score:                    candidate.Score, Reason: candidate.Reason,
		})
	}
	return result
}
