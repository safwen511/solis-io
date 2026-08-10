package ebpf

import "github.com/safwen511/solis-io/internal/observability"

const vmBlockLatencySchemaVersion = "1"

// VMBlockLatencyReport is an experimental, single-host block-latency
// attribution report. It deliberately separates measured latency from the
// validation counters used to assess whether attribution is plausible.
type VMBlockLatencyReport struct {
	SchemaVersion       string                             `json:"schema_version"`
	ObservedAtUTC       string                             `json:"observed_at_utc"`
	Duration            string                             `json:"duration"`
	Interval            string                             `json:"interval"`
	Mode                string                             `json:"mode"`
	CollectionMode      string                             `json:"collection_mode"`
	AttributionMethod   string                             `json:"attribution_method"`
	AttributionQuality  string                             `json:"attribution_quality"`
	DeviceFilter        string                             `json:"device_filter"`
	Availability        VMBlockLatencyAvailability         `json:"availability"`
	Diagnostics         VMBlockRuntimeDiagnostics          `json:"diagnostics"`
	VMs                 []VMBlockLatencyVM                 `json:"vms"`
	HostSummary         VMBlockLatencySummary              `json:"host_summary"`
	KernelCounters      VMBlockKernelCounters              `json:"kernel_counters"`
	Validation          VMBlockLatencyValidation           `json:"validation"`
	Unattributed        VMBlockLatencyUnattributed         `json:"unattributed"`
	UnavailableSections []VMBlockLatencyUnavailableSection `json:"unavailable_sections"`
	Caveats             []string                           `json:"caveats"`
	Privacy             observability.PrivacyFlags         `json:"privacy"`
}

// VMBlockKernelCounters are host-wide typed-BTF attachment proof counters.
// They are not per-VM operations and do not carry request pointers.
type VMBlockKernelCounters struct {
	IssueSeen    uint64 `json:"issue_seen"`
	CompleteSeen uint64 `json:"complete_seen"`
	NullRequest  uint64 `json:"null_request"`
}

// VMBlockLatencyAvailability describes the runtime collector state.
type VMBlockLatencyAvailability struct {
	Available bool   `json:"available"`
	Status    string `json:"status"`
	Error     string `json:"error"`
}

// VMBlockRuntimeDiagnostics records bounded host state relevant to a failed
// privileged load or attach. It contains no process arguments, environment,
// payloads, or secrets.
type VMBlockRuntimeDiagnostics struct {
	Stage                   string                   `json:"stage"`
	EUID                    int                      `json:"euid"`
	RawError                string                   `json:"raw_error"`
	CapabilitySummary       VMBlockCapabilitySummary `json:"capability_summary"`
	LockdownMode            string                   `json:"lockdown_mode"`
	MemlockLimit            string                   `json:"memlock_limit"`
	PerfEventParanoid       string                   `json:"perf_event_paranoid"`
	UnprivilegedBPFDisabled string                   `json:"unprivileged_bpf_disabled"`
}

// VMBlockCapabilitySummary exposes only the effective capability mask and
// four capability bits relevant to eBPF setup.
type VMBlockCapabilitySummary struct {
	Available      bool   `json:"available"`
	CapEff         string `json:"cap_eff"`
	CAPBPF         bool   `json:"cap_bpf"`
	CAPPerfmon     bool   `json:"cap_perfmon"`
	CAPSysAdmin    bool   `json:"cap_sys_admin"`
	CAPSysResource bool   `json:"cap_sys_resource"`
	Error          string `json:"error"`
}

// VMBlockLatencyVM contains attributed latency for one inventory VM.
type VMBlockLatencyVM struct {
	Name                   string                          `json:"name"`
	Tenant                 string                          `json:"tenant"`
	Role                   string                          `json:"role"`
	QEMUPID                int                             `json:"qemu_pid"`
	CgroupPath             string                          `json:"cgroup_path"`
	CgroupID               uint64                          `json:"cgroup_id"`
	Disk                   string                          `json:"disk"`
	Devices                []string                        `json:"devices"`
	ReadOps                uint64                          `json:"read_ops"`
	WriteOps               uint64                          `json:"write_ops"`
	FlushOps               uint64                          `json:"flush_ops"`
	UnknownOps             uint64                          `json:"unknown_ops"`
	TotalOps               uint64                          `json:"total_ops"`
	LatencyMinMS           float64                         `json:"latency_min_ms"`
	LatencyAvgMS           float64                         `json:"latency_avg_ms"`
	LatencyP50MS           float64                         `json:"latency_p50_ms"`
	LatencyP95MS           float64                         `json:"latency_p95_ms"`
	LatencyP99MS           float64                         `json:"latency_p99_ms"`
	LatencyMaxMS           float64                         `json:"latency_max_ms"`
	PercentilesApproximate bool                            `json:"percentiles_approximate"`
	Histogram              []VMBlockLatencyHistogramBucket `json:"histogram"`
	DeviceOperations       []VMBlockLatencyDeviceOperation `json:"device_operations"`
	MappingQuality         string                          `json:"mapping_quality"`
	AttributionQuality     string                          `json:"attribution_quality"`
	Caveats                []string                        `json:"caveats"`
}

// VMBlockLatencySummary is the attributed host-wide aggregate. It does not
// include unattributed requests.
type VMBlockLatencySummary struct {
	ReadOps                uint64                          `json:"read_ops"`
	WriteOps               uint64                          `json:"write_ops"`
	FlushOps               uint64                          `json:"flush_ops"`
	UnknownOps             uint64                          `json:"unknown_ops"`
	TotalOps               uint64                          `json:"total_ops"`
	LatencyMinMS           float64                         `json:"latency_min_ms"`
	LatencyAvgMS           float64                         `json:"latency_avg_ms"`
	LatencyP50MS           float64                         `json:"latency_p50_ms"`
	LatencyP95MS           float64                         `json:"latency_p95_ms"`
	LatencyP99MS           float64                         `json:"latency_p99_ms"`
	LatencyMaxMS           float64                         `json:"latency_max_ms"`
	PercentilesApproximate bool                            `json:"percentiles_approximate"`
	Histogram              []VMBlockLatencyHistogramBucket `json:"histogram"`
}

// VMBlockLatencyHistogramBucket is one fixed, bounded latency bucket.
// Percentiles in this report are derived from these buckets and are therefore
// approximate; min, max, count, and average remain based on exact event values.
type VMBlockLatencyHistogramBucket struct {
	Range   string  `json:"range"`
	Count   uint64  `json:"count"`
	Percent float64 `json:"percent"`
}

// VMBlockLatencyDeviceOperation is a bounded aggregate for one VM, block
// device, and operation. No individual request latency values are retained.
type VMBlockLatencyDeviceOperation struct {
	Device                 string                          `json:"device"`
	Operation              string                          `json:"operation"`
	Count                  uint64                          `json:"count"`
	TotalLatencyMS         float64                         `json:"total_latency_ms"`
	LatencyMinMS           float64                         `json:"latency_min_ms"`
	LatencyAvgMS           float64                         `json:"latency_avg_ms"`
	LatencyP50MS           float64                         `json:"latency_p50_ms"`
	LatencyP95MS           float64                         `json:"latency_p95_ms"`
	LatencyP99MS           float64                         `json:"latency_p99_ms"`
	LatencyMaxMS           float64                         `json:"latency_max_ms"`
	PercentilesApproximate bool                            `json:"percentiles_approximate"`
	Histogram              []VMBlockLatencyHistogramBucket `json:"histogram"`
}

// VMBlockLatencyUnattributed records conditions that prevent or weaken VM
// attribution. Duplicate/reissue counters are kept separate from the count of
// completed unattributed operations because they need not represent distinct
// completed requests.
type VMBlockLatencyUnattributed struct {
	MissingBio             uint64  `json:"missing_bio"`
	MissingBlkcg           uint64  `json:"missing_blkcg"`
	UnmappedCgroup         uint64  `json:"unmapped_cgroup"`
	LookupMiss             uint64  `json:"lookup_miss"`
	DuplicateIssue         uint64  `json:"duplicate_issue"`
	RequeueOrReissue       uint64  `json:"requeue_or_reissue"`
	UnsupportedRequest     uint64  `json:"unsupported_request"`
	StackedDeviceAmbiguous uint64  `json:"stacked_device_ambiguous"`
	IncompleteAtWindowEnd  uint64  `json:"incomplete_at_window_end"`
	DroppedEvents          uint64  `json:"dropped_events"`
	RingBufferLost         uint64  `json:"ring_buffer_lost"`
	MapFull                uint64  `json:"map_full"`
	TotalUnattributedOps   uint64  `json:"total_unattributed_ops"`
	UnattributedPercent    float64 `json:"unattributed_percent"`
}

// VMBlockLatencyUnavailableSection preserves partial results without
// pretending an unavailable collector succeeded.
type VMBlockLatencyUnavailableSection struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

// VMBlockLatencyValidation contains independent, non-latency validation
// signals. Stacked block-device rows remain separate by design.
type VMBlockLatencyValidation struct {
	CgroupIOStat  []CgroupIOStatDelta  `json:"cgroup_io_stat"`
	VirshDomstats []VirshBlockDelta    `json:"virsh_domstats"`
	QEMUPressure  []QEMUPressureSignal `json:"qemu_pressure"`
	Caveats       []string             `json:"caveats"`
}

// CgroupIOStatDelta is a per-VM, per-device cgroup v2 counter delta.
type CgroupIOStatDelta struct {
	VM                    string `json:"vm"`
	CgroupPath            string `json:"cgroup_path"`
	Device                string `json:"device"`
	Status                string `json:"status"`
	CounterReset          bool   `json:"counter_reset"`
	ReadBytes             uint64 `json:"read_bytes"`
	WriteBytes            uint64 `json:"write_bytes"`
	ReadOps               uint64 `json:"read_ops"`
	WriteOps              uint64 `json:"write_ops"`
	DiscardBytes          uint64 `json:"discard_bytes"`
	DiscardOps            uint64 `json:"discard_ops"`
	DiscardBytesAvailable bool   `json:"discard_bytes_available"`
	DiscardOpsAvailable   bool   `json:"discard_ops_available"`
}

// VirshBlockDelta is a per-VM virtual-disk counter delta. Time is cumulative
// libvirt/QEMU block timing, not a host physical-device histogram.
type VirshBlockDelta struct {
	VM           string `json:"vm"`
	Block        string `json:"block"`
	Status       string `json:"status"`
	CounterReset bool   `json:"counter_reset"`
	ReadBytes    uint64 `json:"read_bytes"`
	WriteBytes   uint64 `json:"write_bytes"`
	ReadOps      uint64 `json:"read_ops"`
	WriteOps     uint64 `json:"write_ops"`
	ReadTimeNS   uint64 `json:"read_time_ns"`
	WriteTimeNS  uint64 `json:"write_time_ns"`
	FlushOps     uint64 `json:"flush_ops"`
	FlushTimeNS  uint64 `json:"flush_time_ns"`
}

// QEMUPressureSignal is pressure correlation only, not request latency.
type QEMUPressureSignal struct {
	VM               string  `json:"vm"`
	AverageWriteMiBS float64 `json:"average_write_mib_s"`
	AverageSyscwS    float64 `json:"average_syscw_s"`
	Available        bool    `json:"available"`
	Error            string  `json:"error"`
}

// VMBlockCgroupMapping maps kernel cgroup inode IDs to one local libvirt VM.
type VMBlockCgroupMapping struct {
	Name           string   `json:"name"`
	Tenant         string   `json:"tenant"`
	Role           string   `json:"role"`
	QEMUPID        int      `json:"qemu_pid"`
	Disk           string   `json:"disk"`
	PrimaryPath    string   `json:"primary_path"`
	PrimaryID      uint64   `json:"primary_id"`
	CgroupPaths    []string `json:"cgroup_paths"`
	CgroupIDs      []uint64 `json:"cgroup_ids"`
	MappingQuality string   `json:"mapping_quality"`
}

// VMBlockEvent is the sanitized event boundary used by the aggregator and
// fake tests. It contains no payload, process arguments, or process memory.
type VMBlockEvent struct {
	Kind                   string
	RequestPointer         uint64 `json:"-"`
	TimestampNS            uint64
	CgroupID               uint64
	Device                 string
	Operation              string
	MissingBio             bool
	MissingBlkcg           bool
	RequeueOrReissue       bool
	UnsupportedRequest     bool
	StackedDeviceAmbiguous bool
}
