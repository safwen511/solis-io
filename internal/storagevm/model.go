// Package storagevm collects single-host per-VM storage validation counters.
// These counters are correlation evidence and are not block-latency
// attribution.
package storagevm

import "github.com/safwen511/solis-io/internal/observability"

const SchemaVersion = "1"

// VMStorageStatsReport is one time-bounded, provider-side validation snapshot.
type VMStorageStatsReport struct {
	SchemaVersion       string                     `json:"schema_version"`
	ObservedAtUTC       string                     `json:"observed_at_utc"`
	Duration            string                     `json:"duration"`
	Interval            string                     `json:"interval"`
	ConfigSource        string                     `json:"config_source"`
	VMs                 []VMStorageStatsVM         `json:"vms"`
	HostDevices         []HostDevice               `json:"host_devices"`
	Caveats             []string                   `json:"caveats"`
	UnavailableSections []UnavailableSection       `json:"unavailable_sections"`
	Privacy             observability.PrivacyFlags `json:"privacy"`
}

// VMStorageStatsVM contains independent validation signals for one VM.
type VMStorageStatsVM struct {
	Name            string                `json:"name"`
	Tenant          string                `json:"tenant"`
	Role            string                `json:"role"`
	State           string                `json:"state"`
	QEMUPID         int                   `json:"qemu_pid"`
	Disk            string                `json:"disk"`
	CgroupPath      string                `json:"cgroup_path"`
	CgroupID        uint64                `json:"cgroup_id"`
	MappingQuality  string                `json:"mapping_quality"`
	CgroupIOStat    CgroupIOStatEvidence  `json:"cgroup_io_stat"`
	VirshDomstats   VirshDomstatsEvidence `json:"virsh_domstats"`
	QEMUPressure    QEMUPressureEvidence  `json:"qemu_pressure"`
	EvidenceQuality string                `json:"evidence_quality"`
	Caveats         []string              `json:"caveats"`
}

// CgroupIOStatEvidence describes a cgroup v2 io.stat observation window.
type CgroupIOStatEvidence struct {
	Available               bool                  `json:"available"`
	Quality                 string                `json:"quality"`
	SourceCgroupPath        string                `json:"source_cgroup_path"`
	SourceCgroupKind        string                `json:"source_cgroup_kind"`
	SourceCgroupInodeBefore uint64                `json:"source_cgroup_inode_before"`
	SourceCgroupInodeAfter  uint64                `json:"source_cgroup_inode_after"`
	Devices                 []CgroupIODeviceDelta `json:"devices"`
	MissingBaselineDevices  []string              `json:"missing_baseline_devices"`
	MissingAfterDevices     []string              `json:"missing_after_devices"`
	CounterResetDevices     []string              `json:"counter_reset_devices"`
	DuplicateDevices        []string              `json:"duplicate_devices"`
	Error                   string                `json:"error"`
	Caveats                 []string              `json:"caveats"`
}

// CgroupIODeviceDelta is one independent storage-layer row. It is never
// summed with another stacked layer by this collector.
type CgroupIODeviceDelta struct {
	DeviceID              string   `json:"device_id"`
	DeviceName            string   `json:"device_name"`
	Status                string   `json:"status"`
	CounterReset          bool     `json:"counter_reset"`
	ReadBytesDelta        uint64   `json:"read_bytes_delta"`
	WriteBytesDelta       uint64   `json:"write_bytes_delta"`
	ReadIOsDelta          uint64   `json:"read_ios_delta"`
	WriteIOsDelta         uint64   `json:"write_ios_delta"`
	DiscardBytesDelta     uint64   `json:"discard_bytes_delta"`
	DiscardIOsDelta       uint64   `json:"discard_ios_delta"`
	DBytesDelta           uint64   `json:"dbytes_delta"`
	DIOsDelta             uint64   `json:"dios_delta"`
	DiscardBytesAvailable bool     `json:"discard_bytes_available"`
	DiscardIOsAvailable   bool     `json:"discard_ios_available"`
	SourcePath            string   `json:"source_path"`
	LayerKind             string   `json:"layer_kind"`
	Caveats               []string `json:"caveats"`
}

// VirshDomstatsEvidence describes virtual-disk counters and cumulative timing.
type VirshDomstatsEvidence struct {
	Available bool                    `json:"available"`
	Quality   string                  `json:"quality"`
	Disks     []VirshVirtualDiskDelta `json:"disks"`
	Error     string                  `json:"error"`
	Caveats   []string                `json:"caveats"`
}

// VirshVirtualDiskDelta is one virtual disk from virsh domstats --block.
type VirshVirtualDiskDelta struct {
	Target             string   `json:"target"`
	Status             string   `json:"status"`
	CounterReset       bool     `json:"counter_reset"`
	ReadReqsDelta      uint64   `json:"rd_reqs_delta"`
	ReadBytesDelta     uint64   `json:"rd_bytes_delta"`
	ReadTimeNSDelta    uint64   `json:"rd_times_ns_delta"`
	WriteReqsDelta     uint64   `json:"wr_reqs_delta"`
	WriteBytesDelta    uint64   `json:"wr_bytes_delta"`
	WriteTimeNSDelta   uint64   `json:"wr_times_ns_delta"`
	FlushReqsDelta     uint64   `json:"flush_reqs_delta"`
	FlushTimeNSDelta   uint64   `json:"flush_times_ns_delta"`
	AverageReadTimeMS  float64  `json:"avg_read_time_ms"`
	AverageWriteTimeMS float64  `json:"avg_write_time_ms"`
	Caveats            []string `json:"caveats"`
}

// QEMUPressureEvidence is process accounting correlation only.
type QEMUPressureEvidence struct {
	Available       bool     `json:"available"`
	Quality         string   `json:"quality"`
	ReadBytesDelta  uint64   `json:"read_bytes_delta"`
	WriteBytesDelta uint64   `json:"write_bytes_delta"`
	SyscrDelta      uint64   `json:"syscr_delta"`
	SyscwDelta      uint64   `json:"syscw_delta"`
	Error           string   `json:"error"`
	Caveats         []string `json:"caveats"`
}

// HostDevice is safe sysfs metadata for one major:minor device row.
type HostDevice struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	SourcePath string `json:"source_path"`
	LayerKind  string `json:"layer_kind"`
}

// UnavailableSection records an optional source failure without aborting the
// report.
type UnavailableSection struct {
	VM      string `json:"vm"`
	Section string `json:"section"`
	Status  string `json:"status"`
	Error   string `json:"error"`
}
