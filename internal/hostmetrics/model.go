// Package hostmetrics collects read-only provider-side Linux host metrics from
// fixed procfs and filesystem sources. It does not access guests or databases.
package hostmetrics

import "github.com/safwen511/solis-io/internal/observability"

const SchemaVersion = "1"

// HostStatus is one windowed, provider-side host observation.
type HostStatus struct {
	SchemaVersion     string                     `json:"schema_version"`
	ObservedAtUTC     string                     `json:"observed_at_utc"`
	WindowID          string                     `json:"window_id"`
	Hostname          string                     `json:"hostname"`
	KernelRelease     string                     `json:"kernel_release"`
	Availability      observability.Availability `json:"availability"`
	CPU               CPUStatus                  `json:"cpu"`
	Memory            MemoryStatus               `json:"memory"`
	PSI               PSIStatus                  `json:"psi"`
	Filesystems       FilesystemSection          `json:"filesystems"`
	Disks             DiskSection                `json:"disks"`
	NetworkInterfaces NetworkSection             `json:"network_interfaces"`
	QEMUProcesses     QEMUProcessSection         `json:"qemu_processes"`
	Privacy           observability.PrivacyFlags `json:"privacy"`
}

// CPUStatus contains percentages calculated from two aggregate /proc/stat CPU
// samples.
type CPUStatus struct {
	Availability     observability.Availability `json:"availability"`
	UserPercent      float64                    `json:"user_percent"`
	SystemPercent    float64                    `json:"system_percent"`
	IdlePercent      float64                    `json:"idle_percent"`
	IOWaitPercent    float64                    `json:"iowait_percent"`
	StealPercent     float64                    `json:"steal_percent"`
	TotalBusyPercent float64                    `json:"total_busy_percent"`
}

// MemoryStatus contains capacity values derived from /proc/meminfo.
type MemoryStatus struct {
	Availability        observability.Availability `json:"availability"`
	MemTotalBytes       uint64                     `json:"mem_total_bytes"`
	MemAvailableBytes   uint64                     `json:"mem_available_bytes"`
	MemUsedBytes        uint64                     `json:"mem_used_bytes"`
	MemAvailablePercent float64                    `json:"mem_available_percent"`
	SwapTotalBytes      uint64                     `json:"swap_total_bytes"`
	SwapFreeBytes       uint64                     `json:"swap_free_bytes"`
	SwapUsedBytes       uint64                     `json:"swap_used_bytes"`
}

// PSIValues contains one some/full pressure line.
type PSIValues struct {
	Availability observability.Availability `json:"availability"`
	Avg10        float64                    `json:"avg10"`
	Avg60        float64                    `json:"avg60"`
	Avg300       float64                    `json:"avg300"`
}

// PSIResourceStatus contains the some and full pressure signals for one
// resource. Older kernels may expose some but not full.
type PSIResourceStatus struct {
	Availability observability.Availability `json:"availability"`
	Some         PSIValues                  `json:"some"`
	Full         PSIValues                  `json:"full"`
}

// PSIStatus groups CPU, memory, and I/O pressure evidence.
type PSIStatus struct {
	Availability observability.Availability `json:"availability"`
	CPU          PSIResourceStatus          `json:"cpu"`
	Memory       PSIResourceStatus          `json:"memory"`
	IO           PSIResourceStatus          `json:"io"`
}

// FilesystemStatus contains statfs capacity and inode metadata only.
type FilesystemStatus struct {
	Mountpoint       string                     `json:"mountpoint"`
	Availability     observability.Availability `json:"availability"`
	TotalBytes       uint64                     `json:"total_bytes"`
	FreeBytes        uint64                     `json:"free_bytes"`
	AvailableBytes   uint64                     `json:"available_bytes"`
	UsedPercent      float64                    `json:"used_percent"`
	FilesTotal       uint64                     `json:"files_total"`
	FilesFree        uint64                     `json:"files_free"`
	FilesUsedPercent float64                    `json:"files_used_percent"`
}

// FilesystemSection contains all requested mountpoint results.
type FilesystemSection struct {
	Availability observability.Availability `json:"availability"`
	Mounts       []FilesystemStatus         `json:"mounts"`
}

// DiskStatus contains final counters and optional windowed rates for one
// /proc/diskstats block device.
type DiskStatus struct {
	Name                   string                     `json:"name"`
	Availability           observability.Availability `json:"availability"`
	ReadsCompleted         uint64                     `json:"reads_completed"`
	WritesCompleted        uint64                     `json:"writes_completed"`
	SectorsRead            uint64                     `json:"sectors_read"`
	SectorsWritten         uint64                     `json:"sectors_written"`
	IOInProgress           uint64                     `json:"io_in_progress"`
	WeightedIOMilliseconds uint64                     `json:"weighted_io_ms"`
	RateAvailability       observability.Availability `json:"rate_availability"`
	ReadSectorsPerSecond   float64                    `json:"read_sectors_per_sec"`
	WriteSectorsPerSecond  float64                    `json:"write_sectors_per_sec"`
	ReadsPerSecond         float64                    `json:"reads_per_sec"`
	WritesPerSecond        float64                    `json:"writes_per_sec"`
}

// DiskSection contains deterministically ordered block devices.
type DiskSection struct {
	Availability observability.Availability `json:"availability"`
	Devices      []DiskStatus               `json:"devices"`
}

// NetworkInterfaceStatus contains final counters and optional windowed byte
// rates from /proc/net/dev.
type NetworkInterfaceStatus struct {
	Interface        string                     `json:"interface"`
	Availability     observability.Availability `json:"availability"`
	RXBytes          uint64                     `json:"rx_bytes"`
	TXBytes          uint64                     `json:"tx_bytes"`
	RXPackets        uint64                     `json:"rx_packets"`
	TXPackets        uint64                     `json:"tx_packets"`
	RXErrors         uint64                     `json:"rx_errors"`
	TXErrors         uint64                     `json:"tx_errors"`
	RXDropped        uint64                     `json:"rx_dropped"`
	TXDropped        uint64                     `json:"tx_dropped"`
	RateAvailability observability.Availability `json:"rate_availability"`
	RXBytesPerSecond float64                    `json:"rx_bytes_per_sec"`
	TXBytesPerSecond float64                    `json:"tx_bytes_per_sec"`
}

// NetworkSection contains deterministically ordered interface counters.
type NetworkSection struct {
	Availability observability.Availability `json:"availability"`
	Interfaces   []NetworkInterfaceStatus   `json:"interfaces"`
}

// QEMUProcessStatus contains sanitized procfs accounting for one local QEMU
// process. RSS and CPU ticks are nil when their files or fields are unavailable.
type QEMUProcessStatus struct {
	PID          int                        `json:"pid"`
	Command      string                     `json:"command"`
	RSSBytes     *uint64                    `json:"rss_bytes"`
	CPUTicks     *uint64                    `json:"cpu_ticks"`
	Availability observability.Availability `json:"availability"`
}

// QEMUProcessSection contains command-name-only QEMU process metadata.
type QEMUProcessSection struct {
	Availability observability.Availability `json:"availability"`
	Processes    []QEMUProcessStatus        `json:"processes"`
}
