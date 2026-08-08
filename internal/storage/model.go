// Package storage captures read-only host block statistics for VM disks.
package storage

import (
	"time"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
)

// Counter is a block statistic that may be unavailable on the host.
type Counter struct {
	Value     uint64
	Available bool
}

// DeviceStats contains selected Linux block statistics for one physical disk.
type DeviceStats struct {
	PhysicalDisk     string
	ReadsCompleted   Counter
	WritesCompleted  Counter
	SectorsRead      Counter
	SectorsWritten   Counter
	IOInProgress     Counter
	IOTimeMS         Counter
	WeightedIOTimeMS Counter
}

// VMTarget combines a VM with its role in the snapshot and host storage mapping.
type VMTarget struct {
	TargetType string
	VM         inventory.VM
	Storage    hoststorage.Mapping
}

// Snapshot contains VM mappings and cumulative host block counters.
type Snapshot struct {
	VictimSelector  string
	SuspectSelector string
	Targets         []VMTarget
	Devices         []DeviceStats
}

// Rate is a per-second counter delta that may be unavailable.
type Rate struct {
	Value     float64
	Available bool
}

// DeviceDelta contains one interval of block activity for a storage-layer device.
type DeviceDelta struct {
	Elapsed               time.Duration
	LayerType             string
	Device                string
	ReadsPerSecond        Rate
	WritesPerSecond       Rate
	SectorsReadPerSecond  Rate
	SectorsWritePerSecond Rate
	ReadMiBPerSecond      Rate
	WriteMiBPerSecond     Rate
	IOInProgress          Counter
	IOTimeDeltaMS         Counter
	WeightedIODeltaMS     Counter
	UtilPercent           Rate
}
