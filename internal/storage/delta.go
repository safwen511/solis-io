package storage

import (
	"fmt"
	"time"
)

// CalculateDelta computes rates and deltas between two block-stat samples.
func CalculateDelta(previous, current DeviceStats, interval time.Duration) (DeviceDelta, error) {
	if interval <= 0 {
		return DeviceDelta{}, fmt.Errorf("sample interval must be greater than zero")
	}

	physicalDisk := current.PhysicalDisk
	if physicalDisk == "" {
		physicalDisk = previous.PhysicalDisk
	}
	weightedDelta, weightedAvailable := counterDelta(previous.WeightedIOTimeMS, current.WeightedIOTimeMS)

	return DeviceDelta{
		PhysicalDisk:          physicalDisk,
		ReadsPerSecond:        counterRate(previous.ReadsCompleted, current.ReadsCompleted, interval),
		WritesPerSecond:       counterRate(previous.WritesCompleted, current.WritesCompleted, interval),
		SectorsReadPerSecond:  counterRate(previous.SectorsRead, current.SectorsRead, interval),
		SectorsWritePerSecond: counterRate(previous.SectorsWritten, current.SectorsWritten, interval),
		IOInProgress:          current.IOInProgress,
		WeightedIODeltaMS: Counter{
			Value:     weightedDelta,
			Available: weightedAvailable,
		},
	}, nil
}

func counterRate(previous, current Counter, interval time.Duration) Rate {
	delta, available := counterDelta(previous, current)
	if !available {
		return Rate{}
	}
	return Rate{
		Value:     float64(delta) / interval.Seconds(),
		Available: true,
	}
}

func counterDelta(previous, current Counter) (uint64, bool) {
	if !previous.Available || !current.Available || current.Value < previous.Value {
		return 0, false
	}
	return current.Value - previous.Value, true
}
