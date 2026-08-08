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

	device := current.PhysicalDisk
	if device == "" {
		device = previous.PhysicalDisk
	}
	readsPerSecond := counterRate(previous.ReadsCompleted, current.ReadsCompleted, interval)
	writesPerSecond := counterRate(previous.WritesCompleted, current.WritesCompleted, interval)
	sectorsReadPerSecond := counterRate(previous.SectorsRead, current.SectorsRead, interval)
	sectorsWritePerSecond := counterRate(previous.SectorsWritten, current.SectorsWritten, interval)
	ioTimeDelta, ioTimeAvailable := counterDelta(previous.IOTimeMS, current.IOTimeMS)
	weightedDelta, weightedAvailable := counterDelta(previous.WeightedIOTimeMS, current.WeightedIOTimeMS)
	utilPercent := Rate{}
	if ioTimeAvailable {
		intervalMS := float64(interval) / float64(time.Millisecond)
		utilPercent = Rate{
			Value:     float64(ioTimeDelta) / intervalMS * 100,
			Available: true,
		}
	}

	return DeviceDelta{
		Device:                device,
		ReadsPerSecond:        readsPerSecond,
		WritesPerSecond:       writesPerSecond,
		SectorsReadPerSecond:  sectorsReadPerSecond,
		SectorsWritePerSecond: sectorsWritePerSecond,
		ReadMiBPerSecond:      scaleRate(sectorsReadPerSecond, 1.0/2048.0),
		WriteMiBPerSecond:     scaleRate(sectorsWritePerSecond, 1.0/2048.0),
		IOInProgress:          current.IOInProgress,
		IOTimeDeltaMS: Counter{
			Value:     ioTimeDelta,
			Available: ioTimeAvailable,
		},
		WeightedIODeltaMS: Counter{
			Value:     weightedDelta,
			Available: weightedAvailable,
		},
		UtilPercent: utilPercent,
	}, nil
}

func scaleRate(rate Rate, scale float64) Rate {
	if !rate.Available {
		return Rate{}
	}
	return Rate{Value: rate.Value * scale, Available: true}
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
