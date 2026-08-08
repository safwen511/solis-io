package qemuio

import (
	"fmt"
	"time"
)

const bytesPerMiB = 1024 * 1024

// CalculateDelta computes selected per-second rates between process samples.
func CalculateDelta(previous, current Counters, interval time.Duration) (Rates, error) {
	if interval <= 0 {
		return Rates{}, fmt.Errorf("sample interval must be greater than zero")
	}

	readBytes, err := processCounterDelta("read_bytes", previous.ReadBytes, current.ReadBytes)
	if err != nil {
		return Rates{}, err
	}
	writeBytes, err := processCounterDelta("write_bytes", previous.WriteBytes, current.WriteBytes)
	if err != nil {
		return Rates{}, err
	}
	syscr, err := processCounterDelta("syscr", previous.Syscr, current.Syscr)
	if err != nil {
		return Rates{}, err
	}
	syscw, err := processCounterDelta("syscw", previous.Syscw, current.Syscw)
	if err != nil {
		return Rates{}, err
	}

	seconds := interval.Seconds()
	readBytesPerSecond := float64(readBytes) / seconds
	writeBytesPerSecond := float64(writeBytes) / seconds
	return Rates{
		ReadBytesPerSecond:  readBytesPerSecond,
		WriteBytesPerSecond: writeBytesPerSecond,
		ReadMiBPerSecond:    readBytesPerSecond / bytesPerMiB,
		WriteMiBPerSecond:   writeBytesPerSecond / bytesPerMiB,
		SyscrPerSecond:      float64(syscr) / seconds,
		SyscwPerSecond:      float64(syscw) / seconds,
	}, nil
}

func processCounterDelta(name string, previous, current uint64) (uint64, error) {
	if current < previous {
		return 0, fmt.Errorf("%s counter decreased", name)
	}
	return current - previous, nil
}
