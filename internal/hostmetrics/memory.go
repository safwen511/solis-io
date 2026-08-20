package hostmetrics

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// parseMemInfo parses and validates mem info.
func parseMemInfo(data []byte, source string) (MemoryStatus, error) {
	values := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		if key != "MemTotal" && key != "MemAvailable" && key != "SwapTotal" && key != "SwapFree" {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return MemoryStatus{}, fmt.Errorf("parse %s: %w", key, err)
		}
		if len(fields) >= 3 && fields[2] != "kB" {
			return MemoryStatus{}, fmt.Errorf("%s has unsupported unit %q", key, fields[2])
		}
		values[key] = value * 1024
	}
	memTotal, totalPresent := values["MemTotal"]
	memAvailable, availablePresent := values["MemAvailable"]
	if !totalPresent || !availablePresent || memTotal == 0 {
		return MemoryStatus{}, errors.New("MemTotal and MemAvailable are required")
	}
	if memAvailable > memTotal {
		return MemoryStatus{}, errors.New("MemAvailable exceeds MemTotal")
	}
	swapTotal := values["SwapTotal"]
	swapFree := values["SwapFree"]
	if swapFree > swapTotal {
		return MemoryStatus{}, errors.New("SwapFree exceeds SwapTotal")
	}
	return MemoryStatus{
		Availability:        measured(source),
		MemTotalBytes:       memTotal,
		MemAvailableBytes:   memAvailable,
		MemUsedBytes:        memTotal - memAvailable,
		MemAvailablePercent: float64(memAvailable) / float64(memTotal) * 100,
		SwapTotalBytes:      swapTotal,
		SwapFreeBytes:       swapFree,
		SwapUsedBytes:       swapTotal - swapFree,
	}, nil
}
