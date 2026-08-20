package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const defaultSysfsBlockPath = "/sys/class/block"

// readDeviceStats reads device stats from its configured source.
func readDeviceStats(physicalDisk string) DeviceStats {
	return readDeviceStatsFrom(physicalDisk, defaultSysfsBlockPath)
}

// readDeviceStatsFrom reads device stats from from its configured source.
func readDeviceStatsFrom(physicalDisk, sysfsBlockPath string) DeviceStats {
	stats := DeviceStats{PhysicalDisk: physicalDisk}
	deviceName := filepath.Base(strings.TrimSpace(physicalDisk))
	if deviceName == "" || deviceName == "." {
		return stats
	}

	data, err := os.ReadFile(filepath.Join(sysfsBlockPath, deviceName, "stat"))
	if err != nil {
		return stats
	}
	parsed, err := parseBlockStat(string(data))
	if err != nil {
		return stats
	}
	parsed.PhysicalDisk = physicalDisk
	return parsed
}

// parseBlockStat parses and validates block stat.
func parseBlockStat(line string) (DeviceStats, error) {
	fields := strings.Fields(line)
	if len(fields) < 11 {
		return DeviceStats{}, fmt.Errorf("block stat has %d fields, need at least 11", len(fields))
	}

	indexes := []int{0, 4, 2, 6, 8, 9, 10}
	values := make([]uint64, len(indexes))
	for i, index := range indexes {
		value, err := strconv.ParseUint(fields[index], 10, 64)
		if err != nil {
			return DeviceStats{}, fmt.Errorf("parse block stat field %d: %w", index+1, err)
		}
		values[i] = value
	}

	return DeviceStats{
		ReadsCompleted:   knownCounter(values[0]),
		WritesCompleted:  knownCounter(values[1]),
		SectorsRead:      knownCounter(values[2]),
		SectorsWritten:   knownCounter(values[3]),
		IOInProgress:     knownCounter(values[4]),
		IOTimeMS:         knownCounter(values[5]),
		WeightedIOTimeMS: knownCounter(values[6]),
	}, nil
}

// knownCounter builds known counter from validated inputs.
func knownCounter(value uint64) Counter {
	return Counter{Value: value, Available: true}
}
