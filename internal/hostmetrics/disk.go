package hostmetrics

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type diskCounters struct {
	Name                   string
	ReadsCompleted         uint64
	WritesCompleted        uint64
	SectorsRead            uint64
	SectorsWritten         uint64
	IOInProgress           uint64
	WeightedIOMilliseconds uint64
}

// parseDiskstats parses and validates diskstats.
func parseDiskstats(data []byte) (map[string]diskCounters, error) {
	devices := make(map[string]diskCounters)
	for lineNumber, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 14 {
			return nil, fmt.Errorf("diskstats line %d has %d fields; need at least 14", lineNumber+1, len(fields))
		}
		indexes := []int{3, 7, 5, 9, 11, 13}
		values := make([]uint64, len(indexes))
		for index, fieldIndex := range indexes {
			value, err := strconv.ParseUint(fields[fieldIndex], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse diskstats line %d field %d: %w", lineNumber+1, fieldIndex+1, err)
			}
			values[index] = value
		}
		name := fields[2]
		devices[name] = diskCounters{
			Name: name, ReadsCompleted: values[0], WritesCompleted: values[1],
			SectorsRead: values[2], SectorsWritten: values[3], IOInProgress: values[4],
			WeightedIOMilliseconds: values[5],
		}
	}
	if len(devices) == 0 {
		return nil, errors.New("diskstats contains no block devices")
	}
	return devices, nil
}

// diskStatuses builds disk statuses from validated inputs.
func diskStatuses(previous, current map[string]diskCounters, interval time.Duration, source string) []DiskStatus {
	names := make([]string, 0, len(current))
	for name := range current {
		names = append(names, name)
	}
	sort.Strings(names)
	statuses := make([]DiskStatus, 0, len(names))
	for _, name := range names {
		counter := current[name]
		status := DiskStatus{
			Name: name, Availability: measured(source), ReadsCompleted: counter.ReadsCompleted,
			WritesCompleted: counter.WritesCompleted, SectorsRead: counter.SectorsRead,
			SectorsWritten: counter.SectorsWritten, IOInProgress: counter.IOInProgress,
			WeightedIOMilliseconds: counter.WeightedIOMilliseconds,
		}
		before, present := previous[name]
		if !present {
			status.RateAvailability = unavailable(source, errors.New("previous disk sample unavailable"))
		} else if err := applyDiskRates(&status, before, counter, interval); err != nil {
			status.RateAvailability = unavailable(source, err)
		} else {
			status.RateAvailability = derived(source)
		}
		statuses = append(statuses, status)
	}
	return statuses
}

// applyDiskRates applies disk rates to the current model.
func applyDiskRates(status *DiskStatus, previous, current diskCounters, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("disk rate interval must be positive")
	}
	before := []uint64{previous.ReadsCompleted, previous.WritesCompleted, previous.SectorsRead, previous.SectorsWritten}
	after := []uint64{current.ReadsCompleted, current.WritesCompleted, current.SectorsRead, current.SectorsWritten}
	deltas := make([]uint64, len(before))
	for index := range before {
		if after[index] < before[index] {
			return errors.New("disk counter reset or wrapped")
		}
		deltas[index] = after[index] - before[index]
	}
	seconds := interval.Seconds()
	status.ReadsPerSecond = float64(deltas[0]) / seconds
	status.WritesPerSecond = float64(deltas[1]) / seconds
	status.ReadSectorsPerSecond = float64(deltas[2]) / seconds
	status.WriteSectorsPerSecond = float64(deltas[3]) / seconds
	return nil
}
