package hostmetrics

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type cpuCounters struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal uint64
}

func parseProcStat(data []byte) (cpuCounters, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "cpu" {
			continue
		}
		if len(fields) < 9 {
			return cpuCounters{}, fmt.Errorf("aggregate cpu line has %d fields; need at least 9", len(fields))
		}
		values := make([]uint64, 8)
		for index := range values {
			value, err := strconv.ParseUint(fields[index+1], 10, 64)
			if err != nil {
				return cpuCounters{}, fmt.Errorf("parse aggregate cpu field %d: %w", index+1, err)
			}
			values[index] = value
		}
		return cpuCounters{
			User: values[0], Nice: values[1], System: values[2], Idle: values[3],
			IOWait: values[4], IRQ: values[5], SoftIRQ: values[6], Steal: values[7],
		}, nil
	}
	return cpuCounters{}, errors.New("aggregate cpu line not found")
}

func calculateCPU(previous, current cpuCounters, source string) (CPUStatus, error) {
	before := []uint64{previous.User, previous.Nice, previous.System, previous.Idle, previous.IOWait, previous.IRQ, previous.SoftIRQ, previous.Steal}
	after := []uint64{current.User, current.Nice, current.System, current.Idle, current.IOWait, current.IRQ, current.SoftIRQ, current.Steal}
	delta := make([]uint64, len(before))
	var total uint64
	for index := range before {
		if after[index] < before[index] {
			return CPUStatus{}, errors.New("aggregate CPU counter reset or wrapped")
		}
		delta[index] = after[index] - before[index]
		total += delta[index]
	}
	if total == 0 {
		return CPUStatus{}, errors.New("aggregate CPU counters did not advance")
	}
	percent := func(value uint64) float64 { return float64(value) / float64(total) * 100 }
	idle := delta[3]
	iowait := delta[4]
	busy := total - idle - iowait
	return CPUStatus{
		Availability:     derived(source),
		UserPercent:      percent(delta[0] + delta[1]),
		SystemPercent:    percent(delta[2] + delta[5] + delta[6]),
		IdlePercent:      percent(idle),
		IOWaitPercent:    percent(iowait),
		StealPercent:     percent(delta[7]),
		TotalBusyPercent: percent(busy),
	}, nil
}
