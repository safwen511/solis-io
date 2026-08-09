package hostmetrics

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func qemuCommand(data []byte) (string, bool) {
	command := strings.TrimSpace(string(data))
	return command, strings.HasPrefix(command, "qemu-system-")
}

func parseRSSBytes(data []byte) (uint64, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "VmRSS:" {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse VmRSS: %w", err)
		}
		if len(fields) >= 3 && fields[2] != "kB" {
			return 0, fmt.Errorf("VmRSS has unsupported unit %q", fields[2])
		}
		return value * 1024, nil
	}
	return 0, errors.New("VmRSS not found")
}

func parseProcessCPUTicks(data []byte) (uint64, error) {
	line := strings.TrimSpace(string(data))
	closing := strings.LastIndex(line, ")")
	if closing < 0 || closing+1 >= len(line) {
		return 0, errors.New("invalid process stat comm field")
	}
	fields := strings.Fields(line[closing+1:])
	if len(fields) < 13 {
		return 0, errors.New("process stat has too few fields")
	}
	userTicks, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse process user ticks: %w", err)
	}
	systemTicks, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse process system ticks: %w", err)
	}
	return userTicks + systemTicks, nil
}

func numericPID(value string) (int, bool) {
	pid, err := strconv.Atoi(value)
	return pid, err == nil && pid > 0
}
