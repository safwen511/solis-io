package top

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ProcessResources is a bounded, privacy-safe view of the current Solis
// process. It contains aggregate resource counters only: no arguments,
// environment, open paths, file names, or per-thread identities.
type ProcessResources struct {
	CPUPercent          float64
	CPUAvailable        bool
	RSSBytes            uint64
	MemoryAvailable     bool
	ReadBytesPerSecond  float64
	WriteBytesPerSecond float64
	DiskIOAvailable     bool
	Goroutines          int
	Uptime              time.Duration
}

type processResourceCounters struct {
	cpu        time.Duration
	readBytes  uint64
	writeBytes uint64
	cpuOK      bool
	diskOK     bool
}

type processResourceMeter struct {
	started  time.Time
	previous time.Time
	counters processResourceCounters
}

// newProcessResourceMeter snapshots Solis aggregate counters for later interval deltas.
func newProcessResourceMeter(now time.Time) *processResourceMeter {
	if now.IsZero() {
		now = time.Now()
	}
	return &processResourceMeter{started: now, previous: now, counters: readProcessResourceCounters()}
}

// Sample reports Solis CPU, RSS, disk I/O, goroutine, and uptime aggregates for the UI.
func (meter *processResourceMeter) Sample(now time.Time) ProcessResources {
	if now.IsZero() {
		now = time.Now()
	}
	current := readProcessResourceCounters()
	result := ProcessResources{Goroutines: runtime.NumGoroutine(), Uptime: now.Sub(meter.started)}
	if result.Uptime < 0 {
		result.Uptime = 0
	}
	if rss, ok := readSelfRSS(); ok {
		result.RSSBytes = rss
		result.MemoryAvailable = true
	}
	elapsed := now.Sub(meter.previous).Seconds()
	if elapsed >= 0.05 && current.cpuOK && meter.counters.cpuOK && current.cpu >= meter.counters.cpu {
		result.CPUPercent = (current.cpu - meter.counters.cpu).Seconds() / elapsed * 100
		result.CPUAvailable = true
	}
	if elapsed >= 0.05 && current.diskOK && meter.counters.diskOK &&
		current.readBytes >= meter.counters.readBytes && current.writeBytes >= meter.counters.writeBytes {
		result.ReadBytesPerSecond = float64(current.readBytes-meter.counters.readBytes) / elapsed
		result.WriteBytesPerSecond = float64(current.writeBytes-meter.counters.writeBytes) / elapsed
		result.DiskIOAvailable = true
	}
	meter.previous = now
	meter.counters = current
	return result
}

// readProcessResourceCounters reads only aggregate self counters, never arguments or environments.
func readProcessResourceCounters() processResourceCounters {
	var result processResourceCounters
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err == nil {
		result.cpu = timevalDuration(usage.Utime) + timevalDuration(usage.Stime)
		result.cpuOK = true
	}
	if readBytes, writeBytes, ok := readSelfDiskIO(); ok {
		result.readBytes = readBytes
		result.writeBytes = writeBytes
		result.diskOK = true
	}
	return result
}

// timevalDuration converts a kernel timeval into a Go duration without floating-point loss.
func timevalDuration(value unix.Timeval) time.Duration {
	return time.Duration(value.Sec)*time.Second + time.Duration(value.Usec)*time.Microsecond
}

// readSelfRSS derives resident bytes from the current process's aggregate statm counters.
func readSelfRSS() (uint64, bool) {
	contents, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(contents))
	if len(fields) < 2 {
		return 0, false
	}
	residentPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	pageSize := os.Getpagesize()
	if pageSize <= 0 || residentPages > ^uint64(0)/uint64(pageSize) {
		return 0, false
	}
	return residentPages * uint64(pageSize), true
}

// readSelfDiskIO reads only aggregate self I/O byte counters.
func readSelfDiskIO() (uint64, uint64, bool) {
	contents, err := os.ReadFile("/proc/self/io")
	if err != nil {
		return 0, 0, false
	}
	return parseSelfDiskIO(string(contents))
}

// parseSelfDiskIO extracts read_bytes and write_bytes while ignoring unrelated fields.
func parseSelfDiskIO(contents string) (uint64, uint64, bool) {
	var readBytes, writeBytes uint64
	readFound := false
	writeFound := false
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "read_bytes":
			readBytes = value
			readFound = true
		case "write_bytes":
			writeBytes = value
			writeFound = true
		}
	}
	if scanner.Err() != nil || !readFound || !writeFound {
		return 0, 0, false
	}
	return readBytes, writeBytes, true
}
