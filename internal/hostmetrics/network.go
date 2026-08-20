package hostmetrics

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type networkCounters struct {
	Interface                               string
	RXBytes, RXPackets, RXErrors, RXDropped uint64
	TXBytes, TXPackets, TXErrors, TXDropped uint64
}

// parseNetDev parses and validates net dev.
func parseNetDev(data []byte) (map[string]networkCounters, error) {
	interfaces := make(map[string]networkCounters)
	for lineNumber, line := range strings.Split(string(data), "\n") {
		namePart, countersPart, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		name := strings.TrimSpace(namePart)
		fields := strings.Fields(countersPart)
		if name == "" || len(fields) < 16 {
			return nil, fmt.Errorf("net/dev line %d has invalid interface data", lineNumber+1)
		}
		indexes := []int{0, 1, 2, 3, 8, 9, 10, 11}
		values := make([]uint64, len(indexes))
		for index, fieldIndex := range indexes {
			value, err := strconv.ParseUint(fields[fieldIndex], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse net/dev line %d field %d: %w", lineNumber+1, fieldIndex+1, err)
			}
			values[index] = value
		}
		interfaces[name] = networkCounters{
			Interface: name, RXBytes: values[0], RXPackets: values[1], RXErrors: values[2], RXDropped: values[3],
			TXBytes: values[4], TXPackets: values[5], TXErrors: values[6], TXDropped: values[7],
		}
	}
	if len(interfaces) == 0 {
		return nil, errors.New("net/dev contains no interfaces")
	}
	return interfaces, nil
}

// networkStatuses builds network statuses from validated inputs.
func networkStatuses(previous, current map[string]networkCounters, interval time.Duration, source string) []NetworkInterfaceStatus {
	names := make([]string, 0, len(current))
	for name := range current {
		names = append(names, name)
	}
	sort.Strings(names)
	statuses := make([]NetworkInterfaceStatus, 0, len(names))
	for _, name := range names {
		counter := current[name]
		status := NetworkInterfaceStatus{
			Interface: name, Availability: measured(source), RXBytes: counter.RXBytes, TXBytes: counter.TXBytes,
			RXPackets: counter.RXPackets, TXPackets: counter.TXPackets, RXErrors: counter.RXErrors,
			TXErrors: counter.TXErrors, RXDropped: counter.RXDropped, TXDropped: counter.TXDropped,
		}
		before, present := previous[name]
		if !present {
			status.RateAvailability = unavailable(source, errors.New("previous network sample unavailable"))
		} else if err := applyNetworkRates(&status, before, counter, interval); err != nil {
			status.RateAvailability = unavailable(source, err)
		} else {
			status.RateAvailability = derived(source)
		}
		statuses = append(statuses, status)
	}
	return statuses
}

// applyNetworkRates applies network rates to the current model.
func applyNetworkRates(status *NetworkInterfaceStatus, previous, current networkCounters, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("network rate interval must be positive")
	}
	if current.RXBytes < previous.RXBytes || current.TXBytes < previous.TXBytes {
		return errors.New("network counter reset or wrapped")
	}
	seconds := interval.Seconds()
	status.RXBytesPerSecond = float64(current.RXBytes-previous.RXBytes) / seconds
	status.TXBytesPerSecond = float64(current.TXBytes-previous.TXBytes) / seconds
	return nil
}
