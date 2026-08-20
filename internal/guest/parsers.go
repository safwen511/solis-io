package guest

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/safwen511/solis-io/internal/observability"
)

// parseSingleLine parses and validates single line.
func parseSingleLine(output, field string) (string, error) {
	value := strings.TrimSpace(output)
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("%s output is empty or malformed", field)
	}
	return value, nil
}

// parseUptime parses and validates uptime.
func parseUptime(output string) (float64, error) {
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return 0, errors.New("uptime output is empty")
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || value < 0 {
		return 0, errors.New("uptime output contains an invalid value")
	}
	return value, nil
}

// parseLoad parses and validates load.
func parseLoad(output string) (observability.GuestCPUStatus, error) {
	fields := strings.Fields(output)
	if len(fields) < 3 {
		return observability.GuestCPUStatus{}, errors.New("load output has fewer than three fields")
	}
	values := make([]float64, 3)
	for index := range values {
		value, err := strconv.ParseFloat(fields[index], 64)
		if err != nil || value < 0 {
			return observability.GuestCPUStatus{}, errors.New("load output contains an invalid value")
		}
		values[index] = value
	}
	return observability.GuestCPUStatus{Load1: values[0], Load5: values[1], Load15: values[2]}, nil
}

// parseMemory parses and validates memory.
func parseMemory(output string) (observability.GuestMemoryStatus, error) {
	values := make(map[string]uint64)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		if name != "MemTotal" && name != "MemAvailable" && name != "SwapTotal" && name != "SwapFree" {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return observability.GuestMemoryStatus{}, fmt.Errorf("%s contains an invalid value", name)
		}
		if len(fields) >= 3 && fields[2] != "kB" {
			return observability.GuestMemoryStatus{}, fmt.Errorf("%s uses an unsupported unit", name)
		}
		values[name] = value * 1024
	}
	if values["MemTotal"] == 0 {
		return observability.GuestMemoryStatus{}, errors.New("MemTotal is missing")
	}
	swapUsed := uint64(0)
	if values["SwapTotal"] >= values["SwapFree"] {
		swapUsed = values["SwapTotal"] - values["SwapFree"]
	}
	return observability.GuestMemoryStatus{
		TotalBytes: values["MemTotal"], AvailableBytes: values["MemAvailable"], SwapUsedBytes: swapUsed,
	}, nil
}

// parseFilesystems parses and validates filesystems.
func parseFilesystems(output string) ([]observability.FilesystemStatus, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		return nil, errors.New("filesystem output has no data rows")
	}
	filesystems := make([]observability.FilesystemStatus, 0, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		size, sizeErr := strconv.ParseUint(fields[1], 10, 64)
		used, usedErr := strconv.ParseUint(fields[2], 10, 64)
		percent, percentErr := strconv.ParseFloat(strings.TrimSuffix(fields[4], "%"), 64)
		if sizeErr != nil || usedErr != nil || percentErr != nil {
			return nil, errors.New("filesystem output contains invalid counters")
		}
		filesystems = append(filesystems, observability.FilesystemStatus{
			Filesystem: fields[0], SizeBytes: size, UsedBytes: used,
			UsedPercent: percent, Mountpoint: strings.Join(fields[5:], " "),
		})
	}
	if len(filesystems) == 0 {
		return nil, errors.New("filesystem output contains no parseable rows")
	}
	sort.Slice(filesystems, func(i, j int) bool { return filesystems[i].Mountpoint < filesystems[j].Mountpoint })
	return filesystems, nil
}

// parseNetworkAddresses parses and validates network addresses.
func parseNetworkAddresses(output string) map[string]string {
	addresses := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		values := make([]string, 0, len(fields)-2)
		for _, value := range fields[2:] {
			if strings.Contains(value, "/") {
				values = append(values, value)
			}
		}
		sort.Strings(values)
		addresses[fields[0]] = strings.Join(values, ",")
	}
	return addresses
}

// parseNetworkCounters parses and validates network counters.
func parseNetworkCounters(output string) (map[string]observability.NetworkStatus, error) {
	counters := make(map[string]observability.NetworkStatus)
	for _, line := range strings.Split(output, "\n") {
		separator := strings.IndexByte(line, ':')
		if separator < 0 {
			continue
		}
		name := strings.TrimSpace(line[:separator])
		fields := strings.Fields(line[separator+1:])
		if name == "" || len(fields) < 16 {
			continue
		}
		values := make([]uint64, 16)
		valid := true
		for index := range values {
			value, err := strconv.ParseUint(fields[index], 10, 64)
			if err != nil {
				valid = false
				break
			}
			values[index] = value
		}
		if !valid {
			return nil, errors.New("network output contains invalid counters")
		}
		counters[name] = observability.NetworkStatus{
			Interface: name, RXBytes: values[0], RXErrors: values[2],
			TXBytes: values[8], TXErrors: values[10],
		}
	}
	if len(counters) == 0 {
		return nil, errors.New("network counter output contains no interfaces")
	}
	return counters, nil
}

// mergeNetwork merges network while preserving explicit availability.
func mergeNetwork(addresses map[string]string, counters map[string]observability.NetworkStatus) []observability.NetworkStatus {
	names := make(map[string]struct{}, len(addresses)+len(counters))
	for name := range addresses {
		names[name] = struct{}{}
	}
	for name := range counters {
		names[name] = struct{}{}
	}
	result := make([]observability.NetworkStatus, 0, len(names))
	for name := range names {
		status := counters[name]
		status.Interface = name
		status.Address = addresses[name]
		result = append(result, status)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Interface < result[j].Interface })
	return result
}

// parseProcessPressure parses and validates process pressure.
func parseProcessPressure(output string) ([]observability.ProcessPressure, error) {
	processes := make([]observability.ProcessPressure, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		pid, pidErr := strconv.Atoi(fields[0])
		ppid, ppidErr := strconv.Atoi(fields[1])
		cpu, cpuErr := strconv.ParseFloat(fields[3], 64)
		memory, memoryErr := strconv.ParseFloat(fields[4], 64)
		if pidErr != nil || ppidErr != nil || cpuErr != nil || memoryErr != nil || pid <= 0 {
			continue
		}
		// Any trailing fields are deliberately ignored; only the short comm field
		// at index two is represented in the model.
		processes = append(processes, observability.ProcessPressure{
			PID: pid, PPID: ppid, Command: fields[2], CPUPercent: cpu, MemoryPercent: memory,
		})
		if len(processes) == 30 {
			break
		}
	}
	if len(processes) == 0 {
		return nil, errors.New("process output contains no parseable rows")
	}
	sort.Slice(processes, func(i, j int) bool {
		if processes[i].CPUPercent != processes[j].CPUPercent {
			return processes[i].CPUPercent > processes[j].CPUPercent
		}
		return processes[i].PID < processes[j].PID
	})
	return processes, nil
}

// parseListeningPorts parses and validates listening ports.
func parseListeningPorts(output string) ([]observability.ListeningPort, error) {
	ports := make([]observability.ListeningPort, 0)
	seen := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		protocol := strings.ToLower(fields[0])
		if protocol != "tcp" && protocol != "udp" {
			continue
		}
		address, port, ok := splitEndpoint(fields[4])
		if !ok {
			continue
		}
		process := parseSSProcess(line)
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%s", protocol, address, port, process)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		ports = append(ports, observability.ListeningPort{Protocol: protocol, Address: address, Port: port, Process: process})
	}
	if len(ports) == 0 && strings.TrimSpace(output) != "" {
		return nil, errors.New("listening-port output contains no parseable sockets")
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Protocol != ports[j].Protocol {
			return ports[i].Protocol < ports[j].Protocol
		}
		if ports[i].Address != ports[j].Address {
			return ports[i].Address < ports[j].Address
		}
		if ports[i].Port != ports[j].Port {
			return ports[i].Port < ports[j].Port
		}
		return ports[i].Process < ports[j].Process
	})
	return ports, nil
}

// ParseListeningPorts parses sanitized ss output for service collection.
func ParseListeningPorts(output string) ([]observability.ListeningPort, error) {
	return parseListeningPorts(output)
}

// splitEndpoint builds split endpoint from validated inputs.
func splitEndpoint(value string) (string, int, bool) {
	separator := strings.LastIndexByte(value, ':')
	if separator < 0 {
		return "", 0, false
	}
	address := strings.Trim(value[:separator], "[]")
	port, err := strconv.Atoi(value[separator+1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	if address != "*" && net.ParseIP(address) == nil {
		return "", 0, false
	}
	return address, port, true
}

// parseSSProcess parses and validates ss process.
func parseSSProcess(line string) string {
	marker := `users:(("`
	start := strings.Index(line, marker)
	if start < 0 {
		return ""
	}
	remaining := line[start+len(marker):]
	end := strings.IndexByte(remaining, '"')
	if end < 0 {
		return ""
	}
	name := remaining[:end]
	for _, character := range name {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-", character)) {
			return ""
		}
	}
	return name
}

// ParseSystemdUnit parses only properties explicitly requested by the fixed
// systemctl command; all other properties are discarded.
func ParseSystemdUnit(output string) (observability.SystemdUnitStatus, error) {
	allowed := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		name, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch name {
		case "Id", "ActiveState", "SubState", "MainPID", "NRestarts", "ExecMainStartTimestamp":
			allowed[name] = strings.TrimSpace(value)
		}
	}
	if allowed["Id"] == "" {
		return observability.SystemdUnitStatus{}, errors.New("systemd output is missing Id")
	}
	mainPID, err := parseOptionalInt(allowed["MainPID"])
	if err != nil {
		return observability.SystemdUnitStatus{}, errors.New("systemd output contains invalid MainPID")
	}
	restarts, err := parseOptionalUint(allowed["NRestarts"])
	if err != nil {
		return observability.SystemdUnitStatus{}, errors.New("systemd output contains invalid NRestarts")
	}
	return observability.SystemdUnitStatus{
		ID: allowed["Id"], ActiveState: allowed["ActiveState"], SubState: allowed["SubState"],
		MainPID: mainPID, Restarts: restarts, MainStartTimestamp: allowed["ExecMainStartTimestamp"],
	}, nil
}

// parseOptionalInt parses and validates optional int.
func parseOptionalInt(value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	return strconv.Atoi(value)
}

// parseOptionalUint parses and validates optional uint.
func parseOptionalUint(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	return strconv.ParseUint(value, 10, 64)
}
