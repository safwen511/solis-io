package ebpf

import (
	"bufio"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CgroupIOCounters is one cumulative cgroup v2 io.stat device row.
type CgroupIOCounters struct {
	Device          string
	ReadBytes       uint64
	WriteBytes      uint64
	ReadOps         uint64
	WriteOps        uint64
	DiscardBytes    uint64
	DiscardOps      uint64
	DiscardBytesSet bool
	DiscardOpsSet   bool
}

// ParseCgroupIOStat parses cgroup v2 io.stat without combining stacked block
// devices. Each major:minor row remains independent.
func ParseCgroupIOStat(data string) ([]CgroupIOCounters, error) {
	rows := make([]CgroupIOCounters, 0)
	seenDevices := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if !validMajorMinor(fields[0]) {
			return nil, fmt.Errorf("invalid cgroup io.stat device %q", fields[0])
		}
		row := CgroupIOCounters{Device: fields[0]}
		if seenDevices[row.Device] {
			return nil, fmt.Errorf("duplicate cgroup io.stat device %q", row.Device)
		}
		seenDevices[row.Device] = true
		for _, field := range fields[1:] {
			key, valueText, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			value, err := strconv.ParseUint(valueText, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse cgroup io.stat %s for %s: %w", key, row.Device, err)
			}
			switch key {
			case "rbytes":
				row.ReadBytes = value
			case "wbytes":
				row.WriteBytes = value
			case "rios":
				row.ReadOps = value
			case "wios":
				row.WriteOps = value
			case "dbytes":
				row.DiscardBytes = value
				row.DiscardBytesSet = true
			case "dios":
				row.DiscardOps = value
				row.DiscardOpsSet = true
			}
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Device < rows[j].Device })
	return rows, nil
}

// DeltaCgroupIOStat computes deltas only for identities present in both
// samples. New, disappeared, and reset rows are explicit and never turn
// cumulative lifetime counters into observation-window activity. Stacked
// device layers remain separate.
func DeltaCgroupIOStat(vm, cgroupPath string, before, after []CgroupIOCounters) ([]CgroupIOStatDelta, error) {
	baseline, err := indexCgroupIOCounters(before)
	if err != nil {
		return nil, fmt.Errorf("baseline cgroup io.stat: %w", err)
	}
	current, err := indexCgroupIOCounters(after)
	if err != nil {
		return nil, fmt.Errorf("after cgroup io.stat: %w", err)
	}
	devices := unionSortedKeys(baseline, current)
	deltas := make([]CgroupIOStatDelta, 0, len(devices))
	for _, device := range devices {
		start, hasBaseline := baseline[device]
		end, hasAfter := current[device]
		delta := CgroupIOStatDelta{VM: vm, CgroupPath: cgroupPath, Device: device}
		switch {
		case !hasBaseline:
			delta.Status = "baseline_missing"
		case !hasAfter:
			delta.Status = "missing_after"
		default:
			delta.Status = "ok"
			delta.ReadBytes, delta.CounterReset = validationCounterDelta(start.ReadBytes, end.ReadBytes)
			var reset bool
			delta.WriteBytes, reset = validationCounterDelta(start.WriteBytes, end.WriteBytes)
			delta.CounterReset = delta.CounterReset || reset
			delta.ReadOps, reset = validationCounterDelta(start.ReadOps, end.ReadOps)
			delta.CounterReset = delta.CounterReset || reset
			delta.WriteOps, reset = validationCounterDelta(start.WriteOps, end.WriteOps)
			delta.CounterReset = delta.CounterReset || reset
			delta.DiscardBytesAvailable = start.DiscardBytesSet && end.DiscardBytesSet
			if delta.DiscardBytesAvailable {
				delta.DiscardBytes, reset = validationCounterDelta(start.DiscardBytes, end.DiscardBytes)
				delta.CounterReset = delta.CounterReset || reset
			}
			delta.DiscardOpsAvailable = start.DiscardOpsSet && end.DiscardOpsSet
			if delta.DiscardOpsAvailable {
				delta.DiscardOps, reset = validationCounterDelta(start.DiscardOps, end.DiscardOps)
				delta.CounterReset = delta.CounterReset || reset
			}
			if delta.CounterReset {
				delta.Status = "counter_reset"
				delta.ReadBytes = 0
				delta.WriteBytes = 0
				delta.ReadOps = 0
				delta.WriteOps = 0
				delta.DiscardBytes = 0
				delta.DiscardOps = 0
			}
		}
		deltas = append(deltas, delta)
	}
	sort.Slice(deltas, func(i, j int) bool { return deltas[i].Device < deltas[j].Device })
	return deltas, nil
}

// VirshBlockCounters is one cumulative virsh domstats --block device group.
type VirshBlockCounters struct {
	Block       string
	ReadBytes   uint64
	WriteBytes  uint64
	ReadOps     uint64
	WriteOps    uint64
	ReadTimeNS  uint64
	WriteTimeNS uint64
	FlushOps    uint64
	FlushTimeNS uint64
}

// ParseVirshDomstatsBlock parses fixed libvirt block-stat keys. Unknown keys
// are ignored and no command text or guest data is accepted.
func ParseVirshDomstatsBlock(data string) ([]VirshBlockCounters, error) {
	values := make(map[int]map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(key, "block.") {
			continue
		}
		parts := strings.Split(key, ".")
		if len(parts) < 3 || parts[1] == "count" {
			continue
		}
		index, err := strconv.Atoi(parts[1])
		if err != nil || index < 0 {
			continue
		}
		field := strings.Join(parts[2:], ".")
		if values[index] == nil {
			values[index] = make(map[string]string)
		}
		if _, duplicate := values[index][field]; duplicate {
			return nil, fmt.Errorf("duplicate virsh domstats block key %q", key)
		}
		values[index][field] = strings.Trim(value, "'\"")
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	indexes := make([]int, 0, len(values))
	for index := range values {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	rows := make([]VirshBlockCounters, 0, len(indexes))
	seenBlocks := make(map[string]bool)
	for _, index := range indexes {
		fields := values[index]
		block := firstNonEmpty(fields["name"], fields["path"], fmt.Sprintf("block.%d", index))
		row := VirshBlockCounters{Block: block}
		if seenBlocks[block] {
			return nil, fmt.Errorf("duplicate virsh domstats block identity %q", block)
		}
		seenBlocks[block] = true
		orderedNumericFields := []struct {
			key         string
			destination *uint64
		}{
			{key: "rd.bytes", destination: &row.ReadBytes},
			{key: "wr.bytes", destination: &row.WriteBytes},
			{key: "rd.reqs", destination: &row.ReadOps},
			{key: "wr.reqs", destination: &row.WriteOps},
			{key: "rd.times", destination: &row.ReadTimeNS},
			{key: "wr.times", destination: &row.WriteTimeNS},
			{key: "fl.reqs", destination: &row.FlushOps},
			{key: "fl.times", destination: &row.FlushTimeNS},
		}
		for _, numeric := range orderedNumericFields {
			if fields[numeric.key] == "" {
				continue
			}
			value, err := strconv.ParseUint(fields[numeric.key], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse virsh domstats %s for %s: %w", numeric.key, block, err)
			}
			*numeric.destination = value
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Block < rows[j].Block })
	return rows, nil
}

// DeltaVirshBlockStats computes deltas only for virtual-disk identities found
// in both samples and explicitly labels baseline, disappearance, and reset
// conditions.
func DeltaVirshBlockStats(vm string, before, after []VirshBlockCounters) ([]VirshBlockDelta, error) {
	baseline, err := indexVirshBlockCounters(before)
	if err != nil {
		return nil, fmt.Errorf("baseline virsh domstats: %w", err)
	}
	current, err := indexVirshBlockCounters(after)
	if err != nil {
		return nil, fmt.Errorf("after virsh domstats: %w", err)
	}
	blocks := unionSortedKeys(baseline, current)
	deltas := make([]VirshBlockDelta, 0, len(blocks))
	for _, block := range blocks {
		start, hasBaseline := baseline[block]
		end, hasAfter := current[block]
		delta := VirshBlockDelta{VM: vm, Block: block}
		switch {
		case !hasBaseline:
			delta.Status = "baseline_missing"
		case !hasAfter:
			delta.Status = "missing_after"
		default:
			delta.Status = "ok"
			delta.ReadBytes, delta.CounterReset = validationCounterDelta(start.ReadBytes, end.ReadBytes)
			var reset bool
			delta.WriteBytes, reset = validationCounterDelta(start.WriteBytes, end.WriteBytes)
			delta.CounterReset = delta.CounterReset || reset
			delta.ReadOps, reset = validationCounterDelta(start.ReadOps, end.ReadOps)
			delta.CounterReset = delta.CounterReset || reset
			delta.WriteOps, reset = validationCounterDelta(start.WriteOps, end.WriteOps)
			delta.CounterReset = delta.CounterReset || reset
			delta.ReadTimeNS, reset = validationCounterDelta(start.ReadTimeNS, end.ReadTimeNS)
			delta.CounterReset = delta.CounterReset || reset
			delta.WriteTimeNS, reset = validationCounterDelta(start.WriteTimeNS, end.WriteTimeNS)
			delta.CounterReset = delta.CounterReset || reset
			delta.FlushOps, reset = validationCounterDelta(start.FlushOps, end.FlushOps)
			delta.CounterReset = delta.CounterReset || reset
			delta.FlushTimeNS, reset = validationCounterDelta(start.FlushTimeNS, end.FlushTimeNS)
			delta.CounterReset = delta.CounterReset || reset
			if delta.CounterReset {
				delta.Status = "counter_reset"
				delta.ReadBytes = 0
				delta.WriteBytes = 0
				delta.ReadOps = 0
				delta.WriteOps = 0
				delta.ReadTimeNS = 0
				delta.WriteTimeNS = 0
				delta.FlushOps = 0
				delta.FlushTimeNS = 0
			}
		}
		deltas = append(deltas, delta)
	}
	sort.Slice(deltas, func(i, j int) bool { return deltas[i].Block < deltas[j].Block })
	return deltas, nil
}

func validMajorMinor(value string) bool {
	major, minor, ok := strings.Cut(value, ":")
	if !ok || major == "" || minor == "" {
		return false
	}
	_, majorErr := strconv.ParseUint(major, 10, 32)
	_, minorErr := strconv.ParseUint(minor, 10, 32)
	return majorErr == nil && minorErr == nil
}

func validationCounterDelta(before, after uint64) (uint64, bool) {
	if after < before {
		return 0, true
	}
	return after - before, false
}

func indexCgroupIOCounters(rows []CgroupIOCounters) (map[string]CgroupIOCounters, error) {
	indexed := make(map[string]CgroupIOCounters, len(rows))
	for _, row := range rows {
		if !validMajorMinor(row.Device) {
			return nil, fmt.Errorf("invalid device %q", row.Device)
		}
		if _, duplicate := indexed[row.Device]; duplicate {
			return nil, fmt.Errorf("duplicate device %q", row.Device)
		}
		indexed[row.Device] = row
	}
	return indexed, nil
}

func indexVirshBlockCounters(rows []VirshBlockCounters) (map[string]VirshBlockCounters, error) {
	indexed := make(map[string]VirshBlockCounters, len(rows))
	for _, row := range rows {
		row.Block = strings.TrimSpace(row.Block)
		if row.Block == "" {
			return nil, fmt.Errorf("empty block identity")
		}
		if _, duplicate := indexed[row.Block]; duplicate {
			return nil, fmt.Errorf("duplicate block identity %q", row.Block)
		}
		indexed[row.Block] = row
	}
	return indexed, nil
}

func unionSortedKeys[T any](left, right map[string]T) []string {
	keys := make([]string, 0, len(left)+len(right))
	seen := make(map[string]bool, len(left)+len(right))
	for key := range left {
		seen[key] = true
		keys = append(keys, key)
	}
	for key := range right {
		if seen[key] {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
