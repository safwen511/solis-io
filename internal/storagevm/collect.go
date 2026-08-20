package storagevm

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
)

// CollectRequest describes one validation window. VMs and mappings must be
// resolved from the local inventory before collection.
type CollectRequest struct {
	VMs          []inventory.VM
	Mappings     []ebpf.VMBlockCgroupMapping
	Duration     time.Duration
	Interval     time.Duration
	ConfigSource string
	LibvirtURI   string
	ObservedAt   time.Time
}

// Collector owns fixed, read-only local sources. Tests replace these sources
// with deterministic fakes; no arbitrary commands are accepted.
type Collector struct {
	cgroupRoot string
	files      fileReader
	virsh      virshBlockSource
	qemu       qemuIOSource
	identity   qemuIdentitySource
	waiter     windowWaiter
	devices    deviceResolver
}

// NewCollector returns the production read-only collector.
func NewCollector() *Collector {
	return &Collector{
		cgroupRoot: defaultCgroupRoot,
		files:      osFileReader{},
		virsh:      execVirshBlockSource{},
		qemu:       procQEMUIOSource{},
		identity:   procQEMUIdentitySource{},
		waiter:     timerWindowWaiter{},
		devices:    sysfsDeviceResolver{sysDevRoot: defaultSysDevRoot, sysClassRoot: defaultSysClassRoot},
	}
}

type sourceSample struct {
	cgroupPath   string
	cgroupKind   string
	cgroupInode  uint64
	cgroupData   []byte
	cgroupErr    error
	virshData    []byte
	virshErr     error
	qemuData     qemuio.Counters
	qemuIdentity ebpf.QEMUProcessIdentity
	qemuErr      error
}

// Collect samples all requested VMs at the start and end of one window.
// Source-specific errors are embedded in the report and do not abort other
// evidence collection.
func (collector *Collector) Collect(ctx context.Context, request CollectRequest) (VMStorageStatsReport, error) {
	if request.Duration <= 0 {
		return VMStorageStatsReport{}, errors.New("duration must be greater than zero")
	}
	if request.Interval <= 0 {
		return VMStorageStatsReport{}, errors.New("interval must be greater than zero")
	}
	if request.Interval > request.Duration {
		return VMStorageStatsReport{}, fmt.Errorf("interval %s cannot exceed duration %s", request.Interval, request.Duration)
	}
	if collector == nil {
		collector = NewCollector()
	}
	collector.applyDefaults()

	observedAt := request.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	vms := append([]inventory.VM(nil), request.VMs...)
	sort.Slice(vms, func(i, j int) bool { return vms[i].Name < vms[j].Name })
	mappings := indexMappings(request.Mappings)
	baseline := make(map[string]sourceSample, len(vms))
	for _, vm := range vms {
		baseline[vm.Name] = collector.sampleBaseline(ctx, vm, mappings[vm.Name], request.LibvirtURI)
	}
	if err := collector.waiter.Wait(ctx, request.Duration, request.Interval); err != nil {
		return VMStorageStatsReport{}, fmt.Errorf("wait for VM storage observation window: %w", err)
	}
	after := make(map[string]sourceSample, len(vms))
	for _, vm := range vms {
		after[vm.Name] = collector.sampleAfter(ctx, vm, mappings[vm.Name], baseline[vm.Name], request.LibvirtURI)
	}

	report := VMStorageStatsReport{
		SchemaVersion: SchemaVersion,
		ObservedAtUTC: observedAt.Format(time.RFC3339Nano),
		Duration:      request.Duration.String(),
		Interval:      request.Interval.String(),
		ConfigSource:  valueOrDefault(request.ConfigSource, "built-in defaults"),
		VMs:           []VMStorageStatsVM{},
		HostDevices:   []HostDevice{},
		Caveats: []string{
			"cgroup io.stat provides per-VM byte and operation counters, not latency",
			"virsh domstats provides virtual-disk counters and cumulative timing, not host physical-device latency",
			"QEMU pressure is process-accounting correlation only",
			"stacked device rows are reported separately and are not summed",
			"this validation report does not prove customer impact or root cause",
		},
		UnavailableSections: []UnavailableSection{},
	}
	hostDevices := make(map[string]HostDevice)
	for _, vm := range vms {
		mapping := mappings[vm.Name]
		vmReport := collector.buildVMReport(vm, mapping, baseline[vm.Name], after[vm.Name], &report, hostDevices)
		report.VMs = append(report.VMs, vmReport)
	}
	for _, device := range hostDevices {
		report.HostDevices = append(report.HostDevices, device)
	}
	return normalizeReport(report), nil
}

// applyDefaults applies defaults to the current model.
func (collector *Collector) applyDefaults() {
	if collector.cgroupRoot == "" {
		collector.cgroupRoot = defaultCgroupRoot
	}
	if collector.files == nil {
		collector.files = osFileReader{}
	}
	if collector.virsh == nil {
		collector.virsh = execVirshBlockSource{}
	}
	if collector.qemu == nil {
		collector.qemu = procQEMUIOSource{}
	}
	if collector.identity == nil {
		collector.identity = procQEMUIdentitySource{}
	}
	if collector.waiter == nil {
		collector.waiter = timerWindowWaiter{}
	}
	if collector.devices == nil {
		collector.devices = sysfsDeviceResolver{sysDevRoot: defaultSysDevRoot, sysClassRoot: defaultSysClassRoot}
	}
}

// sampleBaseline samples baseline for the configured observation interval.
func (collector *Collector) sampleBaseline(ctx context.Context, vm inventory.VM, mapping ebpf.VMBlockCgroupMapping, uri string) sourceSample {
	if isKnownStopped(vm.State) {
		err := fmt.Errorf("VM state is %s", valueOrDefault(strings.TrimSpace(vm.State), "unknown"))
		return sourceSample{cgroupErr: err, virshErr: err, qemuErr: err}
	}
	path, kind, inode, data, cgroupErr := collector.readPreferredIOStat(mapping)
	virshData, virshErr := collector.virsh.ReadBlockStats(ctx, vm.Name, uri)
	qemuIdentity, qemuErr := collector.identity.Validate(mapping)
	var qemuData qemuio.Counters
	if qemuErr == nil {
		qemuData, qemuErr = collector.qemu.Read(strconv.Itoa(qemuIdentity.PID))
	}
	return sourceSample{
		cgroupPath: path, cgroupKind: kind, cgroupInode: inode, cgroupData: data, cgroupErr: cgroupErr,
		virshData: virshData, virshErr: virshErr, qemuData: qemuData, qemuIdentity: qemuIdentity, qemuErr: qemuErr,
	}
}

// sampleAfter samples after for the configured observation interval.
func (collector *Collector) sampleAfter(ctx context.Context, vm inventory.VM, mapping ebpf.VMBlockCgroupMapping, baseline sourceSample, uri string) sourceSample {
	if isKnownStopped(vm.State) {
		err := fmt.Errorf("VM state is %s", valueOrDefault(strings.TrimSpace(vm.State), "unknown"))
		return sourceSample{cgroupErr: err, virshErr: err, qemuErr: err}
	}
	var cgroupData []byte
	var cgroupInode uint64
	var cgroupErr error
	if baseline.cgroupPath == "" {
		cgroupErr = errors.New("cgroup io.stat baseline source unavailable")
	} else {
		path, err := rootedPath(collector.cgroupRoot, baseline.cgroupPath, "io.stat")
		if err != nil {
			cgroupErr = err
		} else {
			cgroupInode, cgroupErr = collector.files.Inode(filepath.Dir(path))
			if cgroupErr == nil {
				cgroupData, cgroupErr = collector.files.ReadFile(path)
			}
		}
	}
	virshData, virshErr := collector.virsh.ReadBlockStats(ctx, vm.Name, uri)
	qemuIdentity, qemuErr := collector.identity.Validate(mapping)
	var qemuData qemuio.Counters
	if qemuErr == nil && !ebpf.SameQEMUProcessIdentity(baseline.qemuIdentity, qemuIdentity) {
		qemuErr = errors.New("QEMU process identity changed during sampling window")
	}
	if qemuErr == nil {
		qemuData, qemuErr = collector.qemu.Read(strconv.Itoa(qemuIdentity.PID))
	}
	return sourceSample{
		cgroupPath: baseline.cgroupPath, cgroupKind: baseline.cgroupKind, cgroupInode: cgroupInode, cgroupData: cgroupData, cgroupErr: cgroupErr,
		virshData: virshData, virshErr: virshErr, qemuData: qemuData, qemuIdentity: qemuIdentity, qemuErr: qemuErr,
	}
}

// readPreferredIOStat reads preferred io stat from its configured source.
func (collector *Collector) readPreferredIOStat(mapping ebpf.VMBlockCgroupMapping) (string, string, uint64, []byte, error) {
	if len(mapping.CgroupPaths) == 0 {
		return "", "", 0, nil, fmt.Errorf("VM cgroup mapping unavailable: %s", valueOrDefault(mapping.MappingQuality, "unavailable"))
	}
	candidates := preferredCgroupCandidates(mapping)
	if len(candidates) == 0 {
		return "", "", 0, nil, errors.New("no aggregate VM or emulator cgroup is available for io.stat")
	}
	var failures []string
	for _, candidate := range candidates {
		path, err := rootedPath(collector.cgroupRoot, candidate.Path, "io.stat")
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		inode, err := collector.files.Inode(filepath.Dir(path))
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: read cgroup inode: %v", candidate.Path, err))
			continue
		}
		data, err := collector.files.ReadFile(path)
		if err == nil {
			return candidate.Path, candidate.Kind, inode, data, nil
		}
		failures = append(failures, fmt.Sprintf("%s: %v", candidate.Path, err))
	}
	return "", "", 0, nil, fmt.Errorf("read VM cgroup io.stat: %s", strings.Join(failures, "; "))
}

// buildVMReport builds vm report from validated inputs.
func (collector *Collector) buildVMReport(vm inventory.VM, mapping ebpf.VMBlockCgroupMapping, baseline, after sourceSample, report *VMStorageStatsReport, hostDevices map[string]HostDevice) VMStorageStatsVM {
	pid, _ := strconv.Atoi(strings.TrimSpace(vm.QEMUPID))
	if mapping.QEMUPID != 0 {
		pid = mapping.QEMUPID
	}
	result := VMStorageStatsVM{
		Name: vm.Name, Tenant: vm.Tenant, Role: vm.Role, State: valueOrDefault(strings.TrimSpace(vm.State), "-"),
		QEMUPID: pid, Disk: vm.Disk, CgroupPath: mapping.PrimaryPath, CgroupID: mapping.PrimaryID,
		MappingQuality: valueOrDefault(mapping.MappingQuality, "unavailable"),
		Caveats:        []string{},
	}
	result.CgroupIOStat = collector.buildCgroupEvidence(vm.Name, baseline, after, hostDevices)
	result.VirshDomstats = buildVirshEvidence(vm.Name, baseline, after)
	result.QEMUPressure = buildQEMUEvidence(baseline, after)

	if mapping.MappingQuality != "cgroup_v2_inode_tree" {
		result.Caveats = append(result.Caveats, "VM cgroup mapping is unavailable or partial: "+valueOrDefault(mapping.MappingQuality, "unavailable"))
		report.UnavailableSections = append(report.UnavailableSections, UnavailableSection{
			VM: vm.Name, Section: "cgroup_mapping", Status: mappingSectionStatus(mapping.MappingQuality), Error: "mapping quality: " + valueOrDefault(mapping.MappingQuality, "unavailable"),
		})
	}
	available := 0
	partial := false
	for _, section := range []struct {
		name      string
		available bool
		quality   string
		err       string
	}{
		{name: "cgroup_io_stat", available: result.CgroupIOStat.Available, quality: result.CgroupIOStat.Quality, err: result.CgroupIOStat.Error},
		{name: "virsh_domstats", available: result.VirshDomstats.Available, quality: result.VirshDomstats.Quality, err: result.VirshDomstats.Error},
		{name: "qemu_pressure", available: result.QEMUPressure.Available, quality: result.QEMUPressure.Quality, err: result.QEMUPressure.Error},
	} {
		if section.available {
			available++
			partial = partial || section.quality != "measured"
			continue
		}
		partial = true
		report.UnavailableSections = append(report.UnavailableSections, UnavailableSection{
			VM: vm.Name, Section: section.name, Status: valueOrDefault(section.quality, "unavailable"), Error: section.err,
		})
	}
	switch {
	case available == 0:
		result.EvidenceQuality = "unavailable"
	case available < 3 || partial:
		result.EvidenceQuality = "partial"
	default:
		result.EvidenceQuality = "measured"
	}
	return result
}

// buildCgroupEvidence builds cgroup evidence from validated inputs.
func (collector *Collector) buildCgroupEvidence(vm string, baseline, after sourceSample, hostDevices map[string]HostDevice) CgroupIOStatEvidence {
	evidence := CgroupIOStatEvidence{
		Quality: "unavailable", SourceCgroupPath: baseline.cgroupPath, SourceCgroupKind: baseline.cgroupKind,
		SourceCgroupInodeBefore: baseline.cgroupInode, SourceCgroupInodeAfter: after.cgroupInode,
		Devices: []CgroupIODeviceDelta{}, MissingBaselineDevices: []string{}, MissingAfterDevices: []string{},
		CounterResetDevices: []string{}, DuplicateDevices: []string{},
		Caveats: []string{"cgroup io.stat provides byte and operation counters, not latency", "stacked device rows are kept separate"},
	}
	if baseline.cgroupErr != nil {
		evidence.Error = "baseline: " + baseline.cgroupErr.Error()
		return evidence
	}
	if after.cgroupErr != nil {
		evidence.Error = "after: " + after.cgroupErr.Error()
		return evidence
	}
	if baseline.cgroupInode == 0 || after.cgroupInode == 0 {
		evidence.Error = "cgroup source inode unavailable"
		return evidence
	}
	if baseline.cgroupInode != after.cgroupInode {
		evidence.Quality = "source_replaced"
		evidence.Error = "cgroup source changed during sampling window"
		evidence.Caveats = append(evidence.Caveats, "cgroup source changed during sampling window; counters were not compared")
		return evidence
	}
	beforeRows, err := ebpf.ParseCgroupIOStat(string(baseline.cgroupData))
	if err != nil {
		evidence.DuplicateDevices = duplicateCgroupDeviceIDs(string(baseline.cgroupData))
		evidence.Error = "parse baseline io.stat: " + err.Error()
		return evidence
	}
	afterRows, err := ebpf.ParseCgroupIOStat(string(after.cgroupData))
	if err != nil {
		evidence.DuplicateDevices = duplicateCgroupDeviceIDs(string(after.cgroupData))
		evidence.Error = "parse after io.stat: " + err.Error()
		return evidence
	}
	deltas, err := ebpf.DeltaCgroupIOStat(vm, baseline.cgroupPath, beforeRows, afterRows)
	if err != nil {
		evidence.Error = err.Error()
		return evidence
	}
	evidence.Available = true
	evidence.Quality = "measured"
	if baseline.cgroupKind == "emulator" {
		evidence.Quality = "partial"
		evidence.Caveats = append(evidence.Caveats, "emulator cgroup fallback is narrower than aggregate VM accounting")
	}
	for _, delta := range deltas {
		device := collector.devices.Resolve(delta.Device)
		hostDevices[device.DeviceID] = device
		row := CgroupIODeviceDelta{
			DeviceID: delta.Device, DeviceName: device.DeviceName, Status: delta.Status, CounterReset: delta.CounterReset,
			ReadBytesDelta: delta.ReadBytes, WriteBytesDelta: delta.WriteBytes,
			ReadIOsDelta: delta.ReadOps, WriteIOsDelta: delta.WriteOps,
			DiscardBytesDelta: delta.DiscardBytes, DiscardIOsDelta: delta.DiscardOps,
			DBytesDelta: delta.DiscardBytes, DIOsDelta: delta.DiscardOps,
			DiscardBytesAvailable: delta.DiscardBytesAvailable, DiscardIOsAvailable: delta.DiscardOpsAvailable,
			SourcePath: device.SourcePath, LayerKind: valueOrDefault(device.LayerKind, "unknown"), Caveats: []string{},
		}
		switch delta.Status {
		case "baseline_missing":
			evidence.Quality = "partial"
			evidence.MissingBaselineDevices = append(evidence.MissingBaselineDevices, delta.Device)
			row.Caveats = append(row.Caveats, "baseline missing; cumulative after counters are not reported as window activity")
		case "missing_after":
			evidence.Quality = "partial"
			evidence.MissingAfterDevices = append(evidence.MissingAfterDevices, delta.Device)
			row.Caveats = append(row.Caveats, "after sample missing; no window delta is available")
		case "counter_reset":
			evidence.Quality = "partial"
			evidence.CounterResetDevices = append(evidence.CounterResetDevices, delta.Device)
			row.Caveats = append(row.Caveats, "one or more counters decreased; this row is not counted as window activity")
		}
		evidence.Devices = append(evidence.Devices, row)
	}
	return evidence
}

// buildVirshEvidence builds virsh evidence from validated inputs.
func buildVirshEvidence(vm string, baseline, after sourceSample) VirshDomstatsEvidence {
	evidence := VirshDomstatsEvidence{
		Quality: "unavailable", Disks: []VirshVirtualDiskDelta{},
		Caveats: []string{"virsh domstats provides virtual-disk counters and cumulative timing, not host physical latency"},
	}
	if baseline.virshErr != nil {
		evidence.Error = "baseline: " + baseline.virshErr.Error()
		return evidence
	}
	if after.virshErr != nil {
		evidence.Error = "after: " + after.virshErr.Error()
		return evidence
	}
	beforeRows, err := ebpf.ParseVirshDomstatsBlock(string(baseline.virshData))
	if err != nil {
		evidence.Error = "parse baseline domstats: " + err.Error()
		return evidence
	}
	afterRows, err := ebpf.ParseVirshDomstatsBlock(string(after.virshData))
	if err != nil {
		evidence.Error = "parse after domstats: " + err.Error()
		return evidence
	}
	deltas, err := ebpf.DeltaVirshBlockStats(vm, beforeRows, afterRows)
	if err != nil {
		evidence.Error = err.Error()
		return evidence
	}
	evidence.Available = true
	evidence.Quality = "measured"
	for _, delta := range deltas {
		row := VirshVirtualDiskDelta{
			Target: delta.Block, Status: delta.Status, CounterReset: delta.CounterReset,
			ReadReqsDelta: delta.ReadOps, ReadBytesDelta: delta.ReadBytes, ReadTimeNSDelta: delta.ReadTimeNS,
			WriteReqsDelta: delta.WriteOps, WriteBytesDelta: delta.WriteBytes, WriteTimeNSDelta: delta.WriteTimeNS,
			FlushReqsDelta: delta.FlushOps, FlushTimeNSDelta: delta.FlushTimeNS, Caveats: []string{},
		}
		if delta.ReadOps > 0 {
			row.AverageReadTimeMS = float64(delta.ReadTimeNS) / float64(delta.ReadOps) / 1_000_000
		}
		if delta.WriteOps > 0 {
			row.AverageWriteTimeMS = float64(delta.WriteTimeNS) / float64(delta.WriteOps) / 1_000_000
		}
		if delta.Status != "ok" {
			evidence.Quality = "partial"
			row.Caveats = append(row.Caveats, deltaStatusCaveat(delta.Status))
		}
		evidence.Disks = append(evidence.Disks, row)
	}
	return evidence
}

// buildQEMUEvidence builds qemu evidence from validated inputs.
func buildQEMUEvidence(baseline, after sourceSample) QEMUPressureEvidence {
	evidence := QEMUPressureEvidence{
		Quality: "unavailable",
		Caveats: []string{"QEMU pressure is process-accounting correlation only and is not block latency"},
	}
	if baseline.qemuErr != nil {
		evidence.Error = "baseline: " + baseline.qemuErr.Error()
		return evidence
	}
	if after.qemuErr != nil {
		evidence.Error = "after: " + after.qemuErr.Error()
		return evidence
	}
	readBytes, readReset := safeCounterDelta(baseline.qemuData.ReadBytes, after.qemuData.ReadBytes)
	writeBytes, writeReset := safeCounterDelta(baseline.qemuData.WriteBytes, after.qemuData.WriteBytes)
	syscr, syscrReset := safeCounterDelta(baseline.qemuData.Syscr, after.qemuData.Syscr)
	syscw, syscwReset := safeCounterDelta(baseline.qemuData.Syscw, after.qemuData.Syscw)
	if readReset || writeReset || syscrReset || syscwReset {
		evidence.Quality = "counter_reset"
		fields := []string{}
		if readReset {
			fields = append(fields, "read_bytes")
		}
		if writeReset {
			fields = append(fields, "write_bytes")
		}
		if syscrReset {
			fields = append(fields, "syscr")
		}
		if syscwReset {
			fields = append(fields, "syscw")
		}
		evidence.Error = strings.Join(fields, ", ") + " counter decreased"
		return evidence
	}
	evidence.ReadBytesDelta = readBytes
	evidence.WriteBytesDelta = writeBytes
	evidence.SyscrDelta = syscr
	evidence.SyscwDelta = syscw
	evidence.Available = true
	evidence.Quality = "measured"
	return evidence
}

type cgroupCandidate struct {
	Path string
	Kind string
}

// preferredCgroupCandidates builds preferred cgroup candidates from validated inputs.
func preferredCgroupCandidates(mapping ebpf.VMBlockCgroupMapping) []cgroupCandidate {
	seen := make(map[string]bool)
	candidates := []cgroupCandidate{}
	for _, path := range mapping.CgroupPaths {
		kind := cgroupPathKind(path)
		if kind == "" || seen[path] {
			continue
		}
		seen[path] = true
		candidates = append(candidates, cgroupCandidate{Path: path, Kind: kind})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := cgroupKindPriority(candidates[i].Kind), cgroupKindPriority(candidates[j].Kind)
		if left != right {
			return left < right
		}
		return candidates[i].Path < candidates[j].Path
	})
	return candidates
}

// cgroupPathKind derives stable operator-facing text for cgroup path kind.
func cgroupPathKind(path string) string {
	cleaned := filepath.Clean(path)
	parts := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
	scopeIndex := -1
	for index, part := range parts {
		middle := strings.TrimSuffix(strings.TrimPrefix(part, "machine-qemu"), ".scope")
		if index > 0 && parts[index-1] == "machine.slice" && strings.HasPrefix(part, "machine-qemu") && strings.HasSuffix(part, ".scope") && middle != "" {
			scopeIndex = index
			break
		}
	}
	if scopeIndex < 0 {
		return ""
	}
	remainder := parts[scopeIndex+1:]
	switch {
	case len(remainder) == 0:
		return "machine_scope"
	case len(remainder) == 1 && remainder[0] == "libvirt":
		return "domain_scope"
	case len(remainder) == 2 && remainder[0] == "libvirt" && remainder[1] == "emulator":
		return "emulator"
	default:
		return ""
	}
}

// cgroupKindPriority builds cgroup kind priority from validated inputs.
func cgroupKindPriority(kind string) int {
	switch kind {
	case "machine_scope":
		return 0
	case "domain_scope":
		return 1
	case "emulator":
		return 2
	default:
		return 99
	}
}

// rootedPath builds rooted path and returns an error when validation or source access fails.
func rootedPath(root, cgroupPath, leaf string) (string, error) {
	if !strings.HasPrefix(cgroupPath, "/") {
		return "", fmt.Errorf("invalid cgroup path %q", cgroupPath)
	}
	cleaned := filepath.Clean(cgroupPath)
	if cleaned == "/" || hasParentComponent(cgroupPath) {
		return "", fmt.Errorf("unsafe cgroup path %q", cgroupPath)
	}
	root = filepath.Clean(root)
	joined := filepath.Join(root, strings.TrimPrefix(cleaned, "/"), leaf)
	relative, err := filepath.Rel(root, joined)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("cgroup path %q escapes root", cgroupPath)
	}
	return joined, nil
}

// hasParentComponent reports whether the value has parent component.
func hasParentComponent(path string) bool {
	for _, component := range strings.Split(path, "/") {
		if component == ".." {
			return true
		}
	}
	return false
}

// indexMappings indexes mappings by its stable identity.
func indexMappings(mappings []ebpf.VMBlockCgroupMapping) map[string]ebpf.VMBlockCgroupMapping {
	result := make(map[string]ebpf.VMBlockCgroupMapping, len(mappings))
	for _, mapping := range mappings {
		result[mapping.Name] = mapping
	}
	return result
}

// duplicateCgroupDeviceIDs returns sorted duplicate cgroup/device identities without losing
// collision evidence.
func duplicateCgroupDeviceIDs(data string) []string {
	seen := make(map[string]bool)
	duplicates := []string{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		device := fields[0]
		if seen[device] {
			duplicates = append(duplicates, device)
		}
		seen[device] = true
	}
	return sortedUnique(duplicates)
}

// safeCounterDelta builds safe counter delta from validated inputs.
func safeCounterDelta(before, after uint64) (uint64, bool) {
	if after < before {
		return 0, true
	}
	return after - before, false
}

// deltaStatusCaveat derives stable operator-facing text for delta status caveat.
func deltaStatusCaveat(status string) string {
	switch status {
	case "baseline_missing":
		return "baseline missing; cumulative after counters are not reported as window activity"
	case "missing_after":
		return "after sample missing; no window delta is available"
	case "counter_reset":
		return "one or more counters decreased; this row is not counted as window activity"
	default:
		return "counter delta is partial"
	}
}

// mappingSectionStatus maps mapping section status into its corresponding evidence identity.
func mappingSectionStatus(quality string) string {
	if quality == "cgroup_v2_inode_partial" {
		return "partial"
	}
	return "unavailable"
}

// isRunning reports whether running.
func isRunning(state string) bool { return strings.EqualFold(strings.TrimSpace(state), "running") }

// isKnownStopped reports whether known stopped.
func isKnownStopped(state string) bool {
	state = strings.ToLower(strings.Join(strings.Fields(state), " "))
	return state == "shut off" || state == "shutoff"
}

// valueOrDefault returns the trimmed value or the supplied fallback when it is empty.
func valueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}
