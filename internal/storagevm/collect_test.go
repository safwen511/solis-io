package storagevm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
)

type sequenceFileReader struct {
	values      map[string][][]byte
	calls       map[string]int
	inodes      map[string][]uint64
	inodeErrors map[string][]error
	inodeCalls  map[string]int
}

// ReadFile reads file from its configured source.
func (reader *sequenceFileReader) ReadFile(path string) ([]byte, error) {
	if reader.calls == nil {
		reader.calls = make(map[string]int)
	}
	values := reader.values[path]
	index := reader.calls[path]
	reader.calls[path]++
	if index >= len(values) {
		return nil, fmt.Errorf("no fake file sample for %s", path)
	}
	return values[index], nil
}

// Inode returns the filesystem inode used as the stable cgroup identity.
func (reader *sequenceFileReader) Inode(path string) (uint64, error) {
	if reader.inodeCalls == nil {
		reader.inodeCalls = make(map[string]int)
	}
	index := reader.inodeCalls[path]
	reader.inodeCalls[path]++
	if index < len(reader.inodeErrors[path]) && reader.inodeErrors[path][index] != nil {
		return 0, reader.inodeErrors[path][index]
	}
	if values, configured := reader.inodes[path]; configured {
		if index >= len(values) {
			return 0, fmt.Errorf("no fake inode sample for %s", path)
		}
		return values[index], nil
	}
	return 1, nil
}

type sequenceVirshSource struct {
	values map[string][][]byte
	errors map[string][]error
	calls  map[string]int
}

// ReadBlockStats reads block stats from its configured source.
func (source *sequenceVirshSource) ReadBlockStats(_ context.Context, vm, _ string) ([]byte, error) {
	if source.calls == nil {
		source.calls = make(map[string]int)
	}
	index := source.calls[vm]
	source.calls[vm]++
	if index < len(source.errors[vm]) && source.errors[vm][index] != nil {
		return nil, source.errors[vm][index]
	}
	if index >= len(source.values[vm]) {
		return nil, errors.New("no fake virsh sample")
	}
	return source.values[vm][index], nil
}

type sequenceQEMUSource struct {
	values map[string][]qemuio.Counters
	errors map[string][]error
	calls  map[string]int
}

type sequenceIdentitySource struct {
	values map[string][]ebpf.QEMUProcessIdentity
	errors map[string][]error
	calls  map[string]int
}

// Validate reports whether the receiver satisfies its required invariants.
func (source *sequenceIdentitySource) Validate(mapping ebpf.VMBlockCgroupMapping) (ebpf.QEMUProcessIdentity, error) {
	if source.calls == nil {
		source.calls = make(map[string]int)
	}
	key := mapping.Name
	index := source.calls[key]
	source.calls[key]++
	if index < len(source.errors[key]) && source.errors[key][index] != nil {
		return ebpf.QEMUProcessIdentity{}, source.errors[key][index]
	}
	if values, configured := source.values[key]; configured {
		if index >= len(values) {
			return ebpf.QEMUProcessIdentity{}, errors.New("no fake QEMU identity sample")
		}
		return values[index], nil
	}
	if mapping.QEMUPID <= 0 || mapping.PrimaryPath == "" {
		return ebpf.QEMUProcessIdentity{}, errors.New("unverified QEMU mapping")
	}
	return ebpf.QEMUProcessIdentity{
		PID: mapping.QEMUPID, Name: "qemu-system-x86", CgroupPath: mapping.PrimaryPath,
		MachineScope: machineScopeForTest(mapping.PrimaryPath), StartTimeTicks: 100,
	}, nil
}

// Read reads bounded source data and propagates access failures.
func (source *sequenceQEMUSource) Read(pid string) (qemuio.Counters, error) {
	if source.calls == nil {
		source.calls = make(map[string]int)
	}
	index := source.calls[pid]
	source.calls[pid]++
	if index < len(source.errors[pid]) && source.errors[pid][index] != nil {
		return qemuio.Counters{}, source.errors[pid][index]
	}
	if index >= len(source.values[pid]) {
		return qemuio.Counters{}, errors.New("no fake QEMU sample")
	}
	return source.values[pid][index], nil
}

type noWaiter struct{}

// Wait completes wait and returns any failure to its caller.
func (noWaiter) Wait(context.Context, time.Duration, time.Duration) error { return nil }

type fakeDeviceResolver map[string]HostDevice

// Resolve resolves source identities from validated inputs and reports unsupported layouts.
func (resolver fakeDeviceResolver) Resolve(id string) HostDevice {
	if device, ok := resolver[id]; ok {
		return device
	}
	return HostDevice{DeviceID: id, LayerKind: "unknown"}
}

// TestCollectorCollectsRealValidationDeltas verifies collector collects real validation deltas.
func TestCollectorCollectsRealValidationDeltas(t *testing.T) {
	scope := `/machine.slice/machine-qemu\x2d3\x2da\x2dweb.scope`
	ioPath := "/fake-cgroup" + scope + "/io.stat"
	files := &sequenceFileReader{values: map[string][][]byte{
		ioPath: {
			[]byte("252:0 rbytes=100 wbytes=200 rios=2 wios=3 dbytes=10 dios=1\n259:0 rbytes=1000 wbytes=2000 rios=20 wios=30\n"),
			[]byte("252:0 rbytes=150 wbytes=260 rios=4 wios=6 dbytes=30 dios=3\n259:0 rbytes=1200 wbytes=2400 rios=24 wios=38\n"),
		},
	}}
	virsh := &sequenceVirshSource{values: map[string][][]byte{"a-web": {
		[]byte(domstats("vda", 10, 100, 1_000_000, 20, 200, 2_000_000, 2, 200_000)),
		[]byte(domstats("vda", 12, 160, 5_000_000, 24, 300, 14_000_000, 3, 700_000)),
	}}}
	qemu := &sequenceQEMUSource{values: map[string][]qemuio.Counters{"123": {
		{ReadBytes: 100, WriteBytes: 200, Syscr: 10, Syscw: 20},
		{ReadBytes: 150, WriteBytes: 500, Syscr: 15, Syscw: 50},
	}}}
	collector := &Collector{
		cgroupRoot: "/fake-cgroup", files: files, virsh: virsh, qemu: qemu, identity: &sequenceIdentitySource{}, waiter: noWaiter{},
		devices: fakeDeviceResolver{
			"252:0": {DeviceID: "252:0", DeviceName: "dm-0", SourcePath: "/dev/dm-0", LayerKind: "lvm"},
			"259:0": {DeviceID: "259:0", DeviceName: "nvme0n1", SourcePath: "/dev/nvme0n1", LayerKind: "physical"},
		},
	}
	report, err := collector.Collect(context.Background(), CollectRequest{
		VMs:      []inventory.VM{{Name: "a-web", Tenant: "tenant-a", Role: "web", State: "running", QEMUPID: "123", Disk: "/images/a-web.qcow2"}},
		Mappings: []ebpf.VMBlockCgroupMapping{{Name: "a-web", QEMUPID: 123, PrimaryPath: scope + "/libvirt/emulator", PrimaryID: 22, CgroupPaths: []string{scope, scope + "/libvirt/emulator"}, CgroupIDs: []uint64{11, 22}, MappingQuality: "cgroup_v2_inode_tree"}},
		Duration: time.Second, Interval: time.Second, ConfigSource: "/etc/solis.json", ObservedAt: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.VMs) != 1 || report.VMs[0].EvidenceQuality != "measured" {
		t.Fatalf("report = %#v", report)
	}
	vm := report.VMs[0]
	if !vm.CgroupIOStat.Available || vm.CgroupIOStat.SourceCgroupPath != scope || len(vm.CgroupIOStat.Devices) != 2 {
		t.Fatalf("cgroup evidence = %#v", vm.CgroupIOStat)
	}
	if vm.CgroupIOStat.Devices[0].DeviceID != "252:0" || vm.CgroupIOStat.Devices[0].WriteBytesDelta != 60 || vm.CgroupIOStat.Devices[0].DiscardBytesDelta != 20 || !vm.CgroupIOStat.Devices[0].DiscardBytesAvailable {
		t.Fatalf("dm delta = %#v", vm.CgroupIOStat.Devices[0])
	}
	if vm.CgroupIOStat.Devices[1].DeviceID != "259:0" || vm.CgroupIOStat.Devices[1].WriteBytesDelta != 400 {
		t.Fatalf("physical delta = %#v", vm.CgroupIOStat.Devices[1])
	}
	if len(report.HostDevices) != 2 || report.HostDevices[0].DeviceID != "252:0" || report.HostDevices[1].DeviceID != "259:0" {
		t.Fatalf("stacked host devices were combined: %#v", report.HostDevices)
	}
	if !vm.VirshDomstats.Available || len(vm.VirshDomstats.Disks) != 1 {
		t.Fatalf("virsh evidence = %#v", vm.VirshDomstats)
	}
	disk := vm.VirshDomstats.Disks[0]
	if disk.ReadReqsDelta != 2 || disk.WriteReqsDelta != 4 || disk.FlushReqsDelta != 1 || disk.AverageReadTimeMS != 2 || disk.AverageWriteTimeMS != 3 {
		t.Fatalf("virtual disk delta = %#v", disk)
	}
	if !vm.QEMUPressure.Available || vm.QEMUPressure.WriteBytesDelta != 300 || vm.QEMUPressure.SyscwDelta != 30 {
		t.Fatalf("QEMU evidence = %#v", vm.QEMUPressure)
	}
	joinedCaveats := strings.ToLower(strings.Join(report.Caveats, " "))
	for _, forbidden := range []string{"per-vm host block latency", "proved customer impact", "definite root cause", "exact physical device latency per vm"} {
		if strings.Contains(joinedCaveats, forbidden) {
			t.Fatalf("forbidden claim %q in %q", forbidden, joinedCaveats)
		}
	}
}

// TestCgroupEvidenceDeltaStates verifies cgroup evidence delta states.
func TestCgroupEvidenceDeltaStates(t *testing.T) {
	collector := &Collector{devices: fakeDeviceResolver{}}
	tests := []struct {
		name             string
		before           string
		after            string
		wantStatus       string
		wantMissingBase  []string
		wantMissingAfter []string
		wantReset        []string
	}{
		{name: "normal", before: "8:0 rbytes=10\n", after: "8:0 rbytes=15\n", wantStatus: "ok"},
		{name: "missing baseline", before: "", after: "8:0 rbytes=999\n", wantStatus: "baseline_missing", wantMissingBase: []string{"8:0"}},
		{name: "missing after", before: "8:0 rbytes=10\n", after: "", wantStatus: "missing_after", wantMissingAfter: []string{"8:0"}},
		{name: "counter reset", before: "8:0 rbytes=10\n", after: "8:0 rbytes=1\n", wantStatus: "counter_reset", wantReset: []string{"8:0"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := collector.buildCgroupEvidence("a-web", sourceSample{cgroupPath: "/scope", cgroupInode: 1, cgroupData: []byte(test.before)}, sourceSample{cgroupPath: "/scope", cgroupInode: 1, cgroupData: []byte(test.after)}, map[string]HostDevice{})
			if !evidence.Available || len(evidence.Devices) != 1 || evidence.Devices[0].Status != test.wantStatus {
				t.Fatalf("evidence = %#v", evidence)
			}
			if !reflect.DeepEqual(evidence.MissingBaselineDevices, test.wantMissingBase) && !(len(evidence.MissingBaselineDevices) == 0 && len(test.wantMissingBase) == 0) {
				t.Fatalf("missing baseline = %#v", evidence.MissingBaselineDevices)
			}
			if !reflect.DeepEqual(evidence.MissingAfterDevices, test.wantMissingAfter) && !(len(evidence.MissingAfterDevices) == 0 && len(test.wantMissingAfter) == 0) {
				t.Fatalf("missing after = %#v", evidence.MissingAfterDevices)
			}
			if !reflect.DeepEqual(evidence.CounterResetDevices, test.wantReset) && !(len(evidence.CounterResetDevices) == 0 && len(test.wantReset) == 0) {
				t.Fatalf("reset = %#v", evidence.CounterResetDevices)
			}
			if test.wantStatus != "ok" && (evidence.Devices[0].ReadBytesDelta != 0 || evidence.Quality != "partial") {
				t.Fatalf("unsafe anomalous delta = %#v", evidence)
			}
		})
	}
}

// TestCgroupEvidenceRejectsDuplicateDevice verifies cgroup evidence rejects duplicate device.
func TestCgroupEvidenceRejectsDuplicateDevice(t *testing.T) {
	collector := &Collector{devices: fakeDeviceResolver{}}
	evidence := collector.buildCgroupEvidence("a-web",
		sourceSample{cgroupPath: "/scope", cgroupInode: 1, cgroupData: []byte("8:0 rbytes=1\n8:0 rbytes=2\n")},
		sourceSample{cgroupPath: "/scope", cgroupInode: 1, cgroupData: []byte("8:0 rbytes=3\n")}, map[string]HostDevice{})
	if evidence.Available || !strings.Contains(evidence.Error, "duplicate") || !reflect.DeepEqual(evidence.DuplicateDevices, []string{"8:0"}) {
		t.Fatalf("evidence = %#v", evidence)
	}
}

// TestVirshEvidenceDeltaStatesAndTiming verifies virsh evidence delta states and timing.
func TestVirshEvidenceDeltaStatesAndTiming(t *testing.T) {
	tests := []struct {
		name       string
		before     string
		after      string
		wantStatus string
	}{
		{name: "normal", before: domstats("vda", 1, 10, 1_000_000, 1, 20, 2_000_000, 0, 0), after: domstats("vda", 3, 30, 5_000_000, 3, 50, 8_000_000, 1, 100), wantStatus: "ok"},
		{name: "missing baseline", before: "", after: domstats("vda", 3, 30, 5_000_000, 3, 50, 8_000_000, 1, 100), wantStatus: "baseline_missing"},
		{name: "missing after", before: domstats("vda", 1, 10, 1_000_000, 1, 20, 2_000_000, 0, 0), after: "", wantStatus: "missing_after"},
		{name: "counter reset", before: domstats("vda", 10, 100, 10, 10, 100, 10, 2, 2), after: domstats("vda", 1, 1, 1, 1, 1, 1, 1, 1), wantStatus: "counter_reset"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := buildVirshEvidence("a-web", sourceSample{virshData: []byte(test.before)}, sourceSample{virshData: []byte(test.after)})
			if !evidence.Available || len(evidence.Disks) != 1 || evidence.Disks[0].Status != test.wantStatus {
				t.Fatalf("evidence = %#v", evidence)
			}
			if test.wantStatus == "ok" && (evidence.Disks[0].AverageReadTimeMS != 2 || evidence.Disks[0].AverageWriteTimeMS != 3) {
				t.Fatalf("timing = %#v", evidence.Disks[0])
			}
			if test.wantStatus != "ok" && evidence.Disks[0].ReadBytesDelta != 0 {
				t.Fatalf("unsafe anomalous delta = %#v", evidence.Disks[0])
			}
		})
	}
}

// TestVirshEvidenceRejectsDuplicateKey verifies virsh evidence rejects duplicate key.
func TestVirshEvidenceRejectsDuplicateKey(t *testing.T) {
	evidence := buildVirshEvidence("a-web", sourceSample{virshData: []byte("block.0.name=vda\nblock.0.rd.bytes=1\nblock.0.rd.bytes=2\n")}, sourceSample{virshData: []byte("block.0.name=vda\n")})
	if evidence.Available || !strings.Contains(evidence.Error, "duplicate") {
		t.Fatalf("evidence = %#v", evidence)
	}
}

// TestQEMUPressureUnavailableIsNonFatal verifies qemu pressure unavailable is non fatal.
func TestQEMUPressureUnavailableIsNonFatal(t *testing.T) {
	scope := `/machine.slice/machine-qemu\x2d3\x2da\x2dweb.scope`
	ioPath := "/fake" + scope + "/io.stat"
	collector := &Collector{
		cgroupRoot: "/fake",
		files:      &sequenceFileReader{values: map[string][][]byte{ioPath: {[]byte("8:0 rbytes=1\n"), []byte("8:0 rbytes=2\n")}}},
		virsh:      &sequenceVirshSource{values: map[string][][]byte{"a-web": {[]byte(domstats("vda", 1, 1, 1, 1, 1, 1, 0, 0)), []byte(domstats("vda", 2, 2, 2, 2, 2, 2, 0, 0))}}},
		qemu:       &sequenceQEMUSource{errors: map[string][]error{"123": {errors.New("permission denied reading /proc/123/io; try running with sudo"), errors.New("permission denied reading /proc/123/io; try running with sudo")}}},
		identity:   &sequenceIdentitySource{},
		waiter:     noWaiter{}, devices: fakeDeviceResolver{},
	}
	report, err := collector.Collect(context.Background(), CollectRequest{
		VMs:      []inventory.VM{{Name: "a-web", State: "running", QEMUPID: "123"}},
		Mappings: []ebpf.VMBlockCgroupMapping{{Name: "a-web", QEMUPID: 123, PrimaryPath: scope, PrimaryID: 10, CgroupPaths: []string{scope}, CgroupIDs: []uint64{10}, MappingQuality: "cgroup_v2_inode_partial"}},
		Duration: time.Second, Interval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.VMs[0].QEMUPressure.Available || !report.VMs[0].CgroupIOStat.Available || !report.VMs[0].VirshDomstats.Available || report.VMs[0].EvidenceQuality != "partial" {
		t.Fatalf("report = %#v", report)
	}
	if !hasUnavailable(report.UnavailableSections, "a-web", "qemu_pressure") {
		t.Fatalf("unavailable sections = %#v", report.UnavailableSections)
	}
}

// TestQEMUPressureRequiresVerifiedPIDIdentity verifies qemu pressure requires verified pid
// identity.
func TestQEMUPressureRequiresVerifiedPIDIdentity(t *testing.T) {
	scope := `/machine.slice/machine-qemu\x2d3\x2da\x2dweb.scope`
	mapping := ebpf.VMBlockCgroupMapping{
		Name: "a-web", QEMUPID: 123, PrimaryPath: scope, CgroupPaths: []string{scope},
		MappingQuality: "cgroup_v2_inode_partial",
	}
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "stale PID", err: errors.New("read QEMU process identity: process does not exist")},
		{name: "reused PID with non-QEMU process", err: errors.New("PID 123 is not a QEMU process")},
		{name: "QEMU outside libvirt cgroup", err: errors.New("QEMU process is not in a libvirt machine scope")},
	} {
		t.Run(test.name, func(t *testing.T) {
			qemu := &sequenceQEMUSource{}
			collector := &Collector{
				cgroupRoot: "/fake", files: &sequenceFileReader{},
				virsh: &sequenceVirshSource{}, qemu: qemu,
				identity: &sequenceIdentitySource{errors: map[string][]error{"a-web": {test.err}}},
			}
			sample := collector.sampleBaseline(context.Background(), inventory.VM{Name: "a-web", State: "running", QEMUPID: "123"}, mapping, "")
			if sample.qemuErr == nil || !strings.Contains(sample.qemuErr.Error(), test.err.Error()) {
				t.Fatalf("qemu error = %v", sample.qemuErr)
			}
			if len(qemu.calls) != 0 {
				t.Fatalf("unvalidated PID was sampled: %#v", qemu.calls)
			}
		})
	}
}

// TestQEMUPressureRevalidatesIdentityAtAfterSample verifies qemu pressure revalidates identity at
// after sample.
func TestQEMUPressureRevalidatesIdentityAtAfterSample(t *testing.T) {
	scope := `/machine.slice/machine-qemu\x2d3\x2da\x2dweb.scope`
	mapping := ebpf.VMBlockCgroupMapping{
		Name: "a-web", QEMUPID: 123, PrimaryPath: scope, CgroupPaths: []string{scope},
		MappingQuality: "cgroup_v2_inode_partial",
	}
	identity := ebpf.QEMUProcessIdentity{PID: 123, Name: "qemu-system-x86", CgroupPath: scope, MachineScope: scope, StartTimeTicks: 100}
	files := &sequenceFileReader{values: map[string][][]byte{"/fake" + scope + "/io.stat": {[]byte("8:0 rbytes=1\n"), []byte("8:0 rbytes=2\n")}}}
	qemu := &sequenceQEMUSource{values: map[string][]qemuio.Counters{"123": {{ReadBytes: 1}}}}
	identities := &sequenceIdentitySource{
		values: map[string][]ebpf.QEMUProcessIdentity{"a-web": {identity}},
		errors: map[string][]error{"a-web": {nil, errors.New("PID identity changed")}},
	}
	collector := &Collector{cgroupRoot: "/fake", files: files, virsh: &sequenceVirshSource{}, qemu: qemu, identity: identities}
	baseline := collector.sampleBaseline(context.Background(), inventory.VM{Name: "a-web", State: "running", QEMUPID: "123"}, mapping, "")
	after := collector.sampleAfter(context.Background(), inventory.VM{Name: "a-web", State: "running", QEMUPID: "123"}, mapping, baseline, "")
	if baseline.qemuErr != nil || after.qemuErr == nil || !strings.Contains(after.qemuErr.Error(), "identity changed") {
		t.Fatalf("baseline error = %v, after error = %v", baseline.qemuErr, after.qemuErr)
	}
	if qemu.calls["123"] != 1 {
		t.Fatalf("after-sample read used invalid PID: calls = %#v", qemu.calls)
	}
	if evidence := buildQEMUEvidence(baseline, after); evidence.Available || evidence.ReadBytesDelta != 0 {
		t.Fatalf("invalid after identity produced pressure: %#v", evidence)
	}
}

// TestCgroupIdentityContinuity verifies cgroup identity continuity.
func TestCgroupIdentityContinuity(t *testing.T) {
	collector := &Collector{devices: fakeDeviceResolver{}}
	before := sourceSample{cgroupPath: "/scope", cgroupKind: "machine_scope", cgroupInode: 10, cgroupData: []byte("8:0 rbytes=10 wbytes=20\n")}
	t.Run("same inode allows delta", func(t *testing.T) {
		after := sourceSample{cgroupPath: "/scope", cgroupKind: "machine_scope", cgroupInode: 10, cgroupData: []byte("8:0 rbytes=15 wbytes=30\n")}
		evidence := collector.buildCgroupEvidence("a-web", before, after, map[string]HostDevice{})
		if !evidence.Available || evidence.Devices[0].ReadBytesDelta != 5 || evidence.SourceCgroupInodeBefore != 10 || evidence.SourceCgroupInodeAfter != 10 {
			t.Fatalf("evidence = %#v", evidence)
		}
	})
	t.Run("replacement inode rejects larger counters", func(t *testing.T) {
		after := sourceSample{cgroupPath: "/scope", cgroupKind: "machine_scope", cgroupInode: 20, cgroupData: []byte("8:0 rbytes=9999 wbytes=9999\n")}
		evidence := collector.buildCgroupEvidence("a-web", before, after, map[string]HostDevice{})
		if evidence.Available || evidence.Quality != "source_replaced" || len(evidence.Devices) != 0 || !strings.Contains(evidence.Error, "changed during sampling window") {
			t.Fatalf("replacement was treated as activity: %#v", evidence)
		}
	})
	t.Run("disappeared cgroup unavailable", func(t *testing.T) {
		after := sourceSample{cgroupPath: "/scope", cgroupErr: errors.New("no such file or directory")}
		evidence := collector.buildCgroupEvidence("a-web", before, after, map[string]HostDevice{})
		if evidence.Available || !strings.Contains(evidence.Error, "after:") {
			t.Fatalf("disappeared source = %#v", evidence)
		}
	})
}

// TestQEMUPressureCounterResetPublishesNoPartialDeltas verifies qemu pressure counter reset
// publishes no partial deltas.
func TestQEMUPressureCounterResetPublishesNoPartialDeltas(t *testing.T) {
	baseline := qemuio.Counters{ReadBytes: 100, WriteBytes: 200, Syscr: 300, Syscw: 400}
	for _, test := range []struct {
		name  string
		after qemuio.Counters
	}{
		{name: "normal", after: qemuio.Counters{ReadBytes: 110, WriteBytes: 220, Syscr: 330, Syscw: 440}},
		{name: "read reset", after: qemuio.Counters{ReadBytes: 1, WriteBytes: 220, Syscr: 330, Syscw: 440}},
		{name: "write reset", after: qemuio.Counters{ReadBytes: 110, WriteBytes: 1, Syscr: 330, Syscw: 440}},
		{name: "syscr reset", after: qemuio.Counters{ReadBytes: 110, WriteBytes: 220, Syscr: 1, Syscw: 440}},
		{name: "syscw reset", after: qemuio.Counters{ReadBytes: 110, WriteBytes: 220, Syscr: 330, Syscw: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := buildQEMUEvidence(sourceSample{qemuData: baseline}, sourceSample{qemuData: test.after})
			if test.name == "normal" {
				if !evidence.Available || evidence.ReadBytesDelta != 10 || evidence.WriteBytesDelta != 20 || evidence.SyscrDelta != 30 || evidence.SyscwDelta != 40 {
					t.Fatalf("normal delta = %#v", evidence)
				}
				return
			}
			if evidence.Available || evidence.Quality != "counter_reset" || evidence.ReadBytesDelta != 0 || evidence.WriteBytesDelta != 0 || evidence.SyscrDelta != 0 || evidence.SyscwDelta != 0 {
				t.Fatalf("reset published partial deltas: %#v", evidence)
			}
		})
	}
}

// TestCgroupCandidateScopeSelection verifies cgroup candidate scope selection.
func TestCgroupCandidateScopeSelection(t *testing.T) {
	scope := `/machine.slice/machine-qemu\x2d3\x2da\x2dweb.scope`
	mapping := ebpf.VMBlockCgroupMapping{CgroupPaths: []string{
		scope + "/libvirt/vcpu0", scope + "/libvirt/emulator", scope + "/libvirt", scope, scope + "/other",
	}}
	candidates := preferredCgroupCandidates(mapping)
	want := []cgroupCandidate{{Path: scope, Kind: "machine_scope"}, {Path: scope + "/libvirt", Kind: "domain_scope"}, {Path: scope + "/libvirt/emulator", Kind: "emulator"}}
	if !reflect.DeepEqual(candidates, want) {
		t.Fatalf("candidates = %#v, want %#v", candidates, want)
	}
	if candidates := preferredCgroupCandidates(ebpf.VMBlockCgroupMapping{CgroupPaths: []string{scope + "/libvirt/vcpu0", scope + "/other"}}); len(candidates) != 0 {
		t.Fatalf("arbitrary child accepted as aggregate: %#v", candidates)
	}
	collector := &Collector{cgroupRoot: "/fake", files: &sequenceFileReader{}}
	if _, _, _, _, err := collector.readPreferredIOStat(ebpf.VMBlockCgroupMapping{CgroupPaths: []string{scope + "/libvirt/vcpu0"}}); err == nil || !strings.Contains(err.Error(), "no aggregate VM or emulator") {
		t.Fatalf("only-vCPU fallback error = %v", err)
	}
}

// TestEmulatorCgroupFallbackIsPartial verifies emulator cgroup fallback is partial.
func TestEmulatorCgroupFallbackIsPartial(t *testing.T) {
	scope := `/machine.slice/machine-qemu\x2d3\x2da\x2dweb.scope`
	emulator := scope + "/libvirt/emulator"
	evidence := (&Collector{devices: fakeDeviceResolver{}}).buildCgroupEvidence("a-web",
		sourceSample{cgroupPath: emulator, cgroupKind: "emulator", cgroupInode: 10, cgroupData: []byte("8:0 rbytes=1\n")},
		sourceSample{cgroupPath: emulator, cgroupKind: "emulator", cgroupInode: 10, cgroupData: []byte("8:0 rbytes=2\n")}, map[string]HostDevice{})
	if !evidence.Available || evidence.Quality != "partial" || !strings.Contains(strings.Join(evidence.Caveats, " "), "narrower") {
		t.Fatalf("emulator fallback = %#v", evidence)
	}
}

// TestStoppedVMIsReportedUnavailableWithoutSourceReads verifies stopped vm is reported unavailable
// without source reads.
func TestStoppedVMIsReportedUnavailableWithoutSourceReads(t *testing.T) {
	collector := &Collector{
		files: &sequenceFileReader{}, virsh: &sequenceVirshSource{}, qemu: &sequenceQEMUSource{},
		waiter: noWaiter{}, devices: fakeDeviceResolver{},
	}
	report, err := collector.Collect(context.Background(), CollectRequest{
		VMs:      []inventory.VM{{Name: "a-db", State: "shut off"}},
		Mappings: []ebpf.VMBlockCgroupMapping{{Name: "a-db", MappingQuality: "missing_qemu_pid"}},
		Duration: time.Second, Interval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.VMs) != 1 || report.VMs[0].EvidenceQuality != "unavailable" || report.VMs[0].CgroupIOStat.Available || report.VMs[0].VirshDomstats.Available || report.VMs[0].QEMUPressure.Available {
		t.Fatalf("stopped VM report = %#v", report)
	}
}

// TestDeterministicPrivacySafeJSON verifies deterministic privacy safe json.
func TestDeterministicPrivacySafeJSON(t *testing.T) {
	report := VMStorageStatsReport{
		SchemaVersion: SchemaVersion, ObservedAtUTC: "2026-08-09T12:00:00Z", Duration: "1s", Interval: "1s",
		ConfigSource: "/etc/solis.json",
		VMs: []VMStorageStatsVM{
			{
				Name: "b", Tenant: "tenant-b", Role: "stress", MappingQuality: "cgroup_v2_inode_partial", EvidenceQuality: "partial",
				CgroupIOStat: CgroupIOStatEvidence{
					Available: true, Quality: "partial", SourceCgroupPath: "/machine/b/libvirt/emulator", SourceCgroupKind: "emulator",
					SourceCgroupInodeBefore: 22, SourceCgroupInodeAfter: 22,
					Devices:             []CgroupIODeviceDelta{{DeviceID: "8:1", Status: "counter_reset", Caveats: []string{"counter reset"}}},
					CounterResetDevices: []string{"8:1"}, Caveats: []string{"emulator fallback"},
				},
				VirshDomstats: VirshDomstatsEvidence{Available: true, Quality: "partial", Disks: []VirshVirtualDiskDelta{{Target: "vda", Status: "missing_after", Caveats: []string{"missing"}}}, Caveats: []string{"virtual timing"}},
				QEMUPressure:  QEMUPressureEvidence{Available: false, Quality: "unavailable", Error: "permission denied", Caveats: []string{"process accounting"}},
				Caveats:       []string{"partial mapping"},
			},
			{Name: "a", CgroupIOStat: CgroupIOStatEvidence{MissingBaselineDevices: []string{"8:3", "8:2"}}},
		},
		HostDevices:         []HostDevice{{DeviceID: "8:1"}, {DeviceID: "8:0"}},
		Caveats:             []string{"validation counters only"},
		UnavailableSections: []UnavailableSection{{VM: "b", Section: "qemu_pressure", Status: "unavailable", Error: "permission denied"}},
	}
	var first, second bytes.Buffer
	if err := WriteJSON(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&second, report); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("JSON differs:\n%s\n%s", first.String(), second.String())
	}
	var decoded VMStorageStatsReport
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.VMs[0].Name != "a" || decoded.HostDevices[0].DeviceID != "8:0" || decoded.VMs[1].CgroupIOStat.SourceCgroupInodeBefore != 22 || len(decoded.UnavailableSections) != 1 || privacyCollected(decoded) {
		t.Fatalf("decoded = %#v", decoded)
	}
	report.Privacy.SecretsCollected = true
	if err := WriteJSON(&bytes.Buffer{}, report); err == nil {
		t.Fatal("expected privacy rejection")
	}
}

// domstats derives stable operator-facing text for domstats.
func domstats(target string, rdReqs, rdBytes, rdTimes, wrReqs, wrBytes, wrTimes, flReqs, flTimes uint64) string {
	return fmt.Sprintf("block.0.name=%s\nblock.0.rd.reqs=%d\nblock.0.rd.bytes=%d\nblock.0.rd.times=%d\nblock.0.wr.reqs=%d\nblock.0.wr.bytes=%d\nblock.0.wr.times=%d\nblock.0.fl.reqs=%d\nblock.0.fl.times=%d\n", target, rdReqs, rdBytes, rdTimes, wrReqs, wrBytes, wrTimes, flReqs, flTimes)
}

// hasUnavailable reports whether the value has unavailable.
func hasUnavailable(sections []UnavailableSection, vm, section string) bool {
	for _, candidate := range sections {
		if candidate.VM == vm && candidate.Section == section {
			return true
		}
	}
	return false
}

// machineScopeForTest derives stable operator-facing text for machine scope for test.
func machineScopeForTest(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		if index > 0 && parts[index-1] == "machine.slice" && strings.HasPrefix(part, "machine-qemu") && strings.HasSuffix(part, ".scope") {
			return "/" + strings.Join(parts[:index+1], "/")
		}
	}
	return ""
}
