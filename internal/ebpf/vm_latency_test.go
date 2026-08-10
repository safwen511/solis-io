package ebpf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/inventory"
)

func TestVMBlockEventJSONNeverExposesRequestPointer(t *testing.T) {
	data, err := json.Marshal(VMBlockEvent{
		Kind: "issue", RequestPointer: 0xfeedbeef, TimestampNS: 1, CgroupID: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "RequestPointer") || strings.Contains(string(data), "request_pointer") || strings.Contains(string(data), "4276993775") {
		t.Fatalf("raw request pointer leaked into event JSON: %s", data)
	}
}

type fakeVMBlockEventSource struct {
	events []VMBlockEvent
	err    error
}

func (source fakeVMBlockEventSource) Collect(_ context.Context, _ time.Duration, consume func(VMBlockEvent) error) error {
	for _, event := range source.events {
		if err := consume(event); err != nil {
			return err
		}
	}
	return source.err
}

func TestVMBlockLatencyFakeEventAggregation(t *testing.T) {
	mappings := []VMBlockCgroupMapping{
		{Name: "a-web", Tenant: "tenant-a", Role: "web", QEMUPID: 101, Disk: "/images/a-web.qcow2", PrimaryPath: "/machine/a/libvirt/emulator", PrimaryID: 11, CgroupIDs: []uint64{10, 11}, MappingQuality: "cgroup_v2_inode_tree"},
		{Name: "b-stress", Tenant: "tenant-b", Role: "stress", QEMUPID: 202, Disk: "/images/b-stress.qcow2", PrimaryPath: "/machine/b/libvirt/emulator", PrimaryID: 21, CgroupIDs: []uint64{20, 21}, MappingQuality: "cgroup_v2_inode_tree"},
	}
	events := []VMBlockEvent{
		{Kind: "issue", RequestPointer: 1, TimestampNS: 1_000_000, CgroupID: 11, Device: "dm-0", Operation: "read"},
		{Kind: "complete", RequestPointer: 1, TimestampNS: 2_000_000, Device: "dm-0"},
		{Kind: "issue", RequestPointer: 2, TimestampNS: 1_000_000, CgroupID: 21, Device: "nvme0n1", Operation: "write"},
		{Kind: "complete", RequestPointer: 2, TimestampNS: 5_000_000, Device: "nvme0n1"},
		{Kind: "issue", RequestPointer: 3, TimestampNS: 1_000_000, CgroupID: 21, Device: "nvme0n1", Operation: "write"},
		{Kind: "complete", RequestPointer: 3, TimestampNS: 3_000_000, Device: "nvme0n1"},
	}
	report := CollectVMBlockLatencyReportWithSource(context.Background(), VMBlockLatencyCollectOptions{
		Duration: 5 * time.Second, Interval: time.Second, ObservedAt: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
	}, mappings, fakeVMBlockEventSource{events: events})
	if !report.Availability.Available || report.AttributionQuality != "experimental_blkcg_correlated" {
		t.Fatalf("availability = %#v, quality = %q", report.Availability, report.AttributionQuality)
	}
	if len(report.VMs) != 2 {
		t.Fatalf("VM count = %d", len(report.VMs))
	}
	if report.VMs[0].Name != "a-web" || report.VMs[0].ReadOps != 1 || report.VMs[0].LatencyAvgMS != 1 {
		t.Fatalf("a-web = %#v", report.VMs[0])
	}
	if report.VMs[0].MappingQuality != "cgroup_v2_inode_tree" || report.VMs[0].AttributionQuality != "experimental_blkcg_correlated" {
		t.Fatalf("separate mapping/attribution quality not preserved: %#v", report.VMs[0])
	}
	if report.VMs[1].Name != "b-stress" || report.VMs[1].WriteOps != 2 || report.VMs[1].LatencyAvgMS != 3 || report.VMs[1].LatencyP95MS != 5 || !report.VMs[1].PercentilesApproximate {
		t.Fatalf("b-stress = %#v", report.VMs[1])
	}
	if report.HostSummary.TotalOps != 3 || report.HostSummary.ReadOps != 1 || report.HostSummary.WriteOps != 2 {
		t.Fatalf("host summary = %#v", report.HostSummary)
	}
}

func TestVMBlockLatencyBoundedHistogramStatistics(t *testing.T) {
	var histogram boundedVMBlockLatencyHistogram
	for _, latency := range []time.Duration{50 * time.Microsecond, 100 * time.Microsecond, 750 * time.Microsecond, 4 * time.Millisecond, 2 * time.Second} {
		histogram.observe(uint64(latency))
	}
	minimum, average, p50, p95, p99, maximum := histogram.summary()
	if minimum != 0.05 || average != 400.98 || p50 != 1 || p95 != 2000 || p99 != 2000 || maximum != 2000 {
		t.Fatalf("stats = %v %v %v %v %v %v", minimum, average, p50, p95, p99, maximum)
	}
	buckets := histogram.publicBuckets()
	if len(buckets) != 14 || buckets[0].Range != "<100 us" || buckets[0].Count != 1 || buckets[1].Count != 1 || buckets[13].Range != "1 s+" || buckets[13].Count != 1 {
		t.Fatalf("buckets = %#v", buckets)
	}
}

func TestVMBlockLatencyUnattributedCounters(t *testing.T) {
	mappings := []VMBlockCgroupMapping{{Name: "a-web", PrimaryID: 11, CgroupIDs: []uint64{11}}}
	events := []VMBlockEvent{
		{Kind: "issue", RequestPointer: 1, TimestampNS: 1, MissingBio: true},
		{Kind: "issue", RequestPointer: 2, TimestampNS: 1, MissingBlkcg: true},
		{Kind: "issue", RequestPointer: 3, TimestampNS: 1, CgroupID: 99, Operation: "write"},
		{Kind: "complete", RequestPointer: 3, TimestampNS: 2},
		{Kind: "complete", RequestPointer: 44, TimestampNS: 2},
		{Kind: "issue", RequestPointer: 5, TimestampNS: 1, CgroupID: 11, Operation: "write", StackedDeviceAmbiguous: true},
		{Kind: "issue", RequestPointer: 6, TimestampNS: 1, UnsupportedRequest: true},
		{Kind: "issue", RequestPointer: 7, TimestampNS: 1, CgroupID: 11, Operation: "write"},
		{Kind: "issue", RequestPointer: 7, TimestampNS: 2, CgroupID: 11, Operation: "write"},
		{Kind: "issue", RequestPointer: 8, TimestampNS: 1, CgroupID: 11, Operation: "write"},
		{Kind: "issue", RequestPointer: 8, TimestampNS: 2, CgroupID: 11, Operation: "write", RequeueOrReissue: true},
	}
	report := CollectVMBlockLatencyReportWithSource(context.Background(), VMBlockLatencyCollectOptions{Duration: time.Second, Interval: time.Second}, mappings, fakeVMBlockEventSource{events: events})
	got := report.Unattributed
	if got.MissingBio != 1 || got.MissingBlkcg != 1 || got.UnmappedCgroup != 1 || got.LookupMiss != 1 || got.StackedDeviceAmbiguous != 1 || got.UnsupportedRequest != 1 || got.DuplicateIssue != 1 || got.RequeueOrReissue != 1 {
		t.Fatalf("unattributed = %#v", got)
	}
	if got.IncompleteAtWindowEnd != 2 || got.TotalUnattributedOps != 8 || got.UnattributedPercent != 100 {
		t.Fatalf("unattributed total = %#v", got)
	}
}

func TestVMBlockLatencyDeviceFilterUsesIssueMetadata(t *testing.T) {
	mappings := []VMBlockCgroupMapping{{Name: "a-web", PrimaryID: 11, CgroupIDs: []uint64{11}, MappingQuality: "cgroup_v2_inode_tree"}}
	events := []VMBlockEvent{
		{Kind: "issue", RequestPointer: 1, TimestampNS: 1_000_000, CgroupID: 11, Device: "dm-0", Operation: "write"},
		{Kind: "complete", RequestPointer: 1, TimestampNS: 3_000_000},
		{Kind: "issue", RequestPointer: 2, TimestampNS: 1_000_000, CgroupID: 11, Device: "nvme0n1", Operation: "write"},
		{Kind: "complete", RequestPointer: 2, TimestampNS: 4_000_000},
	}
	report := CollectVMBlockLatencyReportWithSource(context.Background(), VMBlockLatencyCollectOptions{
		Duration: time.Second, Interval: time.Second, DeviceFilter: "dm-0",
	}, mappings, fakeVMBlockEventSource{events: events})
	if report.HostSummary.TotalOps != 1 || report.VMs[0].WriteOps != 1 || report.VMs[0].LatencyAvgMS != 2 {
		t.Fatalf("filtered report = %#v", report)
	}
	if report.Unattributed.LookupMiss != 0 || report.Unattributed.IncompleteAtWindowEnd != 0 {
		t.Fatalf("filtered requests counted as unattributed: %#v", report.Unattributed)
	}
}

func TestVMBlockLatencyCountsPendingAtWindowEnd(t *testing.T) {
	mappings := []VMBlockCgroupMapping{{Name: "a-web", PrimaryID: 11, CgroupIDs: []uint64{11}, MappingQuality: "cgroup_v2_inode_tree"}}
	report := CollectVMBlockLatencyReportWithSource(context.Background(), VMBlockLatencyCollectOptions{
		Duration: time.Second, Interval: time.Second,
	}, mappings, fakeVMBlockEventSource{events: []VMBlockEvent{
		{Kind: "issue", RequestPointer: 1, TimestampNS: 1, CgroupID: 11, Device: "dm-0", Operation: "read"},
	}})
	if report.Unattributed.IncompleteAtWindowEnd != 1 || report.Unattributed.TotalUnattributedOps != 1 {
		t.Fatalf("pending request accounting = %#v", report.Unattributed)
	}
	if !containsString(report.Caveats, "censored requests") {
		t.Fatalf("missing censored request caveat: %#v", report.Caveats)
	}
}

func TestVMBlockLatencyPermissionAndUnsupportedStatuses(t *testing.T) {
	options := VMBlockLatencyCollectOptions{Duration: time.Second, Interval: time.Second}
	permission := CollectVMBlockLatencyReportWithSource(context.Background(), options, nil, fakeVMBlockEventSource{err: syscall.EPERM})
	if permission.Availability.Status != "permission_denied" || !strings.Contains(permission.Availability.Error, "try running with sudo") {
		t.Fatalf("permission report = %#v", permission.Availability)
	}
	unsupported := CollectVMBlockLatencyReportForPlatform(context.Background(), options, nil, "freebsd")
	if unsupported.Availability.Status != "unsupported" || !strings.Contains(unsupported.Availability.Error, "requires Linux") {
		t.Fatalf("unsupported report = %#v", unsupported.Availability)
	}
	deferred := CollectVMBlockLatencyReportWithKernelSource(context.Background(), options, nil, missingObjectVMBlockKernelSource())
	if deferred.Availability.Available || deferred.Availability.Status != "object_unavailable" {
		t.Fatalf("missing-object report = %#v", deferred.Availability)
	}
	if deferred.HostSummary.TotalOps != 0 || len(deferred.UnavailableSections) == 0 || len(deferred.Caveats) == 0 || privacyCollected(deferred) {
		t.Fatalf("deferred report falsely claims measurement or misses safeguards: %#v", deferred)
	}
	if deferred.HostSummary.LatencyMinMS != 0 || deferred.HostSummary.LatencyAvgMS != 0 || deferred.HostSummary.LatencyP50MS != 0 || deferred.HostSummary.LatencyP95MS != 0 || deferred.HostSummary.LatencyP99MS != 0 || deferred.HostSummary.LatencyMaxMS != 0 || histogramCount(deferred.HostSummary.Histogram) != 0 {
		t.Fatalf("deferred report contains fake latency: %#v", deferred.HostSummary)
	}
	var rendered bytes.Buffer
	if err := WriteVMBlockLatencyJSON(&rendered, deferred); err != nil {
		t.Fatal(err)
	}
	var decoded VMBlockLatencyReport
	if err := json.Unmarshal(rendered.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Availability.Available || decoded.Availability.Status != "object_unavailable" || decoded.HostSummary.TotalOps != 0 || privacyCollected(decoded) {
		t.Fatalf("rendered deferred report = %#v", decoded)
	}
}

func histogramCount(buckets []VMBlockLatencyHistogramBucket) uint64 {
	var count uint64
	for _, bucket := range buckets {
		count += bucket.Count
	}
	return count
}

func TestVMBlockLatencyPreservesMappingQualityWhenAttributionUnavailable(t *testing.T) {
	mappings := []VMBlockCgroupMapping{
		{Name: "a-web", MappingQuality: "cgroup_v2_inode_tree", PrimaryID: 11, CgroupIDs: []uint64{11}},
		{Name: "b-web", MappingQuality: "cgroup_v2_inode_partial", PrimaryID: 21, CgroupIDs: []uint64{21}},
	}
	report := CollectVMBlockLatencyReportWithKernelSource(
		context.Background(),
		VMBlockLatencyCollectOptions{Duration: time.Second, Interval: time.Second},
		mappings,
		missingObjectVMBlockKernelSource(),
	)
	if report.VMs[0].MappingQuality != "cgroup_v2_inode_tree" || report.VMs[0].AttributionQuality != "unavailable" {
		t.Fatalf("complete mapping quality = %#v", report.VMs[0])
	}
	if report.VMs[1].MappingQuality != "cgroup_v2_inode_partial" || report.VMs[1].AttributionQuality != "unavailable" {
		t.Fatalf("partial mapping quality = %#v", report.VMs[1])
	}
	if !hasUnavailableSection(report.UnavailableSections, "cgroup_mapping:b-web", "partial") {
		t.Fatalf("partial mapping section missing: %#v", report.UnavailableSections)
	}
}

func missingObjectVMBlockKernelSource() VMBlockKernelSource {
	return &ciliumVMBlockKernelSource{
		platform:       "linux",
		architecture:   "amd64",
		probeBTF:       func() error { return nil },
		objectProvider: func() ([]byte, error) { return nil, ErrVMBlockObjectUnavailable },
	}
}

func TestVMBlockLatencyDeterministicPrivacySafeJSON(t *testing.T) {
	report := newVMBlockLatencyReport(VMBlockLatencyCollectOptions{
		Duration: time.Second, Interval: time.Second, ObservedAt: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
	}, []VMBlockCgroupMapping{{Name: "b-vm"}, {Name: "a-vm"}})
	report.Availability = VMBlockLatencyAvailability{Status: "experimental_not_implemented"}
	var first, second bytes.Buffer
	if err := WriteVMBlockLatencyJSON(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := WriteVMBlockLatencyJSON(&second, report); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("JSON differs:\n%s\n%s", first.String(), second.String())
	}
	var decoded VMBlockLatencyReport
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.VMs[0].Name != "a-vm" || decoded.Privacy.ProcessArgumentsCollected || decoded.Privacy.EnvironmentCollected || decoded.Privacy.GuestFilesCollected || decoded.Privacy.QueryTextCollected || decoded.Privacy.TableDataCollected || decoded.Privacy.RequestBodyCollected || decoded.Privacy.ResponseBodyCollected || decoded.Privacy.SecretsCollected {
		t.Fatalf("decoded report = %#v", decoded)
	}
	if len(decoded.Caveats) == 0 {
		t.Fatal("expected attribution caveats")
	}
	report.Privacy.ProcessArgumentsCollected = true
	if err := WriteVMBlockLatencyJSON(&bytes.Buffer{}, report); err == nil {
		t.Fatal("expected privacy validation error")
	}
}

func TestBuildVMCgroupMappings(t *testing.T) {
	cgroupRoot := t.TempDir()
	procRoot := t.TempDir()
	scope := `machine.slice/machine-qemu\x2d3\x2da\x2dweb.scope`
	for _, relative := range []string{scope, filepath.Join(scope, "libvirt"), filepath.Join(scope, "libvirt", "emulator"), filepath.Join(scope, "libvirt", "vcpu0")} {
		if err := os.MkdirAll(filepath.Join(cgroupRoot, relative), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	primary := "/" + filepath.Join(scope, "libvirt", "emulator")
	writeFakeProcProcess(t, procRoot, 123, "qemu-system-x86", primary)
	mappings, err := buildVMCgroupMappings([]inventory.VM{{Name: "a-web", Tenant: "tenant-a", Role: "web", QEMUPID: "123", Disk: "/images/a-web.qcow2"}}, cgroupRoot, procRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 1 || mappings[0].PrimaryPath != primary || mappings[0].PrimaryID == 0 || len(mappings[0].CgroupIDs) < 4 || mappings[0].MappingQuality != "cgroup_v2_inode_tree" {
		t.Fatalf("mapping = %#v", mappings)
	}
	index, err := IndexVMCgroupMappings(mappings)
	if err != nil {
		t.Fatal(err)
	}
	if index[mappings[0].PrimaryID] != 0 {
		t.Fatalf("index = %#v", index)
	}
}

func TestBuildVMCgroupMappingsRejectsUnsafePIDIdentity(t *testing.T) {
	cgroupRoot := t.TempDir()
	procRoot := t.TempDir()
	scope := `machine.slice/machine-qemu\x2d3\x2da\x2dweb.scope`
	primary := "/" + filepath.Join(scope, "libvirt", "emulator")
	if err := os.MkdirAll(filepath.Join(cgroupRoot, strings.TrimPrefix(primary, "/")), 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		pid         int
		processName string
		cgroup      string
		quality     string
		create      bool
	}{
		{name: "stale PID", pid: 201, quality: "stale_or_unreadable_qemu_pid"},
		{name: "reused non-QEMU PID", pid: 202, processName: "sleep", cgroup: primary, quality: "non_qemu_pid", create: true},
		{name: "QEMU outside libvirt", pid: 203, processName: "qemu-system-x86", cgroup: "/user.slice/user-1000.slice/session-1.scope", quality: "not_libvirt_vm_cgroup", create: true},
		{name: "QEMU in lookalike non-machine slice", pid: 205, processName: "qemu-system-x86", cgroup: `/user.slice/machine-qemu\x2d3\x2da\x2dweb.scope/libvirt/emulator`, quality: "not_libvirt_vm_cgroup", create: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.create {
				writeFakeProcProcess(t, procRoot, test.pid, test.processName, test.cgroup)
			}
			mappings, err := buildVMCgroupMappings([]inventory.VM{{Name: "a-web", QEMUPID: strconv.Itoa(test.pid)}}, cgroupRoot, procRoot)
			if err != nil {
				t.Fatal(err)
			}
			if len(mappings) != 1 || mappings[0].MappingQuality != test.quality || len(mappings[0].CgroupIDs) != 0 || mappings[0].PrimaryID != 0 {
				t.Fatalf("mapping = %#v", mappings)
			}
		})
	}
}

func TestBuildVMCgroupMappingsUsesOnlySafeProcMetadata(t *testing.T) {
	cgroupRoot := t.TempDir()
	procRoot := t.TempDir()
	scope := `machine.slice/machine-qemu\x2d3\x2da\x2dweb.scope`
	primary := "/" + scope
	if err := os.MkdirAll(filepath.Join(cgroupRoot, strings.TrimPrefix(primary, "/")), 0o755); err != nil {
		t.Fatal(err)
	}
	// Only status, cgroup, and stat are present. cmdline and environ deliberately
	// do not exist, proving the mapper neither requires nor opens them.
	writeFakeProcProcess(t, procRoot, 204, "qemu-system-x86", primary)
	mappings, err := buildVMCgroupMappings([]inventory.VM{{Name: "a-web", QEMUPID: "204"}}, cgroupRoot, procRoot)
	if err != nil {
		t.Fatal(err)
	}
	if mappings[0].PrimaryID == 0 || mappings[0].MappingQuality != "cgroup_v2_inode_partial" {
		t.Fatalf("mapping = %#v", mappings[0])
	}
}

func TestValidateMappedQEMUProcessUsesSafeStableIdentity(t *testing.T) {
	procRoot := t.TempDir()
	scope := `/machine.slice/machine-qemu\x2d3\x2da\x2dweb.scope`
	primary := scope + "/libvirt/emulator"
	writeFakeProcProcess(t, procRoot, 301, "qemu-system-x86", primary)
	mapping := VMBlockCgroupMapping{
		Name: "a-web", QEMUPID: 301, PrimaryPath: primary,
		CgroupPaths: []string{scope, primary}, MappingQuality: "cgroup_v2_inode_tree",
	}
	identity, err := validateMappedQEMUProcess(mapping, procRoot)
	if err != nil {
		t.Fatal(err)
	}
	if identity.PID != 301 || identity.CgroupPath != primary || identity.MachineScope != scope || identity.StartTimeTicks != 12345 {
		t.Fatalf("identity = %#v", identity)
	}
	if _, err := os.Lstat(filepath.Join(procRoot, "301", "cmdline")); !os.IsNotExist(err) {
		t.Fatalf("test unexpectedly supplied cmdline: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(procRoot, "301", "environ")); !os.IsNotExist(err) {
		t.Fatalf("test unexpectedly supplied environ: %v", err)
	}

	writeFakeProcProcess(t, procRoot, 302, "sleep", primary)
	nonQEMU := mapping
	nonQEMU.QEMUPID = 302
	if _, err := validateMappedQEMUProcess(nonQEMU, procRoot); err == nil || !strings.Contains(err.Error(), "not a QEMU") {
		t.Fatalf("non-QEMU error = %v", err)
	}
	writeFakeProcProcess(t, procRoot, 303, "qemu-system-x86", "/user.slice/session.scope")
	outside := mapping
	outside.QEMUPID = 303
	outside.PrimaryPath = "/user.slice/session.scope"
	outside.CgroupPaths = []string{"/user.slice/session.scope"}
	if _, err := validateMappedQEMUProcess(outside, procRoot); err == nil || !strings.Contains(err.Error(), "not in a libvirt") {
		t.Fatalf("outside-cgroup error = %v", err)
	}
	stale := mapping
	stale.QEMUPID = 999
	if _, err := validateMappedQEMUProcess(stale, procRoot); err == nil {
		t.Fatal("expected stale PID error")
	}
}

func TestCgroupMappingRejectsDuplicateOwner(t *testing.T) {
	_, err := IndexVMCgroupMappings([]VMBlockCgroupMapping{{Name: "a", CgroupIDs: []uint64{10}}, {Name: "b", CgroupIDs: []uint64{10}}})
	if err == nil || !strings.Contains(err.Error(), "maps to both") {
		t.Fatalf("error = %v", err)
	}
}

func TestCgroupMappingRejectsEscapingPath(t *testing.T) {
	if _, err := cleanCgroupPath("/machine.slice/../outside"); err == nil {
		t.Fatal("expected unsafe cgroup path error")
	}
}

func TestCgroupIOStatParsingAndLayeredDeltas(t *testing.T) {
	before, err := ParseCgroupIOStat("259:0 rbytes=100 wbytes=200 rios=2 wios=3\n252:1 rbytes=100 wbytes=200 rios=2 wios=3\n")
	if err != nil {
		t.Fatal(err)
	}
	after, err := ParseCgroupIOStat("252:1 rbytes=150 wbytes=260 rios=4 wios=6\n259:0 rbytes=150 wbytes=260 rios=4 wios=6\n")
	if err != nil {
		t.Fatal(err)
	}
	deltas, err := DeltaCgroupIOStat("a-web", "/machine/a", before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(deltas) != 2 || deltas[0].Device != "252:1" || deltas[1].Device != "259:0" {
		t.Fatalf("stacked rows were combined or misordered: %#v", deltas)
	}
	for _, delta := range deltas {
		if delta.Status != "ok" || delta.CounterReset || delta.ReadBytes != 50 || delta.WriteBytes != 60 || delta.ReadOps != 2 || delta.WriteOps != 3 {
			t.Fatalf("delta = %#v", delta)
		}
	}
}

func TestCgroupIOStatDeltaStatesAndDuplicateRejection(t *testing.T) {
	before := []CgroupIOCounters{
		{Device: "8:0", ReadBytes: 100, WriteBytes: 200},
		{Device: "8:1", ReadBytes: 20},
		{Device: "8:2", ReadBytes: 300},
	}
	after := []CgroupIOCounters{
		{Device: "8:0", ReadBytes: 150, WriteBytes: 250},
		{Device: "8:2", ReadBytes: 10},
		{Device: "8:3", ReadBytes: 9999, WriteBytes: 8888},
	}
	deltas, err := DeltaCgroupIOStat("a-web", "/machine/a", before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(deltas) != 4 || deltas[0].Status != "ok" || deltas[0].ReadBytes != 50 || deltas[1].Status != "missing_after" || deltas[2].Status != "counter_reset" || !deltas[2].CounterReset || deltas[2].ReadBytes != 0 || deltas[3].Status != "baseline_missing" || deltas[3].ReadBytes != 0 {
		t.Fatalf("delta states = %#v", deltas)
	}
	if _, err := ParseCgroupIOStat("8:0 rbytes=1\n8:0 rbytes=2\n"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate parse error = %v", err)
	}
	if _, err := DeltaCgroupIOStat("a-web", "/machine/a", []CgroupIOCounters{{Device: "8:0"}, {Device: "8:0"}}, nil); err == nil {
		t.Fatal("expected duplicate baseline device error")
	}
	zero, err := DeltaCgroupIOStat("a-web", "/machine/a", []CgroupIOCounters{{Device: "8:4", ReadBytes: 10}}, []CgroupIOCounters{{Device: "8:4", ReadBytes: 10}})
	if err != nil {
		t.Fatal(err)
	}
	if len(zero) != 1 || zero[0].Status != "ok" || zero[0].CounterReset || zero[0].ReadBytes != 0 {
		t.Fatalf("legitimate zero delta treated as reset: %#v", zero)
	}
}

func TestVirshDomstatsBlockParsingAndDelta(t *testing.T) {
	before, err := ParseVirshDomstatsBlock("block.0.name=vda\nblock.0.rd.reqs=10\nblock.0.rd.bytes=100\nblock.0.rd.times=1000\nblock.0.wr.reqs=20\nblock.0.wr.bytes=200\nblock.0.wr.times=2000\n")
	if err != nil {
		t.Fatal(err)
	}
	after, err := ParseVirshDomstatsBlock("block.0.name=vda\nblock.0.rd.reqs=13\nblock.0.rd.bytes=160\nblock.0.rd.times=1300\nblock.0.wr.reqs=25\nblock.0.wr.bytes=300\nblock.0.wr.times=2600\n")
	if err != nil {
		t.Fatal(err)
	}
	deltas, err := DeltaVirshBlockStats("a-web", before, after)
	if err != nil {
		t.Fatal(err)
	}
	want := []VirshBlockDelta{{VM: "a-web", Block: "vda", Status: "ok", ReadBytes: 60, WriteBytes: 100, ReadOps: 3, WriteOps: 5, ReadTimeNS: 300, WriteTimeNS: 600}}
	if !reflect.DeepEqual(deltas, want) {
		t.Fatalf("deltas = %#v, want %#v", deltas, want)
	}
}

func TestVirshDomstatsDeltaStatesAndDuplicateRejection(t *testing.T) {
	before := []VirshBlockCounters{{Block: "vda", ReadBytes: 100}, {Block: "vdb", ReadBytes: 50}, {Block: "vdc", WriteBytes: 100}}
	after := []VirshBlockCounters{{Block: "vda", ReadBytes: 125}, {Block: "vdc", WriteBytes: 10}, {Block: "vdd", ReadBytes: 999}}
	deltas, err := DeltaVirshBlockStats("a-web", before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(deltas) != 4 || deltas[0].Status != "ok" || deltas[0].ReadBytes != 25 || deltas[1].Status != "missing_after" || deltas[2].Status != "counter_reset" || !deltas[2].CounterReset || deltas[3].Status != "baseline_missing" || deltas[3].ReadBytes != 0 {
		t.Fatalf("delta states = %#v", deltas)
	}
	if _, err := ParseVirshDomstatsBlock("block.0.name=vda\nblock.0.rd.bytes=1\nblock.0.rd.bytes=2\n"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate key error = %v", err)
	}
	if _, err := ParseVirshDomstatsBlock("block.0.name=vda\nblock.1.name=vda\n"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate identity error = %v", err)
	}
	if _, err := DeltaVirshBlockStats("a-web", []VirshBlockCounters{{Block: "vda"}, {Block: "vda"}}, nil); err == nil {
		t.Fatal("expected duplicate baseline block error")
	}
	zero, err := DeltaVirshBlockStats("a-web", []VirshBlockCounters{{Block: "vde", WriteOps: 10}}, []VirshBlockCounters{{Block: "vde", WriteOps: 10}})
	if err != nil {
		t.Fatal(err)
	}
	if len(zero) != 1 || zero[0].Status != "ok" || zero[0].CounterReset || zero[0].WriteOps != 0 {
		t.Fatalf("legitimate zero delta treated as reset: %#v", zero)
	}
}

func TestVirshDomstatsMalformedNumericErrorIsDeterministic(t *testing.T) {
	input := "block.0.name=vda\nblock.0.rd.bytes=bad-read\nblock.0.wr.bytes=bad-write\nblock.0.rd.reqs=bad-reqs\n"
	for iteration := 0; iteration < 50; iteration++ {
		_, err := ParseVirshDomstatsBlock(input)
		if err == nil || !strings.Contains(err.Error(), "parse virsh domstats rd.bytes for vda") {
			t.Fatalf("iteration %d error = %v", iteration, err)
		}
	}
}

func writeFakeProcProcess(t *testing.T, procRoot string, pid int, name, cgroup string) {
	t.Helper()
	root := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "status"), []byte("Name:\t"+name+"\nState:\tS (sleeping)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup"), []byte("0::"+cgroup+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	statFields := []string{"S"}
	for range 18 {
		statFields = append(statFields, "0")
	}
	statFields = append(statFields, "12345")
	stat := fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(statFields, " "))
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte(stat), 0o600); err != nil {
		t.Fatal(err)
	}
}

func containsString(values []string, fragment string) bool {
	for _, value := range values {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func hasUnavailableSection(sections []VMBlockLatencyUnavailableSection, name, status string) bool {
	for _, section := range sections {
		if section.Name == name && section.Status == status {
			return true
		}
	}
	return false
}
