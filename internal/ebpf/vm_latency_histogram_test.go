package ebpf

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestVMBlockLatencyRuntimeAccumulatorHasNoLatencySlice(t *testing.T) {
	accumulatorType := reflect.TypeOf(vmLatencyAccumulator{})
	for index := 0; index < accumulatorType.NumField(); index++ {
		field := accumulatorType.Field(index)
		if field.Type.Kind() == reflect.Slice {
			t.Fatalf("runtime accumulator field %s is an unbounded slice: %s", field.Name, field.Type)
		}
	}
	histogramType := reflect.TypeOf(boundedVMBlockLatencyHistogram{})
	buckets, ok := histogramType.FieldByName("buckets")
	if !ok || buckets.Type.Kind() != reflect.Array || buckets.Type.Len() != len(vmBlockLatencyBucketUpperNS) {
		t.Fatalf("histogram buckets are not fixed: %#v", buckets)
	}
}

func TestVMBlockLatencySeparatesVMDeviceAndOperation(t *testing.T) {
	mappings := []VMBlockCgroupMapping{
		{Name: "a-web", CgroupIDs: []uint64{11}, MappingQuality: "cgroup_v2_inode_tree"},
		{Name: "b-stress", CgroupIDs: []uint64{22}, MappingQuality: "cgroup_v2_inode_tree"},
	}
	events := []VMBlockEvent{
		{Kind: "issue", RequestPointer: 1, TimestampNS: 1, CgroupID: 11, Device: "dm-0", Operation: "read"},
		{Kind: "complete", RequestPointer: 1, TimestampNS: uint64(50*time.Microsecond) + 1},
		{Kind: "issue", RequestPointer: 2, TimestampNS: 1, CgroupID: 11, Device: "dm-0", Operation: "write"},
		{Kind: "complete", RequestPointer: 2, TimestampNS: uint64(300*time.Microsecond) + 1},
		{Kind: "issue", RequestPointer: 3, TimestampNS: 1, CgroupID: 11, Device: "dm-0", Operation: "flush"},
		{Kind: "complete", RequestPointer: 3, TimestampNS: uint64(1500*time.Microsecond) + 1},
		{Kind: "issue", RequestPointer: 4, TimestampNS: 1, CgroupID: 11, Device: "nvme0n1", Operation: "discard"},
		{Kind: "complete", RequestPointer: 4, TimestampNS: uint64(6*time.Millisecond) + 1},
		{Kind: "issue", RequestPointer: 5, TimestampNS: 1, CgroupID: 22, Device: "nvme0n1", Operation: "write"},
		{Kind: "complete", RequestPointer: 5, TimestampNS: uint64(30*time.Millisecond) + 1},
	}
	report := CollectVMBlockLatencyReportWithSource(
		context.Background(), VMBlockLatencyCollectOptions{Duration: time.Second, Interval: time.Second}, mappings,
		fakeVMBlockEventSource{events: events},
	)
	if len(report.VMs) != 2 {
		t.Fatalf("VMs = %#v", report.VMs)
	}
	aWeb := report.VMs[0]
	if aWeb.Name != "a-web" || aWeb.ReadOps != 1 || aWeb.WriteOps != 1 || aWeb.FlushOps != 1 || aWeb.UnknownOps != 1 || aWeb.TotalOps != 4 {
		t.Fatalf("a-web = %#v", aWeb)
	}
	if len(aWeb.DeviceOperations) != 4 {
		t.Fatalf("device operations = %#v", aWeb.DeviceOperations)
	}
	want := []struct{ device, operation string }{
		{"dm-0", "read"}, {"dm-0", "write"}, {"dm-0", "flush"}, {"nvme0n1", "unknown"},
	}
	for index, expected := range want {
		got := aWeb.DeviceOperations[index]
		if got.Device != expected.device || got.Operation != expected.operation || got.Count != 1 || len(got.Histogram) != 14 {
			t.Fatalf("operation %d = %#v", index, got)
		}
	}
	bStress := report.VMs[1]
	if bStress.Name != "b-stress" || bStress.WriteOps != 1 || bStress.TotalOps != 1 || bStress.LatencyAvgMS != 30 {
		t.Fatalf("b-stress = %#v", bStress)
	}
	if report.HostSummary.ReadOps != 1 || report.HostSummary.WriteOps != 2 || report.HostSummary.FlushOps != 1 || report.HostSummary.UnknownOps != 1 || report.HostSummary.TotalOps != 5 {
		t.Fatalf("host summary = %#v", report.HostSummary)
	}
}

func TestVMBlockLatencyDeterministicNestedHistogramJSON(t *testing.T) {
	report := VMBlockLatencyReport{
		SchemaVersion: "1", ObservedAtUTC: "2026-08-10T12:00:00Z", Duration: "1s", Interval: "1s", Mode: "experimental",
		Availability: VMBlockLatencyAvailability{Available: true, Status: "available"},
		VMs: []VMBlockLatencyVM{
			{Name: "b", Histogram: emptyVMBlockLatencyBuckets(), DeviceOperations: []VMBlockLatencyDeviceOperation{operationSummary("z", "write", histogramWithLatency(time.Millisecond))}},
			{Name: "a", Histogram: emptyVMBlockLatencyBuckets(), DeviceOperations: []VMBlockLatencyDeviceOperation{
				operationSummary("z", "unknown", histogramWithLatency(10*time.Millisecond)),
				operationSummary("a", "flush", histogramWithLatency(2*time.Millisecond)),
				operationSummary("a", "read", histogramWithLatency(100*time.Microsecond)),
			}},
		},
		UnavailableSections: []VMBlockLatencyUnavailableSection{{Name: "z", Status: "error"}, {Name: "a", Status: "partial"}},
		Caveats:             []string{"experimental only"},
	}
	report.Unattributed = VMBlockLatencyUnattributed{MissingBio: 1, RingBufferLost: 2, MapFull: 3}
	var first, second bytes.Buffer
	if err := WriteVMBlockLatencyJSON(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := WriteVMBlockLatencyJSON(&second, report); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("JSON is not deterministic:\n%s\n%s", first.String(), second.String())
	}
	var decoded VMBlockLatencyReport
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.VMs[0].Name != "a" || decoded.VMs[0].DeviceOperations[0].Operation != "read" || decoded.VMs[0].DeviceOperations[1].Operation != "flush" || decoded.VMs[0].DeviceOperations[2].Device != "z" {
		t.Fatalf("normalized VM/device operations = %#v", decoded.VMs)
	}
	if privacyCollected(decoded) {
		t.Fatalf("privacy flags = %#v", decoded.Privacy)
	}
}

func histogramWithLatency(latency time.Duration) boundedVMBlockLatencyHistogram {
	var histogram boundedVMBlockLatencyHistogram
	histogram.observe(uint64(latency))
	return histogram
}
