package top

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/hostmetrics"
	"github.com/safwen511/solis-io/internal/observability"
	statusview "github.com/safwen511/solis-io/internal/status"
)

func TestBuildViewMergesStatusAndAttributedLatency(t *testing.T) {
	report := attributedReport()
	view, err := BuildView(Snapshot{
		ObservedAtUTC:        time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
		StatusAvailable:      true,
		StatusState:          "available",
		Status:               statusReport(),
		Host:                 hostReport(),
		EBPFLatencyRequested: true,
		EBPFLatency:          &report,
	}, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if !view.Attribution.CollectorAvailable || !view.Attribution.AttributionAvailable || view.Attribution.Quality != "available" {
		t.Fatalf("attribution = %#v", view.Attribution)
	}
	if view.Attribution.UnattributedPercent != 1 || view.Attribution.HostTotalOps != 101 || view.Attribution.HostP95MS != 2 {
		t.Fatalf("attribution summary = %#v", view.Attribution)
	}
	if len(view.Rows) != 2 || view.Rows[0].Name != "b-stress" || view.Rows[0].AttributedOps != 100 || view.Rows[1].Name != "a-web" {
		t.Fatalf("rows = %#v", view.Rows)
	}
	if len(view.Storage) != 1 || view.Storage[0].Device != "/dev/nvme0n1" || !view.Storage[0].Available || view.Storage[0].WriteMiBPerSecond != 1 {
		t.Fatalf("storage = %#v", view.Storage)
	}
	if !view.Host.Available || view.Host.CPUBusyPercent != 20 || view.Host.IOWaitPercent != 2 || view.Host.IOPSISomeAvg10 != 0.5 {
		t.Fatalf("host = %#v", view.Host)
	}
}

func TestBuildViewKeepsUnavailableEvidenceDistinctFromZero(t *testing.T) {
	view, err := BuildView(Snapshot{
		ObservedAtUTC:        time.Now(),
		StatusAvailable:      true,
		Status:               statusReport(),
		EBPFLatencyRequested: true,
		EBPFUnavailableState: "permission_denied",
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	if view.Attribution.CollectorAvailable || view.Attribution.Status != "permission_denied" {
		t.Fatalf("attribution = %#v", view.Attribution)
	}
	for _, row := range view.Rows {
		if row.AttributionAvailable || row.AttributionState != "permission_denied" {
			t.Fatalf("row = %#v", row)
		}
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{Iteration: 1, Every: 5 * time.Second}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"eBPF VM attribution: UNAVAILABLE", "status=permission_denied", "ATTR_OPS", "P95_MS~"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "a-web        0") {
		t.Fatalf("unavailable attribution rendered as a measured zero:\n%s", output.String())
	}
}

func TestBuildViewHidesPerVMValuesWhenAttributionQualityIsUnavailable(t *testing.T) {
	report := attributedReport()
	report.AttributionQuality = "unavailable"
	report.AttributionSummary.AttributedOps = 3
	report.AttributionSummary.AttributedPercent = 8.57
	report.Unattributed.UnattributedPercent = 91.43
	report.VMs[1].TotalOps = 3
	report.VMs[1].LatencyP95MS = 2
	view, err := BuildView(Snapshot{
		ObservedAtUTC: time.Now(), StatusAvailable: true, Status: statusReport(),
		EBPFLatencyRequested: true, EBPFLatency: &report,
	}, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if !view.Attribution.CollectorAvailable || view.Attribution.AttributionAvailable || view.Attribution.Quality != "unavailable" {
		t.Fatalf("attribution = %#v", view.Attribution)
	}
	for _, row := range view.Rows {
		if row.AttributionAvailable || row.AttributedOps != 0 || row.LatencyP95MS != 0 {
			t.Fatalf("unavailable per-VM evidence was published: %#v", row)
		}
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{Iteration: 1, Every: time.Second}); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "a-web") || strings.HasPrefix(line, "b-stress") {
			if !strings.Contains(line, "-") {
				t.Fatalf("unavailable row does not contain missing-value markers: %q", line)
			}
		}
	}
}

func TestBuildViewMarksVMStatusUnavailableWhenQEMUEvidenceIsUnavailable(t *testing.T) {
	report := statusReport()
	for index := range report.VMs {
		report.VMs[index].IOAvailable = false
	}
	view, err := BuildView(Snapshot{
		ObservedAtUTC: time.Now(), StatusAvailable: true, Status: report,
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	if view.StatusState != "unavailable" || view.Pressures != (statusview.PressureCounts{}) {
		t.Fatalf("status = %q, pressures = %#v", view.StatusState, view.Pressures)
	}
	for _, row := range view.Rows {
		if row.WriteAvailable || row.Pressure != "unavailable" {
			t.Fatalf("row = %#v", row)
		}
	}
}

func TestWriteFramePrivacySafeProjection(t *testing.T) {
	report := attributedReport()
	report.VMs[0].CgroupPath = "/machine.slice/private.scope"
	report.Diagnostics.RawError = "internal diagnostic"
	view, err := BuildView(Snapshot{
		ObservedAtUTC:        time.Now(),
		StatusAvailable:      true,
		Status:               statusReport(),
		EBPFLatencyRequested: true,
		EBPFLatency:          &report,
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{Iteration: 1, Every: time.Second}); err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(output.String())
	for _, forbidden := range []string{"request_pointer", "0xffff", "cmdline", "/proc/", "private.scope", "internal diagnostic"} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("dashboard contains forbidden/internal value %q:\n%s", forbidden, output.String())
		}
	}
}

func TestInteractiveFrameShowsSelectedVMDetailsAndLossCounters(t *testing.T) {
	report := attributedReport()
	source := &fakeSource{snapshot: Snapshot{
		ObservedAtUTC: time.Now(), StatusAvailable: true, Status: statusReport(),
		Host: hostReport(), EBPFLatencyRequested: true, EBPFLatency: &report,
	}}
	var output bytes.Buffer
	if err := RunInteractive(context.Background(), bytes.NewReader(nil), &output, source, Options{
		Duration: time.Millisecond, Interval: time.Millisecond, Every: time.Second,
		Iterations: 1, Clear: false, Sort: "ops", IncludeEBPFLatency: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Sort: ops",
		">  b-stress",
		"Selected VM: b-stress",
		"Attributed operations: total=100 read=5 write=90 flush=3 discard=1 unknown=1",
		"Latency ms~: p50=0.500 p95=2.000 p99=5.000 max=7.000",
		"259:3 write: ops=90 p95_ms~=2.000",
		"Attribution loss: missing_bio=2 missing_blkcg=1 unmapped_cgroup=3 lookup_miss=4",
		"Keys: j/k or arrows select",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("interactive output missing %q:\n%s", want, output.String())
		}
	}
}

func TestKeyActionsAndSelection(t *testing.T) {
	actions := readKeyActions(strings.NewReader("j\x1b[Akpnworl?"))
	var got []keyAction
	for action := range actions {
		got = append(got, action)
	}
	want := []keyAction{keyDown, keyUp, keyUp, keySortPressure, keySortName, keySortWrite, keySortOps, keyRefresh, keySortLatency, keyHelp}
	if len(got) != len(want) {
		t.Fatalf("actions = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("actions[%d] = %v, want %v", index, got[index], want[index])
		}
	}

	view := View{Rows: []VMRow{{Name: "a"}, {Name: "b"}, {Name: "c"}}}
	state := interactiveState{selectedVM: "a", sort: "name"}
	applyInteractiveAction(&view, &state, keyUp)
	if state.selectedVM != "c" {
		t.Fatalf("wrapped up selection = %q", state.selectedVM)
	}
	applyInteractiveAction(&view, &state, keyDown)
	if state.selectedVM != "a" {
		t.Fatalf("wrapped down selection = %q", state.selectedVM)
	}
}

func TestInteractiveQuitWaitsForCollectionCleanup(t *testing.T) {
	source := &cleanupSource{started: make(chan struct{}), cleaned: make(chan struct{})}
	reader, writer := io.Pipe()
	defer reader.Close()
	go func() {
		<-source.started
		_, _ = writer.Write([]byte("q"))
		_ = writer.Close()
	}()
	var output bytes.Buffer
	if err := RunInteractive(context.Background(), reader, &output, source, Options{
		Duration: time.Second, Interval: time.Second, Every: time.Second, Clear: false, Sort: "name",
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-source.cleaned:
	default:
		t.Fatal("interactive quit returned before source cleanup")
	}
}

func TestRunUsesBoundedRefreshesWithoutClearSequences(t *testing.T) {
	source := &fakeSource{snapshot: Snapshot{
		ObservedAtUTC:   time.Now(),
		StatusAvailable: true,
		Status:          statusReport(),
	}}
	var output bytes.Buffer
	err := Run(context.Background(), &output, source, Options{
		Duration: time.Millisecond, Interval: time.Millisecond, Every: time.Millisecond,
		Iterations: 2, Clear: false, Sort: "name",
	})
	if err != nil {
		t.Fatal(err)
	}
	if source.calls != 2 || strings.Count(output.String(), "Solis I/O Top (read-only)") != 2 {
		t.Fatalf("calls = %d, output:\n%s", source.calls, output.String())
	}
	if strings.Contains(output.String(), "\x1b[2J") {
		t.Fatalf("unexpected clear sequence:\n%q", output.String())
	}
}

func TestRunTreatsContextCancellationAsCleanStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	if err := Run(ctx, &output, cancelSource{}, Options{
		Duration: time.Second, Interval: time.Second, Every: time.Second, Sort: "name",
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("output = %q", output.String())
	}
}

type fakeSource struct {
	snapshot Snapshot
	calls    int
}

func (source *fakeSource) Collect(_ context.Context, _ CollectRequest) (Snapshot, error) {
	source.calls++
	return source.snapshot, nil
}

type cancelSource struct{}

func (cancelSource) Collect(ctx context.Context, _ CollectRequest) (Snapshot, error) {
	<-ctx.Done()
	return Snapshot{}, errors.New("wrapped: " + ctx.Err().Error())
}

type cleanupSource struct {
	started chan struct{}
	cleaned chan struct{}
}

func (source *cleanupSource) Collect(ctx context.Context, _ CollectRequest) (Snapshot, error) {
	close(source.started)
	<-ctx.Done()
	close(source.cleaned)
	return Snapshot{}, ctx.Err()
}

func statusReport() statusview.Report {
	return statusview.Report{
		SchemaVersion: statusview.SchemaVersion,
		Duration:      "3s",
		Interval:      "1s",
		VMs: []statusview.VMStatus{
			{Name: "a-web", Tenant: "tenant-a", Role: "web", PhysicalDisk: "/dev/nvme0n1", Pressure: "idle", Reason: "idle", IOAvailable: true},
			{Name: "b-stress", Tenant: "tenant-b", Role: "stress", PhysicalDisk: "/dev/nvme0n1", AverageWriteMiBPerSecond: 50, MaxWriteMiBPerSecond: 60, AverageSyscwPerSecond: 1000, Pressure: "high", Reason: "dominant byte write rate", IOAvailable: true},
		},
	}
}

func attributedReport() ebpf.VMBlockLatencyReport {
	return ebpf.VMBlockLatencyReport{
		Availability:       ebpf.VMBlockLatencyAvailability{Available: true, Status: "available"},
		AttributionQuality: "available",
		HostSummary: ebpf.VMBlockLatencySummary{
			TotalOps: 101, LatencyP95MS: 2, PercentilesApproximate: true,
		},
		AttributionSummary: ebpf.VMBlockAttributionSummary{
			AttributedOps: 100, UnattributedOps: 1, AttributedPercent: 99, MatchedVMCount: 1,
		},
		Unattributed: ebpf.VMBlockLatencyUnattributed{
			MissingBio: 2, MissingBlkcg: 1, UnmappedCgroup: 3, LookupMiss: 4,
			IncompleteAtWindowEnd: 5, MapFull: 0, DroppedEvents: 0, RingBufferLost: 0,
			TotalUnattributedOps: 1, UnattributedPercent: 1,
		},
		VMAttributionPreflight: ebpf.VMBlockAttributionPreflight{Available: true, Status: "enabled"},
		VMs: []ebpf.VMBlockLatencyVM{
			{Name: "a-web", Tenant: "tenant-a", Role: "web", TotalOps: 0, AttributionQuality: "no_attributed_events"},
			{
				Name: "b-stress", Tenant: "tenant-b", Role: "stress",
				ReadOps: 5, WriteOps: 90, FlushOps: 3, DiscardOps: 1, UnknownOps: 1, TotalOps: 100,
				LatencyP50MS: 0.5, LatencyP95MS: 2, LatencyP99MS: 5, LatencyMaxMS: 7,
				AttributionQuality: "available", MappingQuality: "cgroup_v2_inode_tree", Devices: []string{"259:3"},
				DeviceOperations: []ebpf.VMBlockLatencyDeviceOperation{{Device: "259:3", Operation: "write", Count: 90, LatencyP95MS: 2}},
			},
		},
	}
}

func hostReport() *hostmetrics.HostStatus {
	available := observability.Availability{Available: true, Quality: "measured"}
	return &hostmetrics.HostStatus{
		Availability: available,
		CPU: hostmetrics.CPUStatus{
			Availability: available, TotalBusyPercent: 20, IOWaitPercent: 2,
		},
		Memory: hostmetrics.MemoryStatus{
			Availability: available, MemAvailablePercent: 75,
		},
		PSI: hostmetrics.PSIStatus{IO: hostmetrics.PSIResourceStatus{
			Some: hostmetrics.PSIValues{Availability: available, Avg10: 0.5},
		}},
		Disks: hostmetrics.DiskSection{Availability: available, Devices: []hostmetrics.DiskStatus{{
			Name: "nvme0n1", RateAvailability: available, WriteSectorsPerSecond: 2048,
			WritesPerSecond: 32, IOInProgress: 1,
		}}},
	}
}
