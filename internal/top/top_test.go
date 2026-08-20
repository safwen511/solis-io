package top

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/hostmetrics"
	"github.com/safwen511/solis-io/internal/observability"
	statusview "github.com/safwen511/solis-io/internal/status"
)

// TestBuildViewMergesStatusAndAttributedLatency verifies build view merges status and attributed
// latency.
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

// TestPressureSortUsesAttributedIOToOrderEqualPressurePeers verifies pressure sort uses attributed
// io to order equal pressure peers.
func TestPressureSortUsesAttributedIOToOrderEqualPressurePeers(t *testing.T) {
	rows := []VMRow{
		{Name: "a-db", Pressure: "low", WriteAvailable: true, WriteMiBPerSecond: 0.02, AttributionAvailable: true, AttributedOps: 11},
		{Name: "b-stress", Pressure: "low", WriteAvailable: true, WriteMiBPerSecond: 8, AttributionAvailable: true, AttributedOps: 8152},
		{Name: "a-web", Pressure: "idle", WriteAvailable: true},
	}
	sortRows(rows, "pressure")
	if rows[0].Name != "b-stress" || rows[1].Name != "a-db" || rows[2].Name != "a-web" {
		t.Fatalf("pressure order = %#v", rows)
	}
}

// TestBuildViewKeepsUnavailableEvidenceDistinctFromZero verifies build view keeps unavailable
// evidence distinct from zero.
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
	for _, want := range []string{"eBPF collector: UNAVAILABLE", "VM attribution: UNAVAILABLE", "status=permission_denied", "ATTR_OPS", "P95_MS~"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "a-web        0") {
		t.Fatalf("unavailable attribution rendered as a measured zero:\n%s", output.String())
	}
}

// TestBuildViewHidesPerVMValuesWhenAttributionQualityIsUnavailable verifies build view hides per vm
// values when attribution quality is unavailable.
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

// TestBuildViewMarksVMStatusUnavailableWhenQEMUEvidenceIsUnavailable verifies build view marks vm
// status unavailable when qemu evidence is unavailable.
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

// TestBuildViewIncludesRunningAndStoppedInventoryVMs verifies build view includes running and
// stopped inventory VMs.
func TestBuildViewIncludesRunningAndStoppedInventoryVMs(t *testing.T) {
	view, err := BuildView(Snapshot{
		ObservedAtUTC: time.Now(),
		Inventory: []InventoryVM{
			{Name: "a-web", Tenant: "tenant-a", Role: "web", State: "running", Network: "tenant-a-net", PlannedIP: "192.168.130.20", LeaseIP: "192.168.130.20", MemoryMB: "2048", VCPUs: "2", DiskGB: "20", DiskPath: "/images/a-web.qcow2"},
			{Name: "b-offline", Tenant: "tenant-b", Role: "worker", State: "shut off", Network: "tenant-b-net", PlannedIP: "192.168.140.50", MemoryMB: "1024", VCPUs: "1", DiskGB: "10", DiskPath: "/images/b-offline.qcow2"},
		},
		StatusAvailable: true,
		Status: statusview.Report{
			SchemaVersion: statusview.SchemaVersion, Duration: "3s", Interval: "1s",
			VMs: []statusview.VMStatus{{Name: "a-web", Tenant: "tenant-a", Role: "web", State: "running", Pressure: "idle", Reason: "idle", IOAvailable: true}},
		},
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	if view.VMs != (VMCounts{Total: 2, Running: 1, NotRunning: 1}) {
		t.Fatalf("VM counts = %#v", view.VMs)
	}
	if len(view.Rows) != 2 || view.Rows[0].Name != "a-web" || view.Rows[1].Name != "b-offline" {
		t.Fatalf("rows = %#v", view.Rows)
	}
	offline := view.Rows[1]
	if offline.Running || offline.State != "shut off" || offline.Pressure != "not_running" ||
		offline.AttributionAvailable || offline.AttributionState != "not_running" {
		t.Fatalf("offline row = %#v", offline)
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{
		Iteration: 1, Every: time.Second, SelectedVM: "b-offline", Sort: "name",
		Interactive: true, ActivePanel: panelDetails, Application: true, ShowBanner: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"███████╗", "LIVE PROVIDER CONSOLE", "total=2 running=1 not_running=1 unknown=0",
		"INVESTIGATE  b-offline", "•  SHUT OFF", "planned=192.168.140.50",
		"vcpus=1 memory_mb=1024 disk_gb=10", "Live investigation is unavailable because this VM is not running",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("application output missing %q:\n%s", want, output.String())
		}
	}
	for _, forbidden := range []string{"request_pointer", "0xffff", "cmdline", "/proc/"} {
		if strings.Contains(strings.ToLower(output.String()), forbidden) {
			t.Errorf("application contains forbidden value %q:\n%s", forbidden, output.String())
		}
	}
}

// TestBuildViewKeepsUnknownLibvirtStateDistinctFromStopped verifies build view keeps unknown
// libvirt state distinct from stopped.
func TestBuildViewKeepsUnknownLibvirtStateDistinctFromStopped(t *testing.T) {
	view, err := BuildView(Snapshot{
		ObservedAtUTC: time.Now(),
		Inventory:     []InventoryVM{{Name: "a-web", State: ""}},
		Status:        statusview.Report{SchemaVersion: statusview.SchemaVersion, Duration: "1s", Interval: "1s"},
		StatusState:   "collection_error",
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	if view.VMs != (VMCounts{Total: 1, Unknown: 1}) {
		t.Fatalf("VM counts = %#v", view.VMs)
	}
	row := view.Rows[0]
	if row.State != "unknown" || row.Pressure != AttributionUnavailable || row.PressureReason != "libvirt runtime state is unavailable" || row.AttributionState != AttributionUnavailable {
		t.Fatalf("unknown row = %#v", row)
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{Iteration: 1, Every: time.Second, SelectedVM: "a-web", Interactive: true, ActivePanel: panelDetails, Application: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "libvirt runtime state is unavailable") || strings.Contains(output.String(), "because this VM is not running") {
		t.Fatalf("unknown state was rendered as stopped:\n%s", output.String())
	}
}

// TestWriteFramePrivacySafeProjection verifies write frame privacy safe projection.
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

// TestWriteFrameNeutralizesTerminalControlCharacters verifies write frame neutralizes terminal
// control characters.
func TestWriteFrameNeutralizesTerminalControlCharacters(t *testing.T) {
	report := statusReport()
	report.VMs[0].Name = "a-\x1b[31mweb"
	report.VMs[0].Tenant = "tenant\nunsafe"
	view, err := BuildView(Snapshot{
		ObservedAtUTC: time.Now(), StatusAvailable: true, Status: report,
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{Iteration: 1, Every: time.Second}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\x1b[31m") || strings.Contains(output.String(), "tenant\nunsafe") {
		t.Fatalf("terminal control characters were not neutralized:\n%q", output.String())
	}
}

// TestInteractiveDetailPanelShowsSelectedVMDetailsAndLossCounters verifies interactive detail panel
// shows selected vm details and loss counters.
func TestInteractiveDetailPanelShowsSelectedVMDetailsAndLossCounters(t *testing.T) {
	report := attributedReport()
	source := delayedSource{delay: 10 * time.Millisecond, snapshot: Snapshot{
		ObservedAtUTC: time.Now(), StatusAvailable: true, Status: statusReport(),
		Host: hostReport(), EBPFLatencyRequested: true, EBPFLatency: &report,
	}}
	var output bytes.Buffer
	if err := RunInteractive(context.Background(), strings.NewReader("\n"), &output, source, Options{
		Duration: time.Millisecond, Interval: time.Millisecond, Every: time.Second,
		Iterations: 1, Clear: false, Sort: "ops", IncludeEBPFLatency: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Sort: ops",
		"VM PROFILE  b-stress",
		"Attributed operations: total=100 read=5 write=90 flush=3 discard=1 unknown=1",
		"Latency ms~: p50=0.500 p95=2.000 p99=5.000 max=7.000",
		"259:3 write: ops=90 p95_ms~=2.000",
		"Attribution loss: missing_bio=2 missing_blkcg=1 unmapped_cgroup=3 lookup_miss=4",
		"[Investigate VM]",
		"j/k select", "Tab/←/→ panel",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("interactive output missing %q:\n%s", want, output.String())
		}
	}
}

// TestApplicationHomePanelKeepsPersistentBranding verifies application home panel keeps persistent
// branding.
func TestApplicationHomePanelKeepsPersistentBranding(t *testing.T) {
	view, err := BuildView(Snapshot{
		ObservedAtUTC: time.Now(), StatusAvailable: true, Status: statusReport(),
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{
		Iteration: 1, Every: 7 * time.Second, UIRefresh: 200 * time.Millisecond,
		SelectedVM: "a-web", Sort: "name", Interactive: true,
		ActivePanel: panelOverview, Application: true,
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "▶  a-web") {
		t.Fatalf("home VM table is missing:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "███████╗") || !strings.Contains(output.String(), "real VM-attributed block latency") {
		t.Fatalf("application branding is not persistent:\n%s", output.String())
	}
	for _, want := range []string{"╭─ SOLIS I/O", "╭─ SESSION", "╭─ LIVE EVIDENCE", "╭─ NAVIGATION", "╭─ VIRTUAL MACHINES", "│  QEMU_PRESSURE"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("designed application frame missing %q:\n%s", want, output.String())
		}
	}
	for _, unexpected := range []string{"VM PROFILE", "Recent derived events", "MONITOR                       live host"} {
		if strings.Contains(output.String(), unexpected) {
			t.Fatalf("compact home unexpectedly contains %q:\n%s", unexpected, output.String())
		}
	}
}

// TestApplicationKeepsFullWordmarkOnWideShortTerminal verifies application keeps full wordmark on
// wide short terminal.
func TestApplicationKeepsFullWordmarkOnWideShortTerminal(t *testing.T) {
	view, err := BuildView(Snapshot{
		ObservedAtUTC: time.Now(), StatusAvailable: true, Status: statusReport(),
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{
		Iteration: 1, Every: 7 * time.Second, SelectedVM: "a-web", Sort: "name",
		Interactive: true, ActivePanel: panelOverview, Application: true,
		Width: 180, Height: 42,
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"╭─ SOLIS I/O", "███████╗", "real VM-attributed block latency", "╭─ VIRTUAL MACHINES", "↑/↓ SELECT"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("short-terminal design missing %q:\n%s", want, output.String())
		}
	}
}

// TestApplicationHeaderShowsBoundedSolisProcessResources verifies application header shows bounded
// solis process resources.
func TestApplicationHeaderShowsBoundedSolisProcessResources(t *testing.T) {
	view, err := BuildView(Snapshot{
		ObservedAtUTC: time.Now(), StatusAvailable: true, Status: statusReport(),
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{
		Iteration: 1, Every: 7 * time.Second, SelectedVM: "a-web", Sort: "name",
		Interactive: true, ActivePanel: panelOverview, Application: true,
		Width: 180, Height: 42,
		ProcessResources: ProcessResources{
			CPUPercent: 2.5, CPUAvailable: true,
			RSSBytes: 32 * 1024 * 1024, MemoryAvailable: true,
			ReadBytesPerSecond: 1536, WriteBytesPerSecond: 2 * 1024 * 1024, DiskIOAvailable: true,
			Goroutines: 12, Uptime: 65 * time.Second,
		},
	}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{
		"SOLIS PROCESS", "2.5% of one core", "32.0 MiB RSS", "DISK READ  1.5 KiB/s",
		"DISK WRITE 2.0 MiB/s", "12 goroutines", "1m05s", "Scope: current Solis process only",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("process-resource header missing %q:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"cmdline", "environ", "/proc/", "0xffff", "request_pointer"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("process-resource header leaked forbidden value %q:\n%s", forbidden, text)
		}
	}
}

// TestParseSelfDiskIOUsesOnlyAggregateByteCounters verifies parse self disk io uses only aggregate
// byte counters.
func TestParseSelfDiskIOUsesOnlyAggregateByteCounters(t *testing.T) {
	readBytes, writeBytes, ok := parseSelfDiskIO("rchar: 99\nwchar: 101\nread_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 0\n")
	if !ok || readBytes != 4096 || writeBytes != 8192 {
		t.Fatalf("parseSelfDiskIO() = (%d, %d, %t)", readBytes, writeBytes, ok)
	}
	if _, _, ok := parseSelfDiskIO("read_bytes: 4096\n"); ok {
		t.Fatal("partial process disk counters were accepted")
	}
}

// TestProcessResourceMeterReadsCurrentSolisAggregates verifies process resource meter reads current
// solis aggregates.
func TestProcessResourceMeterReadsCurrentSolisAggregates(t *testing.T) {
	now := time.Now()
	meter := newProcessResourceMeter(now.Add(-time.Second))
	resources := meter.Sample(now)
	if !resources.CPUAvailable {
		t.Fatal("current Solis CPU accounting is unavailable")
	}
	if !resources.MemoryAvailable || resources.RSSBytes == 0 {
		t.Fatalf("current Solis RSS = %d, available=%t", resources.RSSBytes, resources.MemoryAvailable)
	}
	if !resources.DiskIOAvailable {
		t.Fatal("current Solis aggregate disk-I/O accounting is unavailable")
	}
	if resources.Goroutines < 1 || resources.Uptime < time.Second {
		t.Fatalf("current Solis runtime = goroutines:%d uptime:%s", resources.Goroutines, resources.Uptime)
	}
}

// TestApplicationCommandCenterExposesFixedProductWorkflows verifies application command center
// exposes fixed product workflows.
func TestApplicationCommandCenterExposesFixedProductWorkflows(t *testing.T) {
	view, err := BuildView(Snapshot{
		ObservedAtUTC: time.Now(), Inventory: []InventoryVM{{Name: "a-web", State: "running"}},
		StatusAvailable: true, Status: statusReport(),
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{
		Iteration: 1, Every: 7 * time.Second, SelectedVM: "a-web", Sort: "name",
		Interactive: true, ActivePanel: panelWorkflows, SelectedWorkflow: 1, Application: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"███████╗", "[4 COMMANDS]",
		"COMMAND CENTER", "Selected VM: a-web", "▶  Capture evidence bundle",
		"Investigate selected VM", "Watch selected VM", "Observe selected VM",
		"System doctor", "eBPF doctor", "VM inventory", "Current status", "Version and build",
		"no shell execution", "private capture writer",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("command center missing %q:\n%s", want, output.String())
		}
	}
	for _, forbidden := range []string{"request_pointer", "0xffff", "cmdline", "/proc/"} {
		if strings.Contains(strings.ToLower(output.String()), forbidden) {
			t.Fatalf("command center contains forbidden value %q:\n%s", forbidden, output.String())
		}
	}
}

// TestApplicationUsesCompactLayoutAfterNarrowTerminalResize verifies application uses compact
// layout after narrow terminal resize.
func TestApplicationUsesCompactLayoutAfterNarrowTerminalResize(t *testing.T) {
	report := attributedReport()
	view, err := BuildView(Snapshot{
		ObservedAtUTC: time.Now(), StatusAvailable: true, Status: statusReport(),
		Host: hostReport(), EBPFLatencyRequested: true, EBPFLatency: &report,
	}, "pressure")
	if err != nil {
		t.Fatal(err)
	}
	var home bytes.Buffer
	if err := WriteFrame(&home, view, Frame{
		Iteration: 1, Every: 7 * time.Second, UIRefresh: 200 * time.Millisecond,
		SelectedVM: "b-stress", Sort: "pressure", Interactive: true,
		ActivePanel: panelOverview, Application: true, Width: 90,
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SOLIS I/O", "LIVE KVM STORAGE", "Cadence: 7s", "Host pressure:", "Storage ops:", "STATE", "QEMU", "1-4 panels"} {
		if !strings.Contains(home.String(), want) {
			t.Errorf("compact home missing %q:\n%s", want, home.String())
		}
	}
	for _, unwanted := range []string{"███████╗", "QEMU_PRESSURE", "TENANT  ROLE"} {
		if strings.Contains(home.String(), unwanted) {
			t.Errorf("compact home contains wide-only content %q:\n%s", unwanted, home.String())
		}
	}

	var commands bytes.Buffer
	if err := WriteFrame(&commands, view, Frame{
		Iteration: 1, Every: 7 * time.Second, SelectedVM: "b-stress", Sort: "pressure",
		Interactive: true, ActivePanel: panelWorkflows, Application: true, Width: 90,
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Selected action:", "More CLI:", "Only Bundle writes output"} {
		if !strings.Contains(commands.String(), want) {
			t.Errorf("compact command center missing %q:\n%s", want, commands.String())
		}
	}
}

// TestApplicationRunsWorkflowInsideConsoleAndResumesCollection verifies application runs workflow
// inside console and resumes collection.
func TestApplicationRunsWorkflowInsideConsoleAndResumesCollection(t *testing.T) {
	source := &resumableCleanupSource{firstCleaned: make(chan struct{}), resumed: make(chan struct{})}
	input, inputWriter := io.Pipe()
	output := &workflowSignalWriter{complete: make(chan struct{})}
	workflowStarted := make(chan LaunchRequest, 1)
	releaseWorkflow := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- RunInteractive(context.Background(), input, output, source, Options{
			Duration: time.Second, Interval: time.Second, Every: time.Second, Clear: false, Sort: "name", Application: true,
			RunWorkflow: func(_ context.Context, request LaunchRequest) (WorkflowResult, error) {
				workflowStarted <- request
				<-releaseWorkflow
				return WorkflowResult{Output: "doctor result: ready"}, nil
			},
		})
	}()
	if _, err := io.WriteString(inputWriter, "4jjjj\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case request := <-workflowStarted:
		if request.Workflow != WorkflowDoctor || request.VM != "" {
			t.Fatalf("workflow request = %#v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("workflow did not start")
	}
	select {
	case <-source.firstCleaned:
	case <-time.After(time.Second):
		t.Fatal("workflow started before live collector cleanup")
	}
	close(releaseWorkflow)
	select {
	case <-output.complete:
	case <-time.After(time.Second):
		t.Fatalf("completed workflow output was not rendered inside the console:\n%s", output.String())
	}
	if _, err := io.WriteString(inputWriter, "b"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-source.resumed:
	case <-time.After(time.Second):
		t.Fatal("live collection did not resume after returning from workflow output")
	}
	if _, err := io.WriteString(inputWriter, "q"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "doctor result: ready") {
		t.Fatalf("embedded workflow output missing result:\n%s", output.String())
	}
}

// TestWorkflowOutputPanelNeutralizesControlsAndKeepsApplicationActive verifies workflow output
// panel neutralizes controls and keeps application active.
func TestWorkflowOutputPanelNeutralizesControlsAndKeepsApplicationActive(t *testing.T) {
	var output bytes.Buffer
	if err := WriteFrame(&output, View{Duration: "5s", Interval: "1s"}, Frame{
		Interactive: true, Application: true, ActivePanel: panelWorkflowOutput,
		WorkflowRequest: LaunchRequest{Workflow: WorkflowDoctor},
		WorkflowOutput:  "ready\x1b[31m\nsecond line",
		Width:           100,
		Height:          30,
	}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"SOLIS I/O", "[4 OUTPUT]", "DOCTOR  •  COMPLETE", "ready?[31m", "second line", "↑/k up", "b resumes the live monitor"} {
		if !strings.Contains(text, want) {
			t.Errorf("workflow output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\x1b") {
		t.Fatalf("workflow output retained terminal escape sequence:\n%q", text)
	}
}

// TestWorkflowOutputPanelAlwaysShowsScrollPositionAndKeys verifies workflow output panel always
// shows scroll position and keys.
func TestWorkflowOutputPanelAlwaysShowsScrollPositionAndKeys(t *testing.T) {
	var output bytes.Buffer
	workflowOutput := strings.Join([]string{
		"line-01", "line-02", "line-03", "line-04", "line-05",
		"line-06", "line-07", "line-08", "line-09", "line-10",
	}, "\n")
	if err := WriteFrame(&output, View{Duration: "5s", Interval: "1s"}, Frame{
		Interactive: true, Application: true, ActivePanel: panelWorkflowOutput,
		WorkflowRequest: LaunchRequest{Workflow: WorkflowObserve, VM: "a-web"},
		WorkflowOutput:  workflowOutput,
		WorkflowScroll:  2,
		Width:           100,
		Height:          20,
	}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"line-03", "line-06", "SCROLL", "↑/k up", "↓/j down", "lines 3-6 of 10"} {
		if !strings.Contains(text, want) {
			t.Errorf("scrolling workflow output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "line-01") || strings.Contains(text, "line-07") {
		t.Fatalf("workflow output ignored bounded viewport:\n%s", text)
	}
}

// TestObserveSummaryOffersExplicitPrivateDetailSave verifies observe summary offers explicit
// private detail save.
func TestObserveSummaryOffersExplicitPrivateDetailSave(t *testing.T) {
	var output bytes.Buffer
	if err := WriteFrame(&output, View{Duration: "5s", Interval: "1s"}, Frame{
		Interactive: true, Application: true, ActivePanel: panelWorkflowOutput,
		WorkflowRequest: LaunchRequest{Workflow: WorkflowObserve, VM: "a-web"},
		WorkflowOutput:  "OBSERVATION SUMMARY\nEvidence quality: measured",
		WorkflowDetail:  true,
		Width:           160,
		Height:          40,
	}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{
		"OBSERVATION SUMMARY  •  COMPLETE",
		"Evidence quality: measured",
		"Full JSON is held in memory and has not been written",
		"SAVE DETAILED OBSERVATION?  s yes",
		"b no, discard and return",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Observe result missing %q:\n%s", want, text)
		}
	}
}

// TestObserveSummaryReportsSavedDetailPath verifies observe summary reports saved detail path.
func TestObserveSummaryReportsSavedDetailPath(t *testing.T) {
	var output bytes.Buffer
	if err := WriteFrame(&output, View{Duration: "5s", Interval: "1s"}, Frame{
		Interactive: true, Application: true, ActivePanel: panelWorkflowOutput,
		WorkflowRequest:   LaunchRequest{Workflow: WorkflowObserve, VM: "a-web"},
		WorkflowOutput:    "OBSERVATION SUMMARY",
		WorkflowDetail:    true,
		WorkflowSavedPath: "/safe/captures/observe-a-web.json",
		Width:             160,
		Height:            40,
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "SAVED privately (0600): /safe/captures/observe-a-web.json") {
		t.Fatalf("saved detail path is not visible:\n%s", output.String())
	}
}

// TestTerminalColorThemeIsSemanticAndOptIn verifies terminal color theme is semantic and opt in.
func TestTerminalColorThemeIsSemanticAndOptIn(t *testing.T) {
	plain := "╭─ LIVE EVIDENCE ─╮\n│ VM attribution: AVAILABLE  pressure: HIGH │\n│ ▶ b-stress RUNNING │\n"
	styled := colorizeApplicationFrame(plain)
	if !strings.Contains(styled, "\x1b[") || !strings.Contains(styled, "\x1b[32mAVAILABLE") || !strings.Contains(styled, "\x1b[31mHIGH") {
		t.Fatalf("semantic terminal colors missing: %q", styled)
	}
	if strings.Contains(plain, "\x1b[") {
		t.Fatalf("plain frame unexpectedly contains terminal color: %q", plain)
	}
}

// TestApplicationInvestigatesAnySelectedVMWithHistoryAndPeers verifies application investigates any
// selected vm with history and peers.
func TestApplicationInvestigatesAnySelectedVMWithHistoryAndPeers(t *testing.T) {
	report := attributedReport()
	view, err := BuildView(Snapshot{
		ObservedAtUTC:   time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC),
		CompletedAtUTC:  time.Date(2026, 8, 14, 10, 0, 3, 0, time.UTC),
		StatusAvailable: true, Status: statusReport(),
		EBPFLatencyRequested: true, EBPFLatency: &report,
	}, "ops")
	if err != nil {
		t.Fatal(err)
	}
	history := []VMInvestigationSample{
		{CompletedAtUTC: time.Date(2026, 8, 14, 9, 59, 56, 0, time.UTC), Pressure: "high", WriteMiBPerSecond: 48, WriteAvailable: true, AttributedOps: 90, LatencyP95MS: 1, AttributionAvailable: true, AttributionState: "available"},
		{CompletedAtUTC: view.CompletedAtUTC, Pressure: "high", WriteMiBPerSecond: 50, WriteAvailable: true, AttributedOps: 100, LatencyP95MS: 2, AttributionAvailable: true, AttributionState: "available"},
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{
		Iteration: 2, Every: 7 * time.Second, UIRefresh: 200 * time.Millisecond,
		SelectedVM: "b-stress", Sort: "ops", Interactive: true,
		ActivePanel: panelDetails, History: history, Application: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"INVESTIGATE  b-stress", "eBPF: state=available ops=100 share=100.00%",
		"Operations: read=5 write=90 flush=3 discard=1 unknown=1",
		"Recent completed evidence windows:", "09:59:56", "10:00:03",
		"Storage peers on /dev/nvme0n1:", "- a-web",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("investigation output missing %q:\n%s", want, output.String())
		}
	}
	for _, forbidden := range []string{"request_pointer", "0xffff", "cmdline", "/proc/"} {
		if strings.Contains(strings.ToLower(output.String()), forbidden) {
			t.Fatalf("investigation output contains %q:\n%s", forbidden, output.String())
		}
	}
}

// TestVMInvestigationHistoryIsBoundedPerVM verifies vm investigation history is bounded per vm.
func TestVMInvestigationHistoryIsBoundedPerVM(t *testing.T) {
	var tracker vmHistoryTracker
	started := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	for index := 0; index < maxVMInvestigationSamples+3; index++ {
		tracker.Update(View{
			CompletedAtUTC: started.Add(time.Duration(index) * time.Second),
			Rows:           []VMRow{{Name: "chosen-vm", Running: true, Pressure: "idle", AttributedOps: uint64(index), AttributionAvailable: true}},
		})
	}
	history := tracker.ForVM("chosen-vm")
	if len(history) != maxVMInvestigationSamples {
		t.Fatalf("history length = %d, want %d", len(history), maxVMInvestigationSamples)
	}
	if history[0].AttributedOps != 3 || history[len(history)-1].AttributedOps != maxVMInvestigationSamples+2 {
		t.Fatalf("bounded history = %#v", history)
	}
	if len(tracker.ForVM("another-vm")) != 0 {
		t.Fatal("history leaked across VM selection")
	}
}

// TestApplicationUIRefreshesWhileBoundedCollectionRuns verifies application ui refreshes while
// bounded collection runs.
func TestApplicationUIRefreshesWhileBoundedCollectionRuns(t *testing.T) {
	now := time.Now().UTC()
	source := delayedSource{
		delay: 250 * time.Millisecond,
		snapshot: Snapshot{
			ObservedAtUTC: now, CompletedAtUTC: now.Add(250 * time.Millisecond),
			StatusAvailable: true, Status: statusReport(),
		},
	}
	var output bytes.Buffer
	if err := RunInteractive(context.Background(), bytes.NewReader(nil), &output, source, Options{
		Duration: time.Second, Interval: time.Second, Every: 2 * time.Second,
		UIRefresh: 100 * time.Millisecond, Iterations: 1, Clear: false, Sort: "name", Application: true,
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), "Sampling: COLLECTING") < 2 {
		t.Fatalf("application did not redraw its collection state at the UI cadence:\n%s", output.String())
	}
	for _, want := range []string{
		"Discovering configured VMs", "Sampling: READY", "Evidence cadence: 2s", "UI refresh: 100ms", "Data age:",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("application output missing %q:\n%s", want, output.String())
		}
	}
}

// TestApplicationScreenUsesAlternateBufferAndRestoresCursor verifies application screen uses
// alternate buffer and restores cursor.
func TestApplicationScreenUsesAlternateBufferAndRestoresCursor(t *testing.T) {
	var output bytes.Buffer
	restore, err := EnterApplicationScreen(&output)
	if err != nil {
		t.Fatal(err)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H\x1b[?25h\x1b[?1049l"; got != want {
		t.Fatalf("terminal application sequences = %q, want %q", got, want)
	}
}

// TestSamplingStatusShowsProgressAndReadyCountdown verifies sampling status shows progress and
// ready countdown.
func TestSamplingStatusShowsProgressAndReadyCountdown(t *testing.T) {
	started := time.Date(2026, 8, 13, 22, 0, 0, 0, time.UTC)
	progress := samplingStatus(Frame{
		Collecting: true, CollectionStarted: started, WindowDuration: 5 * time.Second,
	}, started.Add(2*time.Second))
	if progress != "COLLECTING [====      ] 2s/5s" {
		t.Fatalf("progress = %q", progress)
	}
	ready := samplingStatus(Frame{NextCollectionAt: started.Add(7 * time.Second)}, started.Add(5*time.Second))
	if ready != "READY  next evidence window in 2s" {
		t.Fatalf("ready = %q", ready)
	}
}

// TestApplicationRendersEachFrameWithOneBufferedWrite verifies application renders each frame with
// one buffered write.
func TestApplicationRendersEachFrameWithOneBufferedWrite(t *testing.T) {
	source := &fakeSource{snapshot: Snapshot{
		ObservedAtUTC: time.Now(), StatusAvailable: true, Status: statusReport(),
	}}
	var output countingWriter
	if err := RunInteractive(context.Background(), bytes.NewReader(nil), &output, source, Options{
		Duration: time.Millisecond, Interval: time.Millisecond, Every: time.Second,
		Iterations: 1, Clear: true, Sort: "name", Application: true,
	}); err != nil {
		t.Fatal(err)
	}
	if output.writes != 2 {
		t.Fatalf("write calls = %d, want one initial frame and one completed frame", output.writes)
	}
	if strings.Count(output.String(), "\x1b[H") != 2 {
		t.Fatalf("buffered frames did not each start at terminal home: %q", output.String())
	}
	if strings.Count(output.String(), "real VM-attributed block latency") != 2 {
		t.Fatalf("persistent wordmark was not rendered in every application frame: %q", output.String())
	}
	if !strings.Contains(output.String(), "\x1b[2K\r") || strings.Count(output.String(), "\x1b[J") != 2 {
		t.Fatalf("application did not erase each repainted row and the unused rows below it: %q", output.String())
	}
	if strings.Contains(output.String(), "\x1b[2J") {
		t.Fatalf("application used a flashing full-screen clear during buffered repaint: %q", output.String())
	}
}

// TestKeyActionsAndSelection verifies key actions and selection.
func TestKeyActionsAndSelection(t *testing.T) {
	actions := readKeyActions(strings.NewReader("j\x1b[Akpnworl?\t\nbs\x1b[C\x1b[D1234"))
	var got []keyAction
	for action := range actions {
		got = append(got, action)
	}
	want := []keyAction{
		keyDown, keyUp, keyUp, keySortPressure, keySortName, keySortWrite, keySortOps,
		keyRefresh, keySortLatency, keyHelp, keyNextPanel, keyOpenPanel, keyBack, keySaveDetail,
		keyNextPanel, keyPreviousPanel, keyHomePanel, keyDetailsPanel, keyEventsPanel, keyWorkflowsPanel,
	}
	if len(got) != len(want) {
		t.Fatalf("actions = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("actions[%d] = %v, want %v", index, got[index], want[index])
		}
	}

	view := View{Rows: []VMRow{{Name: "a"}, {Name: "b"}, {Name: "c"}}}
	state := interactiveState{selectedVM: "a", sort: "name", application: true}
	applyInteractiveAction(&view, &state, keyUp)
	if state.selectedVM != "c" {
		t.Fatalf("wrapped up selection = %q", state.selectedVM)
	}
	applyInteractiveAction(&view, &state, keyDown)
	if state.selectedVM != "a" {
		t.Fatalf("wrapped down selection = %q", state.selectedVM)
	}
	applyInteractiveAction(&view, &state, keyNextPanel)
	if state.panel != panelDetails {
		t.Fatalf("next panel = %q", state.panel)
	}
	applyInteractiveAction(&view, &state, keyNextPanel)
	if state.panel != panelEvents {
		t.Fatalf("next panel = %q", state.panel)
	}
	applyInteractiveAction(&view, &state, keyPreviousPanel)
	if state.panel != panelDetails {
		t.Fatalf("previous panel = %q", state.panel)
	}
	applyInteractiveAction(&view, &state, keyBack)
	if state.panel != panelOverview {
		t.Fatalf("back panel = %q", state.panel)
	}
	applyInteractiveAction(&view, &state, keyOpenPanel)
	if state.panel != panelDetails {
		t.Fatalf("open panel = %q", state.panel)
	}
	applyInteractiveAction(&view, &state, keyWorkflowsPanel)
	if state.panel != panelWorkflows {
		t.Fatalf("workflow panel = %q", state.panel)
	}
	applyInteractiveAction(&view, &state, keyDown)
	if state.selectedWorkflow != 1 {
		t.Fatalf("selected workflow = %d", state.selectedWorkflow)
	}
}

// TestDerivedEventsTrackBoundedSafeStateChanges verifies derived events track bounded safe state
// changes.
func TestDerivedEventsTrackBoundedSafeStateChanges(t *testing.T) {
	report := attributedReport()
	initial, err := BuildView(Snapshot{
		ObservedAtUTC:   time.Date(2026, 8, 13, 20, 0, 0, 0, time.UTC),
		StatusAvailable: true, Status: statusReport(), EBPFLatencyRequested: true, EBPFLatency: &report,
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	var tracker eventTracker
	events := tracker.Update(initial)
	joined := renderedEvents(t, events)
	for _, want := range []string{
		"monitoring window collected",
		"b-stress", "QEMU write pressure is high",
		"VM attribution is available", "dominant attributed I/O",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("initial events missing %q:\n%s", want, joined)
		}
	}

	for index := 1; index <= maxMonitorEvents+5; index++ {
		next := initial
		next.ObservedAtUTC = initial.ObservedAtUTC.Add(time.Duration(index) * time.Second)
		next.Rows = append([]VMRow(nil), initial.Rows...)
		for rowIndex := range next.Rows {
			if next.Rows[rowIndex].Name == "b-stress" {
				if index%2 == 0 {
					next.Rows[rowIndex].Pressure = "high"
				} else {
					next.Rows[rowIndex].Pressure = "idle"
				}
			}
		}
		events = tracker.Update(next)
	}
	if len(events) != maxMonitorEvents {
		t.Fatalf("event count = %d, want bounded %d", len(events), maxMonitorEvents)
	}
	joined = renderedEvents(t, events)
	for _, forbidden := range []string{"request_pointer", "0xffff", "cmdline", "/proc/"} {
		if strings.Contains(strings.ToLower(joined), forbidden) {
			t.Fatalf("events contain forbidden value %q:\n%s", forbidden, joined)
		}
	}
}

// TestDerivedEventsDistinguishVMRuntimeStateFromPressure verifies derived events distinguish vm
// runtime state from pressure.
func TestDerivedEventsDistinguishVMRuntimeStateFromPressure(t *testing.T) {
	initial := View{ObservedAtUTC: time.Now(), Rows: []VMRow{{Name: "a-web", State: "running", Running: true, Pressure: "idle"}}}
	next := View{ObservedAtUTC: initial.ObservedAtUTC.Add(time.Second), Rows: []VMRow{{Name: "a-web", State: "shut off", Running: false, Pressure: "not_running"}}}
	var tracker eventTracker
	tracker.Update(initial)
	output := renderedEvents(t, tracker.Update(next))
	if !strings.Contains(output, "VM runtime state changed from running to shut off") {
		t.Fatalf("state event missing:\n%s", output)
	}
	if strings.Contains(output, "write pressure changed") {
		t.Fatalf("runtime state was mislabeled as pressure:\n%s", output)
	}
}

// TestEventPanelRendersOnlyBoundedDerivedEvents verifies event panel renders only bounded derived
// events.
func TestEventPanelRendersOnlyBoundedDerivedEvents(t *testing.T) {
	view, err := BuildView(Snapshot{
		ObservedAtUTC: time.Now(), StatusAvailable: true, Status: statusReport(),
	}, "name")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteFrame(&output, view, Frame{
		Iteration: 1, Every: time.Second, SelectedVM: "a-web", Sort: "name",
		Interactive: true, ActivePanel: panelEvents,
		Events: []MonitorEvent{{ObservedAtUTC: time.Date(2026, 8, 13, 20, 1, 2, 0, time.UTC), Severity: "info", Subject: "a-web", Message: "QEMU write pressure changed from low to idle"}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Events]", "20:01:02", "a-web", "not raw kernel events"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("event panel missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "ATTR_OPS") || strings.Contains(output.String(), "Selected VM:") {
		t.Fatalf("event panel unexpectedly rendered another panel:\n%s", output.String())
	}
}

// renderedEvents renders ed events for presentation.
func renderedEvents(t *testing.T, events []MonitorEvent) string {
	t.Helper()
	var output bytes.Buffer
	if err := writeEvents(&output, events, maxMonitorEvents); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

// TestInteractiveQuitWaitsForCollectionCleanup verifies interactive quit waits for collection
// cleanup.
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

// TestRunUsesBoundedRefreshesWithoutClearSequences verifies run uses bounded refreshes without
// clear sequences.
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

// TestRunTreatsContextCancellationAsCleanStop verifies run treats context cancellation as clean
// stop.
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

type countingWriter struct {
	bytes.Buffer
	writes int
}

// Write writes the value to its configured destination and propagates write failures.
func (writer *countingWriter) Write(data []byte) (int, error) {
	writer.writes++
	return writer.Buffer.Write(data)
}

// WriteString renders string in the package's stable operator-facing format.
func (writer *countingWriter) WriteString(data string) (int, error) {
	writer.writes++
	return writer.Buffer.WriteString(data)
}

type delayedSource struct {
	delay    time.Duration
	snapshot Snapshot
}

// Collect collects bounded evidence from the configured source and propagates source failures.
func (source delayedSource) Collect(ctx context.Context, _ CollectRequest) (Snapshot, error) {
	timer := time.NewTimer(source.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	case <-timer.C:
		return source.snapshot, nil
	}
}

// Collect collects bounded evidence from the configured source and propagates source failures.
func (source *fakeSource) Collect(_ context.Context, _ CollectRequest) (Snapshot, error) {
	source.calls++
	return source.snapshot, nil
}

type cancelSource struct{}

// Collect collects bounded evidence from the configured source and propagates source failures.
func (cancelSource) Collect(ctx context.Context, _ CollectRequest) (Snapshot, error) {
	<-ctx.Done()
	return Snapshot{}, errors.New("wrapped: " + ctx.Err().Error())
}

type cleanupSource struct {
	started chan struct{}
	cleaned chan struct{}
}

// Collect collects bounded evidence from the configured source and propagates source failures.
func (source *cleanupSource) Collect(ctx context.Context, _ CollectRequest) (Snapshot, error) {
	close(source.started)
	<-ctx.Done()
	close(source.cleaned)
	return Snapshot{}, ctx.Err()
}

type resumableCleanupSource struct {
	calls        int
	firstCleaned chan struct{}
	resumed      chan struct{}
}

// Collect collects bounded evidence from the configured source and propagates source failures.
func (source *resumableCleanupSource) Collect(ctx context.Context, _ CollectRequest) (Snapshot, error) {
	source.calls++
	call := source.calls
	if call == 2 {
		close(source.resumed)
	}
	<-ctx.Done()
	if call == 1 {
		close(source.firstCleaned)
	}
	return Snapshot{}, ctx.Err()
}

type workflowSignalWriter struct {
	bytes.Buffer
	complete chan struct{}
	once     sync.Once
}

// Write writes the value to its configured destination and propagates write failures.
func (writer *workflowSignalWriter) Write(value []byte) (int, error) {
	writer.signalComplete(string(value))
	return writer.Buffer.Write(value)
}

// WriteString renders string in the package's stable operator-facing format.
func (writer *workflowSignalWriter) WriteString(value string) (int, error) {
	writer.signalComplete(value)
	return writer.Buffer.WriteString(value)
}

// signalComplete performs signal complete as part of the package workflow.
func (writer *workflowSignalWriter) signalComplete(value string) {
	if strings.Contains(value, "WORKFLOW OUTPUT  •  DOCTOR  •  COMPLETE") {
		writer.once.Do(func() { close(writer.complete) })
	}
}

// statusReport builds status report from validated inputs.
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

// attributedReport builds attributed report from validated inputs.
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

// hostReport builds host report from validated inputs.
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
