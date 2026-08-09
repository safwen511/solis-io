package capture

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/diagnose"
	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/experiment"
	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
)

func TestCaptureDirectoryName(t *testing.T) {
	now := time.Date(2026, 8, 8, 23, 15, 0, 0, time.FixedZone("UTC+2", 2*60*60))
	want := "capture-20260808T211500Z-tenant-a-b-stress"
	if got := captureDirectoryName(now, "tenant-a", "b-stress"); got != want {
		t.Fatalf("captureDirectoryName() = %q, want %q", got, want)
	}
}

func TestCaptureDirectoryNameSanitizesSelectors(t *testing.T) {
	now := time.Date(2026, 8, 8, 21, 15, 0, 0, time.UTC)
	want := "capture-20260808T211500Z-tenant_a-b_stress_"
	if got := captureDirectoryName(now, "tenant/a", "b stress!"); got != want {
		t.Fatalf("captureDirectoryName() = %q, want %q", got, want)
	}
}

func TestWriteMetadata(t *testing.T) {
	inputs := Inputs{
		ReportDirectory: "lab/reports/workload/example",
		Victim:          "tenant-a",
		Suspect:         "b-stress",
		Duration:        10 * time.Second,
		Interval:        2 * time.Second,
	}
	var output bytes.Buffer
	if err := WriteMetadata(&output, inputs, "20260808T211500Z"); err != nil {
		t.Fatalf("WriteMetadata() error = %v", err)
	}

	wantLines := []string{
		"Capture timestamp UTC: 20260808T211500Z",
		"Report directory: lab/reports/workload/example",
		"Victim: tenant-a",
		"Suspect: b-stress",
		"Duration: 10s",
		"Interval: 2s",
		"Solis command: solis capture noisy-neighbor",
		"Capture mode: pairwise",
		"Selected suspect: b-stress",
		"eBPF latency requested: no",
		"eBPF latency file written: no",
		"Discovery file: -",
	}
	for _, line := range wantLines {
		if !strings.Contains(output.String(), line) {
			t.Errorf("metadata missing %q:\n%s", line, output.String())
		}
	}
}

func TestPairwiseCaptureFileSetRemainsUnchanged(t *testing.T) {
	inputs := testCaptureInputs(t.TempDir())
	inputs.IncludeEBPFLatency = false
	evidence := testCaptureEvidence(nil)
	result, err := Write(inputs, evidence, time.Date(2026, 8, 8, 21, 14, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"experiment-summary.txt",
		"incident-explanation.txt",
		"trace-plan.txt",
		"storage-snapshot.txt",
		"qemu-io-summary.txt",
		"diagnosis.txt",
		"metadata.txt",
	}
	if len(result.Files) != len(want) {
		t.Fatalf("files = %v, want %v", result.Files, want)
	}
	for index, name := range want {
		if filepath.Base(result.Files[index]) != name {
			t.Fatalf("file %d = %q, want %q", index, filepath.Base(result.Files[index]), name)
		}
	}
}

func TestDiscoveryCaptureWritesDiscoveryAndSelectedSuspectMetadata(t *testing.T) {
	inputs := testCaptureInputs(t.TempDir())
	inputs.CaptureMode = "discover-suspects"
	discoveryReport := selectedDiscoveryReport()
	evidence := testCaptureEvidence(nil)
	evidence.Discovery = &discoveryReport
	evidence.Diagnosis.Discovery = &discoveryReport
	result, err := Write(inputs, evidence, time.Date(2026, 8, 8, 21, 17, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	discoveryContent, err := os.ReadFile(filepath.Join(result.Directory, "suspect-discovery.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(discoveryContent), "Selected suspect:") || !strings.Contains(string(discoveryContent), "b-stress") {
		t.Fatalf("discovery artifact missing selected suspect:\n%s", discoveryContent)
	}
	metadata, err := os.ReadFile(filepath.Join(result.Directory, "metadata.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Capture mode: discover-suspects",
		"Selected suspect: b-stress",
		"Discovery file: suspect-discovery.txt",
	} {
		if !strings.Contains(string(metadata), want) {
			t.Errorf("metadata missing %q:\n%s", want, metadata)
		}
	}
}

func TestDiscoveryCaptureSucceedsWithoutSelectedSuspect(t *testing.T) {
	inputs := testCaptureInputs(t.TempDir())
	inputs.CaptureMode = "discover-suspects"
	inputs.Suspect = "-"
	inputs.IncludeEBPFLatency = false
	discoveryReport := discovery.Report{
		Victim:          inventory.VM{Name: "a-web"},
		VictimStorage:   hoststorage.Mapping{PhysicalDisk: "/dev/nvme0n1"},
		SelectionReason: "no dominant writer observed",
	}
	evidence := testCaptureEvidence(nil)
	evidence.Discovery = &discoveryReport
	evidence.Diagnosis.Discovery = &discoveryReport
	evidence.Diagnosis.Inputs.Suspect = "-"
	evidence.Diagnosis.Verdict = diagnose.NoDominantCandidateVerdict
	result, err := Write(inputs, evidence, time.Date(2026, 8, 8, 21, 18, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"experiment-summary.txt",
		"incident-explanation.txt",
		"victim-topology.txt",
		"storage-snapshot.txt",
		"qemu-io-summary.txt",
		"suspect-discovery.txt",
		"diagnosis.txt",
		"metadata.txt",
	} {
		if _, err := os.Stat(filepath.Join(result.Directory, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(result.Directory, "trace-plan.txt")); !os.IsNotExist(err) {
		t.Fatalf("trace-plan.txt exists in no-selection capture: %v", err)
	}
	metadata, err := os.ReadFile(filepath.Join(result.Directory, "metadata.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(metadata), "Selected suspect: -") {
		t.Fatalf("metadata missing empty selection:\n%s", metadata)
	}
}

func TestDiscoveryCaptureHandlesEBPFUnavailableAsWarning(t *testing.T) {
	inputs := testCaptureInputs(t.TempDir())
	inputs.CaptureMode = "discover-suspects"
	discoveryReport := selectedDiscoveryReport()
	latency := ebpf.BlockLatencyEvidence{UnavailableReason: "permission denied loading eBPF"}
	evidence := testCaptureEvidence(&latency)
	evidence.Discovery = &discoveryReport
	evidence.Diagnosis.Discovery = &discoveryReport
	result, err := Write(inputs, evidence, time.Date(2026, 8, 8, 21, 19, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(result.Directory, "ebpf-block-latency.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "eBPF block latency evidence unavailable: permission denied loading eBPF") {
		t.Fatalf("eBPF artifact missing warning:\n%s", content)
	}
	metadata, err := os.ReadFile(filepath.Join(result.Directory, "metadata.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"eBPF latency requested: yes",
		"eBPF latency file written: yes",
	} {
		if !strings.Contains(string(metadata), want) {
			t.Errorf("metadata missing %q:\n%s", want, metadata)
		}
	}
}

func TestDiscoveryCaptureWithoutSelectionRecordsVMWareEBPFWarning(t *testing.T) {
	inputs := testCaptureInputs(t.TempDir())
	inputs.CaptureMode = "discover-suspects"
	inputs.Suspect = "-"
	discoveryReport := discovery.Report{
		Victim:          inventory.VM{Name: "a-web"},
		VictimStorage:   hoststorage.Mapping{PhysicalDisk: "/dev/nvme0n1"},
		SelectionReason: "no dominant writer observed",
	}
	latency := ebpf.BlockLatencyEvidence{
		Result: ebpf.BlockLatencyResult{
			Duration:          time.Second,
			CompletedRequests: 1,
		},
		Notice: "eBPF VM-aware latency requires a selected suspect; skipping VM-aware eBPF latency.",
	}
	evidence := testCaptureEvidence(&latency)
	evidence.Discovery = &discoveryReport
	evidence.Diagnosis.Discovery = &discoveryReport
	evidence.Diagnosis.Inputs.Suspect = "-"
	result, err := Write(inputs, evidence, time.Date(2026, 8, 8, 21, 20, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(result.Directory, "ebpf-block-latency.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), latency.Notice) {
		t.Fatalf("eBPF artifact missing VM-aware warning:\n%s", content)
	}
}

func TestWriteCreatesEBPFBlockLatencyArtifact(t *testing.T) {
	latency := ebpf.BlockLatencyEvidence{Result: ebpf.BlockLatencyResult{
		Duration:          time.Second,
		CompletedRequests: 2,
		TotalLatencyNS:    200_000,
		MaxLatencyNS:      150_000,
	}}
	result, err := Write(
		testCaptureInputs(t.TempDir()),
		testCaptureEvidence(&latency),
		time.Date(2026, 8, 8, 21, 15, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(result.Directory, "ebpf-block-latency.txt")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "Total completed requests:  2") {
		t.Fatalf("eBPF artifact missing result:\n%s", content)
	}
	metadata, err := os.ReadFile(filepath.Join(result.Directory, "metadata.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(metadata), "eBPF block latency: ebpf-block-latency.txt") {
		t.Fatalf("metadata missing eBPF artifact reference:\n%s", metadata)
	}
}

func TestWriteContinuesWhenEBPFLatencyUnavailable(t *testing.T) {
	latency := ebpf.BlockLatencyEvidence{UnavailableReason: "tracepoint block:block_rq_issue not found"}
	result, err := Write(
		testCaptureInputs(t.TempDir()),
		testCaptureEvidence(&latency),
		time.Date(2026, 8, 8, 21, 16, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(result.Directory, "ebpf-block-latency.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := "eBPF block latency evidence unavailable: tracepoint block:block_rq_issue not found"
	if !strings.Contains(string(content), want) {
		t.Fatalf("eBPF artifact missing warning %q:\n%s", want, content)
	}
	diagnosis, err := os.ReadFile(filepath.Join(result.Directory, "diagnosis.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(diagnosis), want) {
		t.Fatalf("diagnosis artifact missing warning %q:\n%s", want, diagnosis)
	}
}

func testCaptureInputs(outputDirectory string) Inputs {
	return Inputs{
		OutputDirectory:    outputDirectory,
		ReportDirectory:    "report",
		Victim:             "a-web",
		Suspect:            "b-stress",
		Duration:           time.Second,
		Interval:           time.Second,
		IncludeEBPFLatency: true,
	}
}

func testCaptureEvidence(latency *ebpf.BlockLatencyEvidence) Evidence {
	experimentReport := experiment.Report{
		Directory:   "report",
		Baseline:    experiment.HTTPMetrics{RequestsPerSecond: 100, TimePerRequestMS: 10},
		DuringNoise: experiment.HTTPMetrics{RequestsPerSecond: 80, TimePerRequestMS: 12},
		PostNoise:   experiment.HTTPMetrics{RequestsPerSecond: 100, TimePerRequestMS: 10},
	}
	return Evidence{
		Experiment:  experimentReport,
		EBPFLatency: latency,
		Diagnosis: diagnose.Report{
			Experiment:  experimentReport,
			EBPFLatency: latency,
		},
	}
}

func selectedDiscoveryReport() discovery.Report {
	report := discovery.Report{
		Victim:        inventory.VM{Name: "a-web"},
		VictimStorage: hoststorage.Mapping{PhysicalDisk: "/dev/nvme0n1"},
		Candidates: []discovery.Candidate{{
			VM:         inventory.VM{Name: "b-stress", Tenant: "tenant-b", Role: "stress"},
			SharedDisk: true,
			Summary: qemuio.VMSummary{
				Available:             true,
				AverageSyscwPerSecond: 120000,
				MaxSyscwPerSecond:     140000,
			},
			Score:  "HIGH",
			Reason: "dominant syscall pressure",
		}},
		SelectionReason: "dominant syscall pressure",
	}
	report.Selected = &report.Candidates[0]
	return report
}
