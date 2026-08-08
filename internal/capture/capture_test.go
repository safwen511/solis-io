package capture

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/diagnose"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/experiment"
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
	}
	for _, line := range wantLines {
		if !strings.Contains(output.String(), line) {
			t.Errorf("metadata missing %q:\n%s", line, output.String())
		}
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
