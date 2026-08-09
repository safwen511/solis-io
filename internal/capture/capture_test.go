package capture

import (
	"bytes"
	"encoding/json"
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
	"github.com/safwen511/solis-io/internal/incident"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
	"github.com/safwen511/solis-io/internal/storage"
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
		"Evidence mode: report-backed",
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
		"Incident report: incident-report.md",
		"Evidence JSON: evidence-summary.json",
	}
	for _, line := range wantLines {
		if !strings.Contains(output.String(), line) {
			t.Errorf("metadata missing %q:\n%s", line, output.String())
		}
	}
}

func TestPairwiseCapturePreservesExistingFilesAndAddsIncidentReport(t *testing.T) {
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
		"evidence-summary.json",
		"incident-report.md",
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
	evidence.Diagnosis.Verdict = diagnose.ProbableVerdict
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
		"Incident report: incident-report.md",
		"Evidence JSON: evidence-summary.json",
	} {
		if !strings.Contains(string(metadata), want) {
			t.Errorf("metadata missing %q:\n%s", want, metadata)
		}
	}
	report, err := os.ReadFile(filepath.Join(result.Directory, "incident-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# Solis Noisy Neighbor Incident Report",
		"- Selected suspect: b-stress",
		"- Capture mode: discover-suspects",
		"### Experiment slowdown evidence",
		"### Shared storage topology",
		"### Suspect discovery result",
		"### QEMU writer/syscall attribution",
		"eBPF block latency is host/storage-path level, not exact per-VM attribution.",
		"QEMU io-summary is used for VM writer attribution.",
		"No guest payloads, guest files, process memory, or application contents were inspected.",
		"Consider throttling, migrating, or investigating the selected suspect VM workload (b-stress).",
		"  - incident-report.md",
		"  - evidence-summary.json",
	} {
		if !strings.Contains(string(report), want) {
			t.Errorf("incident report missing %q:\n%s", want, report)
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
		"evidence-summary.json",
		"incident-report.md",
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
	report, err := os.ReadFile(filepath.Join(result.Directory, "incident-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"- Selected suspect: -",
		"Continue monitoring or expand the observation window.",
	} {
		if !strings.Contains(string(report), want) {
			t.Errorf("incident report missing %q:\n%s", want, report)
		}
	}
}

func TestEvidenceSummaryJSONReportBackedSelectedSuspect(t *testing.T) {
	inputs := testCaptureInputs(t.TempDir())
	inputs.IncludeEBPFLatency = true
	latency := ebpf.BlockLatencyEvidence{Result: ebpf.BlockLatencyResult{
		Duration:          time.Second,
		CompletedRequests: 4,
		TotalLatencyNS:    200_000,
		MaxLatencyNS:      100_000,
		Histogram:         [10]uint64{1, 3},
	}}
	evidence := testCaptureEvidence(&latency)
	evidence.Storage.Targets = []storage.VMTarget{
		{
			TargetType: "victim",
			VM: inventory.VM{
				Name: "a-web", Tenant: "tenant-a", Role: "web", QEMUPID: "12345",
				Disk: "/images/a-web.qcow2",
			},
			Storage: hoststorage.Mapping{
				DiskPath: "/images/a-web.qcow2", SourceDevice: "/dev/dm-0",
				ParentDevice: "/dev/nvme0n1p3", PhysicalDisk: "/dev/nvme0n1",
			},
		},
		{
			TargetType: "suspect",
			VM: inventory.VM{
				Name: "b-stress", Tenant: "tenant-b", Role: "stress", QEMUPID: "12346",
				Disk: "/images/b-stress.qcow2",
			},
			Storage: hoststorage.Mapping{
				DiskPath: "/images/b-stress.qcow2", SourceDevice: "/dev/dm-0",
				ParentDevice: "/dev/nvme0n1p3", PhysicalDisk: "/dev/nvme0n1",
			},
		},
	}
	evidence.QEMU = qemuio.SummaryReport{
		VictimAverageWriteMiBPerSecond:  1.25,
		SuspectAverageWriteMiBPerSecond: 42,
		VictimAverageSyscwPerSecond:     10,
		SuspectAverageSyscwPerSecond:    120000,
		VictimDataAvailable:             true,
		SuspectDataAvailable:            true,
		MeaningfulSuspectWritePressure:  true,
		SuspectDominant:                 true,
		DominantWriter:                  "b-stress",
		DominantWriteSyscallSource:      "b-stress",
		Conclusion:                      "Suspect QEMU process is the dominant writer during the observation window.",
	}
	evidence.Diagnosis.Impact = experiment.Impact{ThroughputDropPct: 23.61, LatencyIncreasePct: 30.92}
	evidence.Diagnosis.StorageTopologyAvailable = true
	evidence.Diagnosis.SharedPhysicalDisk = true
	evidence.Diagnosis.Verdict = diagnose.ProbableVerdict
	evidence.Experiment.DuringNoise.FailedRequests = 2

	result, err := Write(inputs, evidence, time.Date(2026, 8, 9, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var summary EvidenceSummary
	content, err := os.ReadFile(filepath.Join(result.Directory, "evidence-summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &summary); err != nil {
		t.Fatalf("evidence-summary.json is invalid: %v\n%s", err, content)
	}
	if summary.SchemaVersion != "1" || summary.Capture.EvidenceMode != "report-backed" {
		t.Fatalf("capture summary = %#v", summary.Capture)
	}
	if summary.Victim.Name != "a-web" || summary.Victim.QEMUPID == nil || *summary.Victim.QEMUPID != 12345 {
		t.Fatalf("victim = %#v", summary.Victim)
	}
	if summary.SelectedSuspect.Name != "b-stress" || summary.SelectedSuspect.Score != "HIGH" {
		t.Fatalf("selected suspect = %#v", summary.SelectedSuspect)
	}
	if !summary.ExperimentEvidence.Available || summary.ExperimentEvidence.FailedRequestsDuringNoise != 2 {
		t.Fatalf("experiment evidence = %#v", summary.ExperimentEvidence)
	}
	if !summary.StorageTopology.SharedPhysicalDisk || summary.StorageTopology.PhysicalDisk != "/dev/nvme0n1" {
		t.Fatalf("storage topology = %#v", summary.StorageTopology)
	}
	if !summary.EBPFLatency.Available || summary.EBPFLatency.CompletedRequests != 4 || len(summary.EBPFLatency.Histogram) != 10 {
		t.Fatalf("eBPF evidence = %#v", summary.EBPFLatency)
	}
	if summary.Verdict.Severity != "probable" {
		t.Fatalf("verdict = %#v", summary.Verdict)
	}
	if summary.Safety.GuestPayloadsInspected || summary.Safety.GuestFilesInspected || summary.Safety.ProcessMemoryInspected {
		t.Fatalf("unsafe evidence flags = %#v", summary.Safety)
	}
}

func TestEvidenceSummaryJSONLiveOnlyWithoutSelectedSuspect(t *testing.T) {
	inputs := testCaptureInputs(t.TempDir())
	inputs.ReportDirectory = ""
	inputs.CaptureMode = "discover-suspects"
	inputs.Suspect = "-"
	inputs.IncludeEBPFLatency = false
	discoveryReport := discovery.Report{
		Victim:          inventory.VM{Name: "a-web", Tenant: "tenant-a", Role: "web"},
		VictimStorage:   hoststorage.Mapping{PhysicalDisk: "/dev/nvme0n1"},
		SelectionReason: "no dominant writer observed",
	}
	evidence := testCaptureEvidence(nil)
	evidence.Experiment = experiment.Report{}
	evidence.Discovery = &discoveryReport
	evidence.Diagnosis = diagnose.Report{
		Inputs:              diagnose.Inputs{Victim: "a-web", Suspect: "-"},
		ExperimentAvailable: false,
		Discovery:           &discoveryReport,
		Verdict:             diagnose.NoDominantLiveCandidateVerdict,
	}

	result, err := Write(inputs, evidence, time.Date(2026, 8, 9, 1, 2, 4, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var summary EvidenceSummary
	content, err := os.ReadFile(filepath.Join(result.Directory, "evidence-summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &summary); err != nil {
		t.Fatalf("evidence-summary.json is invalid: %v", err)
	}
	if summary.Capture.EvidenceMode != "live-only" || summary.Capture.ReportDir != "-" {
		t.Fatalf("capture summary = %#v", summary.Capture)
	}
	if summary.ExperimentEvidence.Available {
		t.Fatalf("experiment evidence = %#v", summary.ExperimentEvidence)
	}
	if summary.SelectedSuspect.Name != "-" || summary.Discovery.SelectedSuspect != "-" {
		t.Fatalf("selection = %#v / %#v", summary.SelectedSuspect, summary.Discovery)
	}
	if !summary.Discovery.Enabled || summary.Discovery.Candidates == nil {
		t.Fatalf("discovery = %#v", summary.Discovery)
	}
	metadata, err := os.ReadFile(filepath.Join(result.Directory, "metadata.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(metadata), "Evidence JSON: evidence-summary.json") {
		t.Fatalf("metadata missing JSON reference:\n%s", metadata)
	}
	report, err := os.ReadFile(filepath.Join(result.Directory, "incident-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "  - evidence-summary.json") {
		t.Fatalf("incident report missing JSON reference:\n%s", report)
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
	report, err := os.ReadFile(filepath.Join(result.Directory, "incident-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"### eBPF block latency evidence",
		"Total completed requests:  2",
	} {
		if !strings.Contains(string(report), want) {
			t.Errorf("incident report missing eBPF evidence %q:\n%s", want, report)
		}
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

func TestWriteLiveOnlyCaptureUsesExplicitUnavailableEvidence(t *testing.T) {
	inputs := testCaptureInputs(t.TempDir())
	inputs.ReportDirectory = ""
	inputs.IncludeEBPFLatency = false
	evidence := testCaptureEvidence(nil)
	evidence.Experiment = experiment.Report{}
	evidence.Incident = incident.Explanation{}
	evidence.Diagnosis = diagnose.Report{
		Inputs: diagnose.Inputs{
			Victim:   "a-web",
			Suspect:  "b-stress",
			Duration: time.Second,
			Interval: time.Second,
		},
		Verdict: diagnose.InsufficientLiveVerdict,
	}
	result, err := Write(inputs, evidence, time.Date(2026, 8, 9, 0, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	checks := map[string][]string{
		"experiment-summary.txt": {
			"No report directory supplied.",
			"Application-level slowdown evidence unavailable in this live-only run.",
		},
		"incident-explanation.txt": {
			"No report directory supplied.",
			"Application-level slowdown evidence unavailable in this live-only run.",
			"See diagnosis.txt and incident-report.md for provider-side live evidence.",
		},
		"incident-report.md": {
			"- Evidence mode: live-only",
			"Application slowdown evidence: unavailable; no --report-dir supplied.",
		},
		"metadata.txt": {
			"Report directory: -",
			"Evidence mode: live-only",
		},
	}
	for name, wantValues := range checks {
		content, err := os.ReadFile(filepath.Join(result.Directory, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range wantValues {
			if !strings.Contains(string(content), want) {
				t.Errorf("%s missing %q:\n%s", name, want, content)
			}
		}
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
			ExperimentAvailable: true,
			Experiment:          experimentReport,
			EBPFLatency:         latency,
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
