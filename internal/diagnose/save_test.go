package diagnose

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
	"github.com/safwen511/solis-io/internal/storage"
)

func TestWriteOutputStdoutMode(t *testing.T) {
	report := outputTestReport()
	var want bytes.Buffer
	if err := Write(&want, report); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var got bytes.Buffer
	path, err := WriteOutput(&got, report, OutputOptions{}, time.Time{})
	if err != nil {
		t.Fatalf("WriteOutput() error = %v", err)
	}
	if path != "" {
		t.Fatalf("WriteOutput() path = %q, want empty stdout path", path)
	}
	if got.String() != want.String() {
		t.Fatalf("stdout output differs from diagnosis:\n%s", got.String())
	}
}

func TestWriteOutputExactPath(t *testing.T) {
	report := outputTestReport()
	path := filepath.Join(t.TempDir(), "diagnosis.txt")
	var stdout bytes.Buffer

	writtenPath, err := WriteOutput(&stdout, report, OutputOptions{Path: path}, time.Time{})
	if err != nil {
		t.Fatalf("WriteOutput() error = %v", err)
	}
	if writtenPath != path {
		t.Fatalf("WriteOutput() path = %q, want %q", writtenPath, path)
	}
	assertDiagnosisFile(t, path, report)
	if got := stdout.String(); got != "diagnosis written to "+path+"\n" {
		t.Fatalf("stdout = %q, want confirmation", got)
	}
}

func TestWriteOutputJSONExactPath(t *testing.T) {
	report := jsonOutputTestReport()
	path := filepath.Join(t.TempDir(), "diagnosis.json")
	var stdout bytes.Buffer

	writtenPath, err := WriteOutput(&stdout, report, OutputOptions{Path: path, JSON: true}, time.Time{})
	if err != nil {
		t.Fatalf("WriteOutput() error = %v", err)
	}
	if writtenPath != path {
		t.Fatalf("WriteOutput() path = %q, want %q", writtenPath, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		SchemaVersion     string `json:"schema_version"`
		EBPFVMAttribution struct {
			Available       bool   `json:"available"`
			Quality         string `json:"quality"`
			SuspectTotalOps uint64 `json:"suspect_total_ops"`
		} `json:"ebpf_vm_attribution"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("saved diagnosis is not JSON: %v\n%s", err, data)
	}
	if decoded.SchemaVersion != "1" || !decoded.EBPFVMAttribution.Available ||
		decoded.EBPFVMAttribution.Quality != "available" || decoded.EBPFVMAttribution.SuspectTotalOps != 32094 {
		t.Fatalf("decoded diagnosis = %#v", decoded)
	}
	if strings.Contains(string(data), "diagnosis written to") || strings.HasPrefix(string(data), "Solis Noisy Neighbor Diagnosis") {
		t.Fatalf("JSON file contains human output: %s", data)
	}
	if got := stdout.String(); got != "diagnosis written to "+path+"\n" {
		t.Fatalf("stdout = %q, want confirmation outside JSON", got)
	}
}

func TestWriteJSONExcludesSensitiveInternalFields(t *testing.T) {
	report := jsonOutputTestReport()
	report.Storage.Targets[0].VM.QEMUCmdline = "forbidden-cmdline-marker"
	report.QEMU.VMs[0].Error = "permission denied reading /proc/123/io"
	report.EBPFVMAttribution.Diagnostics.RawError = "kernel address 0xffff request_pointer cmdline /proc/123/status"

	var output bytes.Buffer
	if err := WriteJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(output.Bytes()) {
		t.Fatalf("invalid JSON: %s", output.String())
	}
	lower := strings.ToLower(output.String())
	for _, forbidden := range []string{"request_pointer", "0xffff", "cmdline", "/proc/"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("JSON contains forbidden token %q: %s", forbidden, output.String())
		}
	}
	if !strings.Contains(output.String(), `"process_arguments_collected": false`) ||
		!strings.Contains(output.String(), `"secrets_collected": false`) {
		t.Fatalf("privacy flags missing or non-false: %s", output.String())
	}
}

func TestWriteOutputDirectoryUsesUTCTimestamp(t *testing.T) {
	report := outputTestReport()
	report.Inputs.Victim = "tenant/a"
	report.Inputs.Suspect = "b stress"
	directory := t.TempDir()
	now := time.Date(2026, 8, 8, 22, 55, 0, 0, time.FixedZone("UTC+2", 2*60*60))
	wantPath := filepath.Join(directory, "diagnosis-20260808T205500Z-tenant_a-b_stress.txt")

	writtenPath, err := WriteOutput(&bytes.Buffer{}, report, OutputOptions{Directory: directory}, now)
	if err != nil {
		t.Fatalf("WriteOutput() error = %v", err)
	}
	if writtenPath != wantPath {
		t.Fatalf("WriteOutput() path = %q, want %q", writtenPath, wantPath)
	}
	assertDiagnosisFile(t, wantPath, report)
}

func TestWriteOutputCreatesParentDirectories(t *testing.T) {
	report := outputTestReport()
	path := filepath.Join(t.TempDir(), "nested", "reports", "diagnosis.txt")
	if _, err := WriteOutput(&bytes.Buffer{}, report, OutputOptions{Path: path}, time.Time{}); err != nil {
		t.Fatalf("WriteOutput() error = %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("parent directory was not created: %v", err)
	}
	assertDiagnosisFile(t, path, report)
}

func TestWriteOutputRejectsConflictingDestinations(t *testing.T) {
	_, err := WriteOutput(
		&bytes.Buffer{},
		outputTestReport(),
		OutputOptions{Path: "report.txt", Directory: "reports"},
		time.Time{},
	)
	if err == nil || !strings.Contains(err.Error(), "--output and --output-dir cannot be used together") {
		t.Fatalf("WriteOutput() error = %v, want destination conflict", err)
	}
}

func TestSanitizeFilenamePart(t *testing.T) {
	tests := map[string]string{
		"tenant-a":      "tenant-a",
		"tenant_A1":     "tenant_A1",
		"tenant a/db!":  "tenant_a_db_",
		"tenant.ümlaut": "tenant__mlaut",
		"":              "_",
	}
	for input, want := range tests {
		if got := SanitizeFilenamePart(input); got != want {
			t.Errorf("SanitizeFilenamePart(%q) = %q, want %q", input, got, want)
		}
	}
}

func outputTestReport() Report {
	return Report{
		Inputs: Inputs{
			ReportDirectory: "lab/reports/workload/test",
			Victim:          "tenant-a",
			Suspect:         "b-stress",
			Duration:        10 * time.Second,
			Interval:        2 * time.Second,
		},
		StorageTopologyAvailable: true,
		SharedPhysicalDisk:       true,
		Verdict:                  InsufficientVerdict,
	}
}

func jsonOutputTestReport() Report {
	report := outputTestReport()
	report.Storage.Targets = []storage.VMTarget{
		{
			TargetType: "victim",
			VM:         inventory.VM{Name: "a-web", Tenant: "tenant-a", Role: "web", QEMUPID: "101", Disk: "/var/lib/libvirt/images/a-web.qcow2"},
			Storage:    hoststorage.Mapping{SourceDevice: "/dev/dm-0", ParentDevice: "/dev/nvme0n1p3", PhysicalDisk: "/dev/nvme0n1"},
		},
		{
			TargetType: "suspect",
			VM:         inventory.VM{Name: "b-stress", Tenant: "tenant-b", Role: "stress", QEMUPID: "202", Disk: "/var/lib/libvirt/images/b-stress.qcow2"},
			Storage:    hoststorage.Mapping{SourceDevice: "/dev/dm-0", ParentDevice: "/dev/nvme0n1p3", PhysicalDisk: "/dev/nvme0n1"},
		},
	}
	report.QEMU.VMs = []qemuio.VMSummary{{Target: qemuio.Target{TargetType: "victim", VM: report.Storage.Targets[0].VM}}}
	report.EBPFVMAttribution = &ebpf.VMBlockLatencyReport{
		CollectionMode:     "typed_btf_vm_attributed_latency",
		AttributionMethod:  "blkcg_cgroup_id_to_libvirt_vm",
		AttributionQuality: "available",
		Availability:       ebpf.VMBlockLatencyAvailability{Available: true, Status: "available"},
		AttributionSummary: ebpf.VMBlockAttributionSummary{AttributedOps: 32094, AttributedPercent: 99.62, MatchedVMCount: 1},
		Unattributed:       ebpf.VMBlockLatencyUnattributed{UnattributedPercent: 0.38},
		VMs: []ebpf.VMBlockLatencyVM{
			{Name: "a-web", Tenant: "tenant-a", Role: "web", AttributionQuality: "available"},
			{Name: "b-stress", Tenant: "tenant-b", Role: "stress", TotalOps: 32094, WriteOps: 32094, LatencyP95MS: 2, AttributionQuality: "available"},
		},
	}
	return report
}

func assertDiagnosisFile(t *testing.T, path string, report Report) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read diagnosis file: %v", err)
	}
	var want bytes.Buffer
	if err := Write(&want, report); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if string(data) != want.String() {
		t.Fatalf("saved diagnosis differs:\n%s", data)
	}
}
