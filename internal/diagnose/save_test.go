package diagnose

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
