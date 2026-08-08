package capture

import (
	"bytes"
	"strings"
	"testing"
	"time"
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
