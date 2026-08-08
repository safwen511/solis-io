package experiment

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const httpFixture = `Failed requests:        2
Requests per second:    100.00 [#/sec] (mean)
Time per request:       200.000 [ms] (mean)
Time per request:       10.000 [ms] (mean, across all concurrent requests)
Transfer rate:          25.50 [Kbytes/sec] received
`

func TestLoadAndWriteSummary(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "baseline.txt", httpFixture)
	duringNoise := strings.NewReplacer("100.00", "75.00", "200.000", "250.000").Replace(httpFixture)
	writeTestFile(t, dir, "during-noise.txt", duringNoise)
	writeTestFile(t, dir, "post-noise.txt", strings.Replace(httpFixture, "100.00", "90.00", 1))
	writeTestFile(t, dir, "fio-noise.txt", "  write: IOPS=10.5k, BW=41.0MiB/s (43.0MB/s)\n  vda: util=88.25%\n")

	report, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if report.Baseline.TimePerRequestMS != 200.000 {
		t.Fatalf("TimePerRequestMS = %v, want first value 200", report.Baseline.TimePerRequestMS)
	}
	if report.FIO.IOPS != "10.5k" || report.FIO.Bandwidth != "41.0MiB/s" {
		t.Fatalf("fio metrics = %#v", report.FIO)
	}

	var output bytes.Buffer
	if err := WriteSummary(&output, report); err != nil {
		t.Fatalf("WriteSummary() error = %v", err)
	}
	for _, expected := range []string{
		"Baseline",
		"Throughput drop:",
		"Latency increase:",
		"25.00%",
		"10.5k",
		"88.25%",
		"Noisy-neighbor impact observed",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("summary missing %q:\n%s", expected, output.String())
		}
	}
}

func TestLoadReportsMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "baseline.txt") {
		t.Fatalf("Load() error = %v, want missing baseline.txt error", err)
	}
}

func TestLoadReportsParseFailure(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "baseline.txt", "Failed requests: 0\n")

	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "missing Requests per second") {
		t.Fatalf("Load() error = %v, want missing field error", err)
	}
}

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
