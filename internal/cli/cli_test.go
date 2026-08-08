package cli

import (
	"strings"
	"testing"
	"time"
)

func TestParseQEMUIOWatchArgsDefaults(t *testing.T) {
	victim, suspect, duration, interval, err := parseQEMUIOWatchArgs([]string{
		"qemu", "io-watch", "--victim", "tenant-a", "--suspect", "b-stress",
	})
	if err != nil {
		t.Fatalf("parseQEMUIOWatchArgs() error = %v", err)
	}
	if victim != "tenant-a" || suspect != "b-stress" {
		t.Fatalf("selectors = %q, %q, want tenant-a, b-stress", victim, suspect)
	}
	if duration != 30*time.Second || interval != 5*time.Second {
		t.Fatalf("durations = %s, %s, want 30s, 5s", duration, interval)
	}
}

func TestParseQEMUIOWatchArgsRejectsLongInterval(t *testing.T) {
	_, _, _, _, err := parseQEMUIOWatchArgs([]string{
		"qemu", "io-watch",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
		"--duration", "1s",
		"--interval", "2s",
	})
	if err == nil || !strings.Contains(err.Error(), "interval 2s cannot exceed duration 1s") {
		t.Fatalf("parseQEMUIOWatchArgs() error = %v, want interval validation error", err)
	}
}

func TestParseQEMUIOSummaryArgsDefaults(t *testing.T) {
	victim, suspect, duration, interval, err := parseQEMUIOSummaryArgs([]string{
		"qemu", "io-summary", "--victim", "tenant-a", "--suspect", "b-stress",
	})
	if err != nil {
		t.Fatalf("parseQEMUIOSummaryArgs() error = %v", err)
	}
	if victim != "tenant-a" || suspect != "b-stress" {
		t.Fatalf("selectors = %q, %q, want tenant-a, b-stress", victim, suspect)
	}
	if duration != 30*time.Second || interval != 5*time.Second {
		t.Fatalf("durations = %s, %s, want 30s, 5s", duration, interval)
	}
}

func TestParseDiagnoseNoisyNeighborArgsDefaults(t *testing.T) {
	options, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "lab/reports/workload/test",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
	})
	if err != nil {
		t.Fatalf("parseDiagnoseNoisyNeighborArgs() error = %v", err)
	}
	if options.ReportDirectory != "lab/reports/workload/test" || options.Victim != "tenant-a" || options.Suspect != "b-stress" {
		t.Fatalf("options = %#v, want requested report and selectors", options)
	}
	if options.Duration != 10*time.Second || options.Interval != 2*time.Second {
		t.Fatalf("durations = %s, %s, want 10s, 2s", options.Duration, options.Interval)
	}
}
