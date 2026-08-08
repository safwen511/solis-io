package cli

import (
	"strings"
	"testing"
	"time"
)

func TestParseEBPFBlockWatchArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    time.Duration
		wantErr string
	}{
		{name: "default", args: []string{"ebpf", "block-watch"}, want: 10 * time.Second},
		{name: "explicit", args: []string{"ebpf", "block-watch", "--duration", "2.5s"}, want: 2500 * time.Millisecond},
		{name: "invalid", args: []string{"ebpf", "block-watch", "--duration", "0s"}, wantErr: "invalid --duration"},
		{name: "unknown option", args: []string{"ebpf", "block-watch", "--interval", "1s"}, wantErr: ebpfBlockWatchUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseEBPFBlockWatchArgs(test.args)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseEBPFBlockWatchArgs() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("duration = %s, want %s", got, test.want)
			}
		})
	}
}

func TestParseRequiredEBPFDuration(t *testing.T) {
	duration, err := parseRequiredEBPFDuration(
		[]string{"ebpf", "block-count", "--duration", "10s"},
		"block-count",
		ebpfBlockCountUsage,
	)
	if err != nil || duration != 10*time.Second {
		t.Fatalf("duration = %s, error = %v", duration, err)
	}

	for _, args := range [][]string{
		{"ebpf", "block-count"},
		{"ebpf", "block-count", "--duration", "0s"},
		{"ebpf", "block-count", "--interval", "1s"},
	} {
		if _, err := parseRequiredEBPFDuration(args, "block-count", ebpfBlockCountUsage); err == nil {
			t.Errorf("args %v: expected error", args)
		}
	}
}

func TestParseRequiredEBPFBlockLatencyDuration(t *testing.T) {
	duration, err := parseRequiredEBPFDuration(
		[]string{"ebpf", "block-latency", "--duration", "750ms"},
		"block-latency",
		ebpfBlockLatencyUsage,
	)
	if err != nil {
		t.Fatal(err)
	}
	if duration != 750*time.Millisecond {
		t.Fatalf("duration = %s, want 750ms", duration)
	}
}

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

func TestParseDiagnoseNoisyNeighborOutputPath(t *testing.T) {
	options, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
		"--output", "reports/diagnosis.txt",
	})
	if err != nil {
		t.Fatalf("parseDiagnoseNoisyNeighborArgs() error = %v", err)
	}
	if options.OutputPath != "reports/diagnosis.txt" || options.OutputDirectory != "" {
		t.Fatalf("output options = %#v, want exact output path", options)
	}
}

func TestParseDiagnoseNoisyNeighborRejectsOutputConflict(t *testing.T) {
	_, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
		"--output", "diagnosis.txt",
		"--output-dir", "reports",
	})
	if err == nil || !strings.Contains(err.Error(), "--output and --output-dir cannot be used together") {
		t.Fatalf("parseDiagnoseNoisyNeighborArgs() error = %v, want output conflict", err)
	}
}

func TestParseCaptureNoisyNeighborDefaults(t *testing.T) {
	options, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--report-dir", "lab/reports/workload/test",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
		"--output-dir", "lab/reports/captures",
	})
	if err != nil {
		t.Fatalf("parseCaptureNoisyNeighborArgs() error = %v", err)
	}
	if options.Duration != 10*time.Second || options.Interval != 2*time.Second {
		t.Fatalf("durations = %s, %s, want 10s, 2s", options.Duration, options.Interval)
	}
	if options.OutputDirectory != "lab/reports/captures" {
		t.Fatalf("OutputDirectory = %q, want lab/reports/captures", options.OutputDirectory)
	}
}

func TestParseCaptureNoisyNeighborRequiresDirectories(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "report directory",
			args: []string{
				"capture", "noisy-neighbor",
				"--victim", "tenant-a",
				"--suspect", "b-stress",
				"--output-dir", "captures",
			},
			want: "missing --report-dir",
		},
		{
			name: "output directory",
			args: []string{
				"capture", "noisy-neighbor",
				"--report-dir", "report",
				"--victim", "tenant-a",
				"--suspect", "b-stress",
			},
			want: "missing --output-dir",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseCaptureNoisyNeighborArgs(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseCaptureNoisyNeighborArgs() error = %v, want %q", err, test.want)
			}
		})
	}
}
