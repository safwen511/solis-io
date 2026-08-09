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

func TestParseEBPFBlockLatencyArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantVictim   string
		wantSuspect  string
		wantDuration time.Duration
		wantErr      string
	}{
		{
			name:         "host wide",
			args:         []string{"ebpf", "block-latency", "--duration", "750ms"},
			wantDuration: 750 * time.Millisecond,
		},
		{
			name:         "VM aware",
			args:         []string{"ebpf", "block-latency", "--suspect", "b-stress", "--duration", "10s", "--victim", "a-web"},
			wantVictim:   "a-web",
			wantSuspect:  "b-stress",
			wantDuration: 10 * time.Second,
		},
		{
			name:    "victim without suspect",
			args:    []string{"ebpf", "block-latency", "--victim", "a-web", "--duration", "10s"},
			wantErr: "--victim and --suspect must be provided together",
		},
		{
			name:    "suspect without victim",
			args:    []string{"ebpf", "block-latency", "--suspect", "b-stress", "--duration", "10s"},
			wantErr: "--victim and --suspect must be provided together",
		},
		{
			name:    "missing duration",
			args:    []string{"ebpf", "block-latency", "--victim", "a-web", "--suspect", "b-stress"},
			wantErr: ebpfBlockLatencyUsage,
		},
		{
			name:    "duplicate option",
			args:    []string{"ebpf", "block-latency", "--duration", "10s", "--duration", "20s"},
			wantErr: "duplicate option --duration",
		},
		{
			name:    "invalid duration",
			args:    []string{"ebpf", "block-latency", "--duration", "0s"},
			wantErr: "invalid --duration",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, err := parseEBPFBlockLatencyArgs(test.args)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if options.Victim != test.wantVictim || options.Suspect != test.wantSuspect || options.Duration != test.wantDuration {
				t.Fatalf("options = %#v", options)
			}
		})
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

func TestParseDiagnoseNoisyNeighborIncludesEBPFLatency(t *testing.T) {
	options, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--include-ebpf-latency",
		"--report-dir", "report",
		"--victim", "a-web",
		"--suspect", "b-stress",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.IncludeEBPFLatency {
		t.Fatal("IncludeEBPFLatency = false, want true")
	}
}

func TestParseDiagnoseNoisyNeighborDiscoversSuspects(t *testing.T) {
	options, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--discover-suspects",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.DiscoverSuspects || options.Suspect != "" {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseDiagnoseNoisyNeighborAllowsLiveOnlyMode(t *testing.T) {
	options, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--victim", "a-web",
		"--discover-suspects",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.ReportDirectory != "" || !options.DiscoverSuspects {
		t.Fatalf("options = %#v, want live-only discovery", options)
	}
}

func TestParseDiagnoseNoisyNeighborRequiresSuspectMode(t *testing.T) {
	_, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
	})
	if err == nil || !strings.Contains(err.Error(), "provide either --suspect <vm> or --discover-suspects") {
		t.Fatalf("error = %v, want suspect mode usage error", err)
	}
}

func TestParseDiagnoseNoisyNeighborRejectsSuspectAndDiscovery(t *testing.T) {
	_, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--suspect", "b-stress",
		"--discover-suspects",
	})
	if err == nil || !strings.Contains(err.Error(), "--suspect and --discover-suspects cannot be used together") {
		t.Fatalf("error = %v, want selector conflict", err)
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
	if options.DiscoverSuspects {
		t.Fatal("DiscoverSuspects = true in pairwise mode")
	}
}

func TestParseCaptureNoisyNeighborDiscoversSuspects(t *testing.T) {
	options, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--discover-suspects",
		"--output-dir", "captures",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.DiscoverSuspects || options.Suspect != "" {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseCaptureNoisyNeighborAllowsLiveOnlyMode(t *testing.T) {
	options, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--victim", "a-web",
		"--discover-suspects",
		"--output-dir", "captures",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.ReportDirectory != "" || !options.DiscoverSuspects {
		t.Fatalf("options = %#v, want live-only discovery", options)
	}
}

func TestParseCaptureNoisyNeighborRequiresSuspectMode(t *testing.T) {
	_, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--output-dir", "captures",
	})
	if err == nil || !strings.Contains(err.Error(), "provide either --suspect <vm> or --discover-suspects") {
		t.Fatalf("error = %v, want suspect mode usage error", err)
	}
}

func TestParseCaptureNoisyNeighborRejectsSuspectAndDiscovery(t *testing.T) {
	_, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--suspect", "b-stress",
		"--discover-suspects",
		"--output-dir", "captures",
	})
	if err == nil || !strings.Contains(err.Error(), "--suspect and --discover-suspects cannot be used together") {
		t.Fatalf("error = %v, want selector conflict", err)
	}
}

func TestParseCaptureNoisyNeighborIncludesEBPFLatency(t *testing.T) {
	options, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--suspect", "b-stress",
		"--include-ebpf-latency",
		"--output-dir", "captures",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.IncludeEBPFLatency {
		t.Fatal("IncludeEBPFLatency = false, want true")
	}
}

func TestParseNoisyNeighborRejectsDuplicateEBPFLatencyFlag(t *testing.T) {
	_, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--suspect", "b-stress",
		"--include-ebpf-latency",
		"--include-ebpf-latency",
	})
	if err == nil || !strings.Contains(err.Error(), "--include-ebpf-latency specified more than once") {
		t.Fatalf("error = %v, want duplicate flag error", err)
	}
}

func TestParseCaptureNoisyNeighborRequiresOutputDirectory(t *testing.T) {
	_, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
	})
	if err == nil || !strings.Contains(err.Error(), "missing --output-dir") {
		t.Fatalf("parseCaptureNoisyNeighborArgs() error = %v, want missing output directory", err)
	}
}

func TestParseWatchNoisyNeighbor(t *testing.T) {
	options, err := parseWatchNoisyNeighborArgs([]string{
		"watch", "noisy-neighbor",
		"--victim", "a-web",
		"--discover-suspects",
		"--window", "8s",
		"--every", "20s",
		"--iterations", "3",
		"--include-ebpf-latency",
		"--capture-on-alert",
		"--cooldown", "90s",
		"--output-dir", "captures",
		"--verbose",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Victim != "a-web" || !options.DiscoverSuspects || options.Suspect != "" {
		t.Fatalf("selectors = %#v", options)
	}
	if options.Window != 8*time.Second || options.Every != 20*time.Second || options.Iterations != 3 {
		t.Fatalf("timing = %#v", options)
	}
	if !options.IncludeEBPFLatency || !options.CaptureOnAlert || !options.Verbose {
		t.Fatalf("flags = %#v", options)
	}
	if options.Cooldown != 90*time.Second || options.OutputDirectory != "captures" {
		t.Fatalf("capture options = %#v", options)
	}
}

func TestParseWatchNoisyNeighborDefaults(t *testing.T) {
	options, err := parseWatchNoisyNeighborArgs([]string{
		"watch", "noisy-neighbor",
		"--victim", "a-web",
		"--suspect", "b-stress",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Window != 10*time.Second || options.Every != 30*time.Second || options.Cooldown != 2*time.Minute {
		t.Fatalf("defaults = %#v", options)
	}
	if options.OutputDirectory != "lab/reports/captures" || options.Iterations != 0 {
		t.Fatalf("defaults = %#v", options)
	}
}

func TestParseWatchNoisyNeighborSelectorValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing victim",
			args: []string{"watch", "noisy-neighbor", "--discover-suspects"},
			want: "missing --victim",
		},
		{
			name: "missing suspect mode",
			args: []string{"watch", "noisy-neighbor", "--victim", "a-web"},
			want: "provide either --suspect <vm> or --discover-suspects",
		},
		{
			name: "conflicting suspect mode",
			args: []string{
				"watch", "noisy-neighbor",
				"--victim", "a-web",
				"--suspect", "b-stress",
				"--discover-suspects",
			},
			want: "--suspect and --discover-suspects cannot be used together",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseWatchNoisyNeighborArgs(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
