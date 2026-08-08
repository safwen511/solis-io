package qemuio

import (
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/inventory"
)

func TestSummarizeSamplesCalculatesTimeWeightedAverages(t *testing.T) {
	victim := Target{TargetType: "victim", VM: inventory.VM{Name: "a-db"}}
	suspect := Target{TargetType: "suspect", VM: inventory.VM{Name: "b-stress"}}
	plan := Plan{VictimSelector: "tenant-a", SuspectSelector: "b-stress", Targets: []Target{victim, suspect}}
	samples := []intervalSample{
		{Target: victim, Interval: time.Second, Rates: Rates{ReadMiBPerSecond: 2, WriteMiBPerSecond: 2, SyscrPerSecond: 10, SyscwPerSecond: 20}},
		{Target: victim, Interval: 3 * time.Second, Rates: Rates{ReadMiBPerSecond: 4, WriteMiBPerSecond: 4, SyscrPerSecond: 30, SyscwPerSecond: 40}},
		{Target: suspect, Interval: time.Second, Rates: Rates{WriteMiBPerSecond: 10}},
		{Target: suspect, Interval: 3 * time.Second, Rates: Rates{WriteMiBPerSecond: 8}},
	}

	report := summarizeSamples(plan, 4*time.Second, time.Second, samples)
	got := report.VMs[0]
	if got.AverageReadMiBPerSecond != 3.5 || got.AverageWriteMiBPerSecond != 3.5 {
		t.Fatalf("averages = %#v, want 3.5 MiB/s read and write", got)
	}
	if got.MaxWriteMiBPerSecond != 4 || got.TotalReadMiB != 14 || got.TotalWrittenMiB != 14 {
		t.Fatalf("maximum/totals = %#v, want max 4 and totals 14", got)
	}
	if got.AverageSyscrPerSecond != 25 || got.AverageSyscwPerSecond != 35 {
		t.Fatalf("syscall averages = %#v, want 25 syscr/s and 35 syscw/s", got)
	}
}

func TestFormatWriteRatio(t *testing.T) {
	if got := formatWriteRatio(0.27, 0); got != "-" {
		t.Fatalf("formatWriteRatio(0.27, 0) = %q, want -", got)
	}
	if got := formatWriteRatio(147, 0); got != "dominant suspect" {
		t.Fatalf("formatWriteRatio(147, 0) = %q, want dominant suspect", got)
	}
	if got := formatWriteRatio(60, 20); got != "3.00x" {
		t.Fatalf("formatWriteRatio(60, 20) = %q, want 3.00x", got)
	}
}

func TestConclusionLogic(t *testing.T) {
	tests := []struct {
		name    string
		victim  float64
		suspect float64
		want    string
	}{
		{"high suspect, low victim", 0, 147, dominantConclusion},
		{"low suspect, zero victim", 0, 0.27, noWritePressureConclusion},
		{"similar meaningful rates", 20, 21, noDominantConclusion},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := conclusionForRates(test.victim, test.suspect); got != test.want {
				t.Fatalf("conclusionForRates(%v, %v) = %q, want %q", test.victim, test.suspect, got, test.want)
			}
		})
	}
}

func TestLowActivityReportHasNoDominantWriter(t *testing.T) {
	victim := Target{TargetType: "victim", VM: inventory.VM{Name: "a-db"}}
	suspect := Target{TargetType: "suspect", VM: inventory.VM{Name: "b-stress"}}
	plan := Plan{VictimSelector: "tenant-a", SuspectSelector: "b-stress", Targets: []Target{victim, suspect}}
	report := summarizeSamples(plan, time.Second, time.Second, []intervalSample{
		{Target: victim, Interval: time.Second, Rates: Rates{}},
		{Target: suspect, Interval: time.Second, Rates: Rates{WriteMiBPerSecond: 0.27}},
	})

	if report.DominantWriter != "-" {
		t.Fatalf("DominantWriter = %q, want -", report.DominantWriter)
	}
	if report.WriteRatio != "-" {
		t.Fatalf("WriteRatio = %q, want -", report.WriteRatio)
	}
	if report.Conclusion != noWritePressureConclusion {
		t.Fatalf("Conclusion = %q, want %q", report.Conclusion, noWritePressureConclusion)
	}
}
