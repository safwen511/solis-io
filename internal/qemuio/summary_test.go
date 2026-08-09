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
	if got.MaxSyscwPerSecond != 40 {
		t.Fatalf("MaxSyscwPerSecond = %v, want 40", got.MaxSyscwPerSecond)
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
		name         string
		victimWrite  float64
		suspectWrite float64
		suspectSyscw float64
		want         string
	}{
		{"high suspect write bytes", 0, 147, 0, dominantConclusion},
		{"low bytes but high suspect syscw", 0, 0, 122364, syscallPressureConclusion},
		{"no byte or syscall pressure", 0, 0.27, 0, noWritePressureConclusion},
		{"similar meaningful byte rates", 20, 21, 0, noDominantConclusion},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := conclusionForSignals(test.victimWrite, test.suspectWrite, test.suspectSyscw); got != test.want {
				t.Fatalf("conclusionForSignals() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSyscallFallbackMarksDominantSuspect(t *testing.T) {
	victim := Target{TargetType: "victim", VM: inventory.VM{Name: "a-db"}}
	suspect := Target{TargetType: "suspect", VM: inventory.VM{Name: "b-stress"}}
	plan := Plan{VictimSelector: "tenant-a", SuspectSelector: "b-stress", Targets: []Target{victim, suspect}}
	report := summarizeSamples(plan, time.Second, time.Second, []intervalSample{
		{Target: victim, Interval: time.Second, Rates: Rates{SyscwPerSecond: 500}},
		{Target: suspect, Interval: time.Second, Rates: Rates{SyscwPerSecond: 122364}},
	})

	if report.MeaningfulSuspectWritePressure {
		t.Fatal("byte-based pressure = true, want false")
	}
	if !report.MeaningfulSuspectSyscwPressure || !report.SuspectSyscwDominant {
		t.Fatalf("syscall pressure fields = %#v", report)
	}
	if report.DominantWriter != "-" || report.DominantWriteSyscallSource != "b-stress" {
		t.Fatalf("dominant sources = writer %q, syscall %q", report.DominantWriter, report.DominantWriteSyscallSource)
	}
	if report.WriteSyscallPressure != "HIGH" || report.Conclusion != syscallPressureConclusion {
		t.Fatalf("classification/conclusion = %q, %q", report.WriteSyscallPressure, report.Conclusion)
	}
}

func TestSyscallComparisonDoesNotMarkSimilarRatesDominant(t *testing.T) {
	victim := Target{TargetType: "victim", VM: inventory.VM{Name: "a-db"}}
	suspect := Target{TargetType: "suspect", VM: inventory.VM{Name: "b-stress"}}
	plan := Plan{VictimSelector: "tenant-a", SuspectSelector: "b-stress", Targets: []Target{victim, suspect}}
	report := summarizeSamples(plan, time.Second, time.Second, []intervalSample{
		{Target: victim, Interval: time.Second, Rates: Rates{SyscwPerSecond: 80000}},
		{Target: suspect, Interval: time.Second, Rates: Rates{SyscwPerSecond: 100000}},
	})

	if !report.MeaningfulSuspectSyscwPressure || report.SuspectSyscwDominant {
		t.Fatalf("syscall pressure fields = %#v", report)
	}
	if report.SyscwRatio != "1.25x" || report.DominantWriteSyscallSource != "-" {
		t.Fatalf("syscall comparison = ratio %q, source %q", report.SyscwRatio, report.DominantWriteSyscallSource)
	}
	if report.Conclusion != syscallPressureConclusion {
		t.Fatalf("Conclusion = %q, want %q", report.Conclusion, syscallPressureConclusion)
	}
}

func TestSummaryForPlanReusesSelectedSamples(t *testing.T) {
	victimVM := inventory.VM{Name: "a-web"}
	suspectVM := inventory.VM{Name: "b-stress"}
	source := SummaryReport{
		Duration: 10 * time.Second,
		Interval: 2 * time.Second,
		VMs: []VMSummary{
			{Target: Target{TargetType: "victim", VM: victimVM}, Available: true, AverageWriteMiBPerSecond: 1},
			{Target: Target{TargetType: "candidate", VM: suspectVM}, Available: true, AverageWriteMiBPerSecond: 40},
		},
	}
	plan := NewPlan("a-web", "b-stress", []inventory.VM{victimVM}, suspectVM)
	report := SummaryForPlan(source, plan)
	if report.SuspectAverageWriteMiBPerSecond != 40 || !report.SuspectDominant {
		t.Fatalf("report = %#v", report)
	}
	if report.DominantWriter != "b-stress" || report.Duration != 10*time.Second || report.Interval != 2*time.Second {
		t.Fatalf("report metadata = %#v", report)
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
