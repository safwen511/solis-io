package watch

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/diagnose"
	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
)

// TestIterationSummaryRendersSelectedSuspect verifies iteration summary renders selected suspect.
func TestIterationSummaryRendersSelectedSuspect(t *testing.T) {
	discoveryReport := discovery.Report{
		Candidates: []discovery.Candidate{{
			VM:     inventory.VM{Name: "b-stress"},
			Score:  "HIGH",
			Reason: "dominant syscall pressure",
		}},
	}
	discoveryReport.Selected = &discoveryReport.Candidates[0]
	report := diagnose.Report{
		Inputs:    diagnose.Inputs{Victim: "a-web", Suspect: "b-stress"},
		Discovery: &discoveryReport,
		QEMU: qemuio.SummaryReport{
			SuspectDataAvailable:            true,
			SuspectAverageWriteMiBPerSecond: 3.2,
			SuspectAverageSyscwPerSecond:    139413,
		},
		Verdict: diagnose.LikelyLiveVerdict,
	}
	summary := NewIterationSummary(time.Date(2026, 8, 9, 1, 2, 3, 0, time.UTC), report)
	var output bytes.Buffer
	if err := WriteIteration(&output, summary); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Selected suspect:", "b-stress", "HIGH", "dominant syscall pressure", "139413.00"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("iteration output missing %q:\n%s", want, output.String())
		}
	}
}

// TestIterationSummaryIncludesVMAttributionQuality verifies iteration summary includes vm
// attribution quality.
func TestIterationSummaryIncludesVMAttributionQuality(t *testing.T) {
	report := diagnose.Report{
		Inputs:  diagnose.Inputs{Victim: "a-web", Suspect: "b-stress"},
		Verdict: diagnose.LikelyLiveVerdict,
		EBPFVMAttribution: &ebpf.VMBlockLatencyReport{
			Availability:       ebpf.VMBlockLatencyAvailability{Available: true, Status: "available"},
			AttributionQuality: "degraded",
			AttributionSummary: ebpf.VMBlockAttributionSummary{AttributedOps: 80, AttributedPercent: 80, MatchedVMCount: 1},
			Unattributed:       ebpf.VMBlockLatencyUnattributed{UnattributedPercent: 20},
		},
	}
	summary := NewIterationSummary(time.Now(), report)
	if !summary.EBPFVMAttributionAvailable || summary.EBPFVMAttributionQuality != "degraded" || summary.EBPFVMUnattributedPercent != 20 {
		t.Fatalf("iteration VM attribution = %#v", summary)
	}
	var output bytes.Buffer
	if err := WriteIteration(&output, summary); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"eBPF VM attribution quality:", "degraded", "eBPF unattributed percent:", "20.00"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

// TestDegradedOrUnavailableEBPFCannotCreateAlert verifies degraded or unavailable ebpf cannot
// create alert.
func TestDegradedOrUnavailableEBPFCannotCreateAlert(t *testing.T) {
	for _, quality := range []string{"degraded", "unavailable"} {
		report := diagnose.Report{
			Verdict: diagnose.InsufficientLiveVerdict,
			EBPFVMAttribution: &ebpf.VMBlockLatencyReport{
				Availability:       ebpf.VMBlockLatencyAvailability{Available: quality == "degraded"},
				AttributionQuality: quality,
			},
		}
		if IsAlertReport(report) {
			t.Fatalf("%s VM attribution created an alert", quality)
		}
	}
	report := diagnose.Report{Verdict: diagnose.LikelyLiveVerdict, EBPFVMAttribution: &ebpf.VMBlockLatencyReport{AttributionQuality: "degraded"}}
	if !IsAlertReport(report) {
		t.Fatal("existing non-eBPF likely verdict was suppressed solely because attribution was degraded")
	}
}

// TestAlertDecision verifies alert decision.
func TestAlertDecision(t *testing.T) {
	if !IsAlert(diagnose.LikelyLiveVerdict) {
		t.Fatal("likely live verdict did not trigger alert")
	}
	if IsAlert(diagnose.InsufficientLiveVerdict) {
		t.Fatal("insufficient verdict triggered alert")
	}
}

// TestAlertFormatting verifies alert formatting.
func TestAlertFormatting(t *testing.T) {
	var output bytes.Buffer
	if err := WriteAlert(&output, IterationSummary{
		Victim:  "a-web",
		Suspect: "b-stress",
		Reason:  "dominant syscall pressure",
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ALERT: likely storage-neighbor pressure detected",
		"victim: a-web",
		"suspect: b-stress",
		"reason: dominant syscall pressure",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("alert output missing %q:\n%s", want, output.String())
		}
	}
}

// TestCaptureCooldown verifies capture cooldown.
func TestCaptureCooldown(t *testing.T) {
	now := time.Date(2026, 8, 9, 1, 0, 0, 0, time.UTC)
	if !CaptureAllowed(now, time.Time{}, 2*time.Minute) {
		t.Fatal("first capture was suppressed")
	}
	if CaptureAllowed(now.Add(time.Minute), now, 2*time.Minute) {
		t.Fatal("capture inside cooldown was allowed")
	}
	if !CaptureAllowed(now.Add(2*time.Minute), now, 2*time.Minute) {
		t.Fatal("capture at cooldown boundary was suppressed")
	}
}

// TestFinalSummaryFormatting verifies final summary formatting.
func TestFinalSummaryFormatting(t *testing.T) {
	var output bytes.Buffer
	if err := WriteFinal(&output, FinalSummary{Iterations: 4, Alerts: 2, Captures: 1}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Iterations run:", "4", "Alerts observed:", "2", "Captures written:", "1"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("final output missing %q:\n%s", want, output.String())
		}
	}
}
