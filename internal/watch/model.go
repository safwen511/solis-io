// Package watch formats and classifies periodic noisy-neighbor observations.
package watch

import (
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/diagnose"
)

// IterationSummary contains the compact operator view for one sample window.
type IterationSummary struct {
	Timestamp                  time.Time
	Victim                     string
	Suspect                    string
	Score                      string
	Reason                     string
	AverageWriteMiBPerSec      float64
	AverageSyscwPerSec         float64
	SuspectMetricsAvailable    bool
	EBPFVMAttributionAvailable bool
	EBPFVMAttributionQuality   string
	EBPFVMUnattributedPercent  float64
	Verdict                    string
}

// FinalSummary contains counters for one watch process lifetime.
type FinalSummary struct {
	Iterations int
	Alerts     int
	Captures   int
}

// NewIterationSummary derives a compact view from an already collected live
// diagnosis. It performs no additional sampling.
func NewIterationSummary(timestamp time.Time, report diagnose.Report) IterationSummary {
	summary := IterationSummary{
		Timestamp: timestamp.UTC(),
		Victim:    report.Inputs.Victim,
		Suspect:   report.Inputs.Suspect,
		Score:     "-",
		Reason:    report.QEMU.Conclusion,
		Verdict:   report.Verdict,
	}
	if report.Discovery != nil {
		summary.Reason = report.Discovery.SelectionReason
		if report.Discovery.Selected == nil {
			summary.Suspect = "-"
		} else {
			summary.Suspect = report.Discovery.Selected.VM.Name
			summary.Score = report.Discovery.Selected.Score
			summary.Reason = report.Discovery.Selected.Reason
		}
	} else {
		summary.Score, summary.Reason = pairwiseClassification(report)
	}
	if summary.Suspect != "" && summary.Suspect != "-" && report.QEMU.SuspectDataAvailable {
		summary.SuspectMetricsAvailable = true
		summary.AverageWriteMiBPerSec = report.QEMU.SuspectAverageWriteMiBPerSecond
		summary.AverageSyscwPerSec = report.QEMU.SuspectAverageSyscwPerSecond
	}
	assessment := diagnose.AssessEBPFVMAttribution(report)
	summary.EBPFVMAttributionAvailable = assessment.Available
	summary.EBPFVMAttributionQuality = assessment.Quality
	summary.EBPFVMUnattributedPercent = assessment.UnattributedPercent
	return summary
}

// IsAlert reports whether one live diagnosis meets the alert condition.
func IsAlert(verdict string) bool {
	return verdict == diagnose.LikelyLiveVerdict
}

// IsAlertReport keeps alerts anchored to the existing non-eBPF live verdict.
// Experimental VM attribution may conservatively veto that verdict, but
// degraded or unavailable attribution can never create an alert by itself.
func IsAlertReport(report diagnose.Report) bool {
	return IsAlert(report.Verdict)
}

// CaptureAllowed applies the capture cooldown. A zero last-capture timestamp
// means no capture has been written yet.
func CaptureAllowed(now, lastCapture time.Time, cooldown time.Duration) bool {
	return lastCapture.IsZero() || !now.Before(lastCapture.Add(cooldown))
}

// pairwiseClassification builds pairwise classification from validated inputs.
func pairwiseClassification(report diagnose.Report) (string, string) {
	qemu := report.QEMU
	switch {
	case qemu.MeaningfulSuspectWritePressure && qemu.SuspectDominant:
		return "HIGH", "dominant byte write rate"
	case !qemu.MeaningfulSuspectWritePressure && qemu.MeaningfulSuspectSyscwPressure && qemu.SuspectSyscwDominant:
		return "HIGH", "dominant syscall pressure"
	case qemu.MeaningfulSuspectWritePressure:
		return "MEDIUM", "write activity, not dominant"
	case qemu.MeaningfulSuspectSyscwPressure:
		return "MEDIUM", "syscall pressure, not dominant"
	case qemu.SuspectDataAvailable:
		return "LOW", "no dominant writer observed"
	default:
		reason := strings.Join(strings.Fields(qemu.Conclusion), " ")
		if reason == "" {
			reason = "QEMU process I/O counters unavailable"
		}
		return "-", reason
	}
}
