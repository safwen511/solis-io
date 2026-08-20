// Package incident explains workload incidents using parsed experiment evidence.
package incident

import (
	"fmt"
	"strings"

	"github.com/safwen511/solis-io/internal/experiment"
)

const recommendation = "Inspect host block telemetry for the suspect VM and victim DB disk during the incident window."

// Explanation contains the evidence and diagnosis for one incident report.
type Explanation struct {
	Report         experiment.Report
	Victim         string
	Suspect        string
	Impact         experiment.Impact
	Assessment     string
	Recommendation string
}

// NewExplanation builds an incident explanation from a parsed experiment report.
func NewExplanation(report experiment.Report, victim, suspect string) (Explanation, error) {
	victim = strings.TrimSpace(victim)
	suspect = strings.TrimSpace(suspect)
	if victim == "" {
		return Explanation{}, fmt.Errorf("victim must not be empty")
	}
	if suspect == "" {
		return Explanation{}, fmt.Errorf("suspect must not be empty")
	}

	impact, err := experiment.CalculateImpact(report)
	if err != nil {
		return Explanation{}, err
	}

	return Explanation{
		Report:         report,
		Victim:         victim,
		Suspect:        suspect,
		Impact:         impact,
		Assessment:     assess(report, impact),
		Recommendation: recommendation,
	}, nil
}

// assess derives stable operator-facing text for assess.
func assess(report experiment.Report, impact experiment.Impact) string {
	assessment := "No conclusive noisy-neighbor storage interference signal."
	if impact.ThroughputDropPct > 0 && impact.LatencyIncreasePct > 0 {
		assessment = "Probable noisy-neighbor storage interference."
	}

	failedRequests := report.Baseline.FailedRequests +
		report.DuringNoise.FailedRequests +
		report.PostNoise.FailedRequests
	if failedRequests > 0 {
		return fmt.Sprintf(
			"%s Application-visible failures observed: %d failed requests across all phases.",
			assessment,
			failedRequests,
		)
	}

	return assessment + " No HTTP failures observed."
}
