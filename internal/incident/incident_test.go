package incident

import (
	"bytes"
	"strings"
	"testing"

	"github.com/safwen511/solis-io/internal/experiment"
)

func TestNewExplanationProbableInterferenceWithoutFailures(t *testing.T) {
	explanation, err := NewExplanation(testReport(), "tenant-a", "b-stress")
	if err != nil {
		t.Fatalf("NewExplanation() error = %v", err)
	}

	want := "Probable noisy-neighbor storage interference. No HTTP failures observed."
	if explanation.Assessment != want {
		t.Fatalf("Assessment = %q, want %q", explanation.Assessment, want)
	}
	if explanation.Impact.ThroughputDropPct != 25 || explanation.Impact.LatencyIncreasePct != 50 {
		t.Fatalf("Impact = %#v, want 25%% throughput drop and 50%% latency increase", explanation.Impact)
	}
}

func TestNewExplanationMentionsApplicationFailures(t *testing.T) {
	report := testReport()
	report.DuringNoise.FailedRequests = 3

	explanation, err := NewExplanation(report, "a-db", "b-stress")
	if err != nil {
		t.Fatalf("NewExplanation() error = %v", err)
	}
	if !strings.Contains(explanation.Assessment, "Application-visible failures observed: 3") {
		t.Fatalf("Assessment = %q, want application-visible failures", explanation.Assessment)
	}
}

func TestNewExplanationNoConclusiveInterference(t *testing.T) {
	report := testReport()
	report.DuringNoise.RequestsPerSecond = 110
	report.DuringNoise.TimePerRequestMS = 90

	explanation, err := NewExplanation(report, "tenant-a", "b-stress")
	if err != nil {
		t.Fatalf("NewExplanation() error = %v", err)
	}
	if !strings.HasPrefix(explanation.Assessment, "No conclusive noisy-neighbor") {
		t.Fatalf("Assessment = %q, want no conclusive signal", explanation.Assessment)
	}
}

func TestWriteExplanation(t *testing.T) {
	explanation, err := NewExplanation(testReport(), "tenant-a", "b-stress")
	if err != nil {
		t.Fatalf("NewExplanation() error = %v", err)
	}

	var output bytes.Buffer
	if err := WriteExplanation(&output, explanation); err != nil {
		t.Fatalf("WriteExplanation() error = %v", err)
	}
	for _, expected := range []string{
		"Report directory:",
		"tenant-a",
		"b-stress",
		"Requests/sec",
		"25.00%",
		"59.9k",
		recommendation,
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("explanation missing %q:\n%s", expected, output.String())
		}
	}
}

func testReport() experiment.Report {
	return experiment.Report{
		Directory: "test-report",
		Baseline: experiment.HTTPMetrics{
			RequestsPerSecond: 100,
			TimePerRequestMS:  100,
		},
		DuringNoise: experiment.HTTPMetrics{
			RequestsPerSecond: 75,
			TimePerRequestMS:  150,
		},
		PostNoise: experiment.HTTPMetrics{
			RequestsPerSecond: 95,
			TimePerRequestMS:  110,
		},
		FIO: experiment.FIOMetrics{
			IOPS:        "59.9k",
			Bandwidth:   "234MiB/s",
			DiskUtilPct: 84.86,
		},
	}
}
