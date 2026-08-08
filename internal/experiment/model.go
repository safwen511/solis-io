// Package experiment parses and summarizes Solis workload experiment reports.
package experiment

import "fmt"

// HTTPMetrics contains the ApacheBench metrics for one experiment phase.
type HTTPMetrics struct {
	FailedRequests    int
	RequestsPerSecond float64
	TimePerRequestMS  float64
	TransferRate      float64
	TransferRateUnit  string
}

// FIOMetrics contains the storage-noise metrics emitted by fio.
type FIOMetrics struct {
	IOPS        string
	Bandwidth   string
	DiskUtilPct float64
}

// Report contains all parsed phases of a workload experiment.
type Report struct {
	Directory   string
	Baseline    HTTPMetrics
	DuringNoise HTTPMetrics
	PostNoise   HTTPMetrics
	FIO         FIOMetrics
}

// Impact contains the HTTP changes measured during the noisy phase.
type Impact struct {
	ThroughputDropPct  float64
	LatencyIncreasePct float64
}

// CalculateImpact compares the during-noise phase with the baseline phase.
func CalculateImpact(report Report) (Impact, error) {
	if report.Baseline.RequestsPerSecond <= 0 {
		return Impact{}, fmt.Errorf("baseline requests per second must be greater than zero")
	}
	if report.Baseline.TimePerRequestMS <= 0 {
		return Impact{}, fmt.Errorf("baseline time per request must be greater than zero")
	}

	return Impact{
		ThroughputDropPct: percentageChange(
			report.Baseline.RequestsPerSecond,
			report.Baseline.RequestsPerSecond-report.DuringNoise.RequestsPerSecond,
		),
		LatencyIncreasePct: percentageChange(
			report.Baseline.TimePerRequestMS,
			report.DuringNoise.TimePerRequestMS-report.Baseline.TimePerRequestMS,
		),
	}, nil
}

func percentageChange(baseline, difference float64) float64 {
	return difference / baseline * 100
}
