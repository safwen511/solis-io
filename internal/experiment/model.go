// Package experiment parses and summarizes Solis workload experiment reports.
package experiment

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
