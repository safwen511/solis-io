// Package ebpf provides experimental, temporary eBPF block observability and
// privacy-safe models for future per-VM attribution.
package ebpf

// Status is the outcome of one eBPF readiness check.
type Status string

const (
	OK   Status = "OK"
	WARN Status = "WARN"
	FAIL Status = "FAIL"
)

// Check contains one readiness result.
type Check struct {
	Status Status
	Name   string
	Detail string
}

// Report contains eBPF readiness checks in deterministic output order.
type Report struct {
	Checks    []Check
	TraceRoot string
}

// Ready reports whether all required eBPF prerequisites passed.
func Ready(report Report) bool {
	for _, check := range report.Checks {
		if check.Status == FAIL {
			return false
		}
	}
	return true
}
