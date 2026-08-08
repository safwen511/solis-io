// Package doctor performs read-only Solis host and lab readiness checks.
package doctor

// Status is the outcome of one readiness check.
type Status string

const (
	OK   Status = "OK"
	WARN Status = "WARN"
	FAIL Status = "FAIL"
	SKIP Status = "SKIP"
)

// Check contains one readiness result and optional remediation.
type Check struct {
	Status      Status
	Name        string
	Detail      string
	Remediation string
}

// Report contains all doctor sections in deterministic order.
type Report struct {
	Host      []Check
	Lab       []Check
	Inventory []Check
	Storage   []Check
	QEMU      []Check
}

// OverallResult returns FAIL, WARN, or PASS based on all checks.
func OverallResult(report Report) string {
	hasWarning := false
	for _, checks := range [][]Check{report.Host, report.Lab, report.Inventory, report.Storage, report.QEMU} {
		for _, check := range checks {
			switch check.Status {
			case FAIL:
				return "FAIL"
			case WARN:
				hasWarning = true
			}
		}
	}
	if hasWarning {
		return "WARN"
	}
	return "PASS"
}
