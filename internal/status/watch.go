package status

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// PressureCounts summarizes the VM pressure levels in one observation.
type PressureCounts struct {
	High int
	Low  int
	Idle int
}

// WatchFrame identifies one rendered live status observation.
type WatchFrame struct {
	Timestamp time.Time
	Every     time.Duration
	Iteration int
}

// WatchSummary contains cumulative watch-mode counters.
type WatchSummary struct {
	IterationsRun            int
	HighPressureObservations int
}

// SortReport orders VM rows deterministically by an allowed status field.
func SortReport(report *Report, field string) error {
	field = strings.ToLower(strings.TrimSpace(field))
	if field == "" {
		field = "name"
	}
	if !ValidSortField(field) {
		return fmt.Errorf("invalid status sort field %q", field)
	}
	sort.SliceStable(report.VMs, func(i, j int) bool {
		left, right := report.VMs[i], report.VMs[j]
		switch field {
		case "tenant":
			if comparison := compareText(left.Tenant, right.Tenant); comparison != 0 {
				return comparison < 0
			}
		case "role":
			if comparison := compareText(left.Role, right.Role); comparison != 0 {
				return comparison < 0
			}
		case "pressure":
			if pressureRank(left.Pressure) != pressureRank(right.Pressure) {
				return pressureRank(left.Pressure) < pressureRank(right.Pressure)
			}
		case "write":
			if left.AverageWriteMiBPerSecond != right.AverageWriteMiBPerSecond {
				return left.AverageWriteMiBPerSecond > right.AverageWriteMiBPerSecond
			}
		case "syscw":
			if left.AverageSyscwPerSecond != right.AverageSyscwPerSecond {
				return left.AverageSyscwPerSecond > right.AverageSyscwPerSecond
			}
		}
		return compareText(left.Name, right.Name) < 0
	})
	return nil
}

// ValidSortField reports whether a field is supported by status sorting.
func ValidSortField(field string) bool {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "name", "tenant", "role", "pressure", "write", "syscw":
		return true
	default:
		return false
	}
}

// CountPressures counts pressure levels in one report.
func CountPressures(report Report) PressureCounts {
	var counts PressureCounts
	for _, vm := range report.VMs {
		switch strings.ToLower(vm.Pressure) {
		case PressureHigh:
			counts.High++
		case PressureLow:
			counts.Low++
		case PressureIdle:
			counts.Idle++
		}
	}
	return counts
}

// WriteWatchFrame renders one compact status-watch refresh.
func WriteWatchFrame(dst io.Writer, report Report, frame WatchFrame) error {
	if _, err := fmt.Fprintf(
		dst,
		"Solis VM Status Watch\n"+
			"Timestamp: %s\n"+
			"Duration: %s\n"+
			"Interval: %s\n"+
			"Refresh every: %s\n"+
			"Iteration: %d\n\n",
		frame.Timestamp.UTC().Format(time.RFC3339),
		report.Duration,
		report.Interval,
		frame.Every,
		frame.Iteration,
	); err != nil {
		return err
	}
	if err := writeVMTable(dst, report); err != nil {
		return err
	}
	counts := CountPressures(report)
	if _, err := fmt.Fprintf(dst, "\nPressure counts: high: %d, low: %d, idle: %d\n", counts.High, counts.Low, counts.Idle); err != nil {
		return err
	}
	return writeWarnings(dst, report)
}

// WriteWatchSummary renders cumulative counters after a clean stop.
func WriteWatchSummary(dst io.Writer, summary WatchSummary) error {
	_, err := fmt.Fprintf(
		dst,
		"\nSolis VM Status Watch Summary\n"+
			"Iterations run: %d\n"+
			"High-pressure observations: %d\n",
		summary.IterationsRun,
		summary.HighPressureObservations,
	)
	return err
}

func compareText(left, right string) int {
	return strings.Compare(strings.ToLower(left), strings.ToLower(right))
}

func pressureRank(pressure string) int {
	switch strings.ToLower(pressure) {
	case PressureHigh:
		return 0
	case PressureLow:
		return 1
	case PressureIdle:
		return 2
	default:
		return 3
	}
}
