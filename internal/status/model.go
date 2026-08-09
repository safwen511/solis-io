// Package status builds a reusable live VM and storage status model.
package status

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
)

const (
	SchemaVersion = "1"
	PressureIdle  = "idle"
	PressureLow   = "low"
	PressureHigh  = "high"
)

// Report is the common model used by the human and JSON status renderers.
type Report struct {
	SchemaVersion string     `json:"schema_version"`
	Duration      string     `json:"duration"`
	Interval      string     `json:"interval"`
	VMs           []VMStatus `json:"vms"`
}

// VMStatus contains provider-visible identity, topology, and QEMU I/O data.
type VMStatus struct {
	Name                     string  `json:"name"`
	Tenant                   string  `json:"tenant"`
	Role                     string  `json:"role"`
	State                    string  `json:"state"`
	IP                       string  `json:"ip"`
	QEMUPID                  int     `json:"qemu_pid"`
	Disk                     string  `json:"disk"`
	SourceDevice             string  `json:"source_device"`
	ParentDevice             string  `json:"parent_device"`
	PhysicalDisk             string  `json:"physical_disk"`
	AverageWriteMiBPerSecond float64 `json:"avg_write_mib_s"`
	MaxWriteMiBPerSecond     float64 `json:"max_write_mib_s"`
	AverageSyscwPerSecond    float64 `json:"avg_syscw_s"`
	MaxSyscwPerSecond        float64 `json:"max_syscw_s"`
	Pressure                 string  `json:"pressure"`
	Reason                   string  `json:"reason"`
	IOAvailable              bool    `json:"-"`
	IOError                  string  `json:"-"`
}

// Sample combines one enriched VM with its storage and process-I/O evidence.
type Sample struct {
	VM      inventory.VM
	Storage hoststorage.Mapping
	QEMU    qemuio.VMSummary
}

// NewReport creates a deterministic renderer-independent status model.
func NewReport(duration, interval time.Duration, samples []Sample) Report {
	samples = append([]Sample(nil), samples...)
	sort.Slice(samples, func(i, j int) bool { return samples[i].VM.Name < samples[j].VM.Name })
	report := Report{
		SchemaVersion: SchemaVersion,
		Duration:      duration.String(),
		Interval:      interval.String(),
		VMs:           make([]VMStatus, 0, len(samples)),
	}
	for _, sample := range samples {
		pressure, reason := ClassifyPressure(sample.QEMU)
		disk := sample.Storage.DiskPath
		if strings.TrimSpace(disk) == "" {
			disk = sample.VM.Disk
		}
		report.VMs = append(report.VMs, VMStatus{
			Name:                     valueOrDash(sample.VM.Name),
			Tenant:                   valueOrDash(sample.VM.Tenant),
			Role:                     valueOrDash(sample.VM.Role),
			State:                    valueOrDash(sample.VM.State),
			IP:                       vmIP(sample.VM),
			QEMUPID:                  pidNumber(sample.VM.QEMUPID),
			Disk:                     valueOrDash(disk),
			SourceDevice:             valueOrDash(sample.Storage.SourceDevice),
			ParentDevice:             valueOrDash(sample.Storage.ParentDevice),
			PhysicalDisk:             valueOrDash(sample.Storage.PhysicalDisk),
			AverageWriteMiBPerSecond: sample.QEMU.AverageWriteMiBPerSecond,
			MaxWriteMiBPerSecond:     sample.QEMU.MaxWriteMiBPerSecond,
			AverageSyscwPerSecond:    sample.QEMU.AverageSyscwPerSecond,
			MaxSyscwPerSecond:        sample.QEMU.MaxSyscwPerSecond,
			Pressure:                 pressure,
			Reason:                   reason,
			IOAvailable:              sample.QEMU.Available,
			IOError:                  oneLine(sample.QEMU.Error),
		})
	}
	return report
}

// ClassifyPressure applies the centralized qemuio byte and syscall thresholds.
func ClassifyPressure(summary qemuio.VMSummary) (string, string) {
	if !summary.Available {
		reason := oneLine(summary.Error)
		if reason == "" {
			reason = "QEMU process I/O counters unavailable"
		}
		return PressureLow, reason
	}
	if qemuio.MeaningfulWriteBytes(summary.AverageWriteMiBPerSecond) {
		return PressureHigh, "dominant byte write rate"
	}
	if qemuio.MeaningfulWriteSyscalls(summary.AverageSyscwPerSecond) {
		return PressureHigh, "high syscall pressure"
	}
	if qemuio.WriteActivityObserved(summary.AverageWriteMiBPerSecond, summary.AverageSyscwPerSecond) {
		return PressureLow, "low write activity"
	}
	return PressureIdle, "idle"
}

func vmIP(vm inventory.VM) string {
	if strings.TrimSpace(vm.IPLease) != "" {
		return strings.TrimSpace(vm.IPLease)
	}
	return valueOrDash(vm.IPPlan)
}

func pidNumber(value string) int {
	pid, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
