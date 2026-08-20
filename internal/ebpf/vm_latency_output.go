package ebpf

import (
	"encoding/json"
	"errors"
	"io"
	"sort"
)

// WriteVMBlockLatencyJSON writes one deterministic, privacy-safe JSON report.
func WriteVMBlockLatencyJSON(dst io.Writer, report VMBlockLatencyReport) error {
	if privacyCollected(report) {
		return errors.New("per-VM eBPF latency report cannot record payload, secret, environment, process-argument, guest-file, query-text, or table-data collection")
	}
	report = normalizeVMBlockLatencyReport(report)
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// privacyCollected reports whether privacy collected.
func privacyCollected(report VMBlockLatencyReport) bool {
	privacy := report.Privacy
	return privacy.ProcessArgumentsCollected || privacy.EnvironmentCollected ||
		privacy.GuestFilesCollected || privacy.QueryTextCollected ||
		privacy.TableDataCollected || privacy.RequestBodyCollected ||
		privacy.ResponseBodyCollected || privacy.SecretsCollected
}

// normalizeVMBlockLatencyReport normalizes vm block latency report into its canonical
// representation.
func normalizeVMBlockLatencyReport(report VMBlockLatencyReport) VMBlockLatencyReport {
	if report.SchemaVersion == "" {
		report.SchemaVersion = vmBlockLatencySchemaVersion
	}
	report.VMs = append([]VMBlockLatencyVM(nil), report.VMs...)
	report.Validation.CgroupIOStat = append([]CgroupIOStatDelta(nil), report.Validation.CgroupIOStat...)
	report.Validation.VirshDomstats = append([]VirshBlockDelta(nil), report.Validation.VirshDomstats...)
	report.Validation.QEMUPressure = append([]QEMUPressureSignal(nil), report.Validation.QEMUPressure...)
	report.Validation.Caveats = append([]string(nil), report.Validation.Caveats...)
	report.UnavailableSections = append([]VMBlockLatencyUnavailableSection(nil), report.UnavailableSections...)
	report.Caveats = append([]string(nil), report.Caveats...)
	report.HostSummary.Histogram = append([]VMBlockLatencyHistogramBucket(nil), report.HostSummary.Histogram...)
	report.HostSummary.DeviceOperations = append([]VMBlockLatencyDeviceOperation(nil), report.HostSummary.DeviceOperations...)
	report.VMAttributionPreflight.MissingFields = sortedUniqueStrings(report.VMAttributionPreflight.MissingFields)
	report.VMAttributionPreflight.Caveats = sortedUniqueStrings(report.VMAttributionPreflight.Caveats)
	if report.VMs == nil {
		report.VMs = []VMBlockLatencyVM{}
	}
	if report.Validation.CgroupIOStat == nil {
		report.Validation.CgroupIOStat = []CgroupIOStatDelta{}
	}
	if report.Validation.VirshDomstats == nil {
		report.Validation.VirshDomstats = []VirshBlockDelta{}
	}
	if report.Validation.QEMUPressure == nil {
		report.Validation.QEMUPressure = []QEMUPressureSignal{}
	}
	if report.Validation.Caveats == nil {
		report.Validation.Caveats = []string{}
	}
	if report.UnavailableSections == nil {
		report.UnavailableSections = []VMBlockLatencyUnavailableSection{}
	}
	if report.Caveats == nil {
		report.Caveats = []string{}
	}
	if report.HostSummary.Histogram == nil {
		report.HostSummary.Histogram = emptyVMBlockLatencyBuckets()
	}
	if report.HostSummary.DeviceOperations == nil {
		report.HostSummary.DeviceOperations = []VMBlockLatencyDeviceOperation{}
	}
	if report.VMAttributionPreflight.MissingFields == nil {
		report.VMAttributionPreflight.MissingFields = []string{}
	}
	if report.VMAttributionPreflight.Caveats == nil {
		report.VMAttributionPreflight.Caveats = []string{}
	}
	for index := range report.HostSummary.DeviceOperations {
		operation := &report.HostSummary.DeviceOperations[index]
		operation.Histogram = append([]VMBlockLatencyHistogramBucket(nil), operation.Histogram...)
		if operation.Histogram == nil {
			operation.Histogram = emptyVMBlockLatencyBuckets()
		}
	}
	sort.Slice(report.HostSummary.DeviceOperations, func(left, right int) bool {
		leftOperation := report.HostSummary.DeviceOperations[left]
		rightOperation := report.HostSummary.DeviceOperations[right]
		if leftOperation.Device != rightOperation.Device {
			return leftOperation.Device < rightOperation.Device
		}
		return blockOperationOrder(leftOperation.Operation) < blockOperationOrder(rightOperation.Operation)
	})
	for index := range report.VMs {
		report.VMs[index].Devices = sortedUniqueStrings(report.VMs[index].Devices)
		report.VMs[index].Histogram = append([]VMBlockLatencyHistogramBucket(nil), report.VMs[index].Histogram...)
		report.VMs[index].DeviceOperations = append([]VMBlockLatencyDeviceOperation(nil), report.VMs[index].DeviceOperations...)
		report.VMs[index].Caveats = append([]string(nil), report.VMs[index].Caveats...)
		if report.VMs[index].Histogram == nil {
			report.VMs[index].Histogram = emptyVMBlockLatencyBuckets()
		}
		if report.VMs[index].DeviceOperations == nil {
			report.VMs[index].DeviceOperations = []VMBlockLatencyDeviceOperation{}
		}
		for operationIndex := range report.VMs[index].DeviceOperations {
			operation := &report.VMs[index].DeviceOperations[operationIndex]
			operation.Histogram = append([]VMBlockLatencyHistogramBucket(nil), operation.Histogram...)
			if operation.Histogram == nil {
				operation.Histogram = emptyVMBlockLatencyBuckets()
			}
		}
		sort.Slice(report.VMs[index].DeviceOperations, func(left, right int) bool {
			leftOperation := report.VMs[index].DeviceOperations[left]
			rightOperation := report.VMs[index].DeviceOperations[right]
			if leftOperation.Device != rightOperation.Device {
				return leftOperation.Device < rightOperation.Device
			}
			return blockOperationOrder(leftOperation.Operation) < blockOperationOrder(rightOperation.Operation)
		})
		if report.VMs[index].Caveats == nil {
			report.VMs[index].Caveats = []string{}
		}
	}
	sort.Slice(report.VMs, func(i, j int) bool { return report.VMs[i].Name < report.VMs[j].Name })
	sort.Slice(report.Validation.CgroupIOStat, func(i, j int) bool {
		left, right := report.Validation.CgroupIOStat[i], report.Validation.CgroupIOStat[j]
		if left.VM != right.VM {
			return left.VM < right.VM
		}
		if left.CgroupPath != right.CgroupPath {
			return left.CgroupPath < right.CgroupPath
		}
		return left.Device < right.Device
	})
	sort.Slice(report.Validation.VirshDomstats, func(i, j int) bool {
		left, right := report.Validation.VirshDomstats[i], report.Validation.VirshDomstats[j]
		if left.VM != right.VM {
			return left.VM < right.VM
		}
		return left.Block < right.Block
	})
	sort.Slice(report.Validation.QEMUPressure, func(i, j int) bool {
		return report.Validation.QEMUPressure[i].VM < report.Validation.QEMUPressure[j].VM
	})
	sort.Slice(report.UnavailableSections, func(i, j int) bool {
		left, right := report.UnavailableSections[i], report.UnavailableSections[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return left.Status < right.Status
	})
	return report
}
