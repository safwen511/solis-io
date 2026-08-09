package storagevm

import (
	"encoding/json"
	"errors"
	"io"
	"sort"
)

// WriteJSON renders deterministic, privacy-safe JSON.
func WriteJSON(dst io.Writer, report VMStorageStatsReport) error {
	if privacyCollected(report) {
		return errors.New("VM storage stats cannot record payloads, secrets, environments, process arguments, guest files, query text, or table data")
	}
	report = normalizeReport(report)
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func privacyCollected(report VMStorageStatsReport) bool {
	p := report.Privacy
	return p.ProcessArgumentsCollected || p.EnvironmentCollected || p.GuestFilesCollected ||
		p.QueryTextCollected || p.TableDataCollected || p.RequestBodyCollected ||
		p.ResponseBodyCollected || p.SecretsCollected
}

func normalizeReport(report VMStorageStatsReport) VMStorageStatsReport {
	if report.SchemaVersion == "" {
		report.SchemaVersion = SchemaVersion
	}
	report.VMs = append([]VMStorageStatsVM(nil), report.VMs...)
	report.HostDevices = append([]HostDevice(nil), report.HostDevices...)
	report.Caveats = nonNilStrings(report.Caveats)
	report.UnavailableSections = append([]UnavailableSection(nil), report.UnavailableSections...)
	if report.VMs == nil {
		report.VMs = []VMStorageStatsVM{}
	}
	if report.HostDevices == nil {
		report.HostDevices = []HostDevice{}
	}
	if report.UnavailableSections == nil {
		report.UnavailableSections = []UnavailableSection{}
	}
	for i := range report.VMs {
		vm := &report.VMs[i]
		vm.Caveats = nonNilStrings(vm.Caveats)
		vm.CgroupIOStat.Devices = append([]CgroupIODeviceDelta(nil), vm.CgroupIOStat.Devices...)
		vm.CgroupIOStat.MissingBaselineDevices = sortedUnique(vm.CgroupIOStat.MissingBaselineDevices)
		vm.CgroupIOStat.MissingAfterDevices = sortedUnique(vm.CgroupIOStat.MissingAfterDevices)
		vm.CgroupIOStat.CounterResetDevices = sortedUnique(vm.CgroupIOStat.CounterResetDevices)
		vm.CgroupIOStat.DuplicateDevices = sortedUnique(vm.CgroupIOStat.DuplicateDevices)
		vm.CgroupIOStat.Caveats = nonNilStrings(vm.CgroupIOStat.Caveats)
		vm.VirshDomstats.Disks = append([]VirshVirtualDiskDelta(nil), vm.VirshDomstats.Disks...)
		vm.VirshDomstats.Caveats = nonNilStrings(vm.VirshDomstats.Caveats)
		vm.QEMUPressure.Caveats = nonNilStrings(vm.QEMUPressure.Caveats)
		if vm.CgroupIOStat.Devices == nil {
			vm.CgroupIOStat.Devices = []CgroupIODeviceDelta{}
		}
		if vm.VirshDomstats.Disks == nil {
			vm.VirshDomstats.Disks = []VirshVirtualDiskDelta{}
		}
		for j := range vm.CgroupIOStat.Devices {
			vm.CgroupIOStat.Devices[j].Caveats = nonNilStrings(vm.CgroupIOStat.Devices[j].Caveats)
		}
		for j := range vm.VirshDomstats.Disks {
			vm.VirshDomstats.Disks[j].Caveats = nonNilStrings(vm.VirshDomstats.Disks[j].Caveats)
		}
		sort.Slice(vm.CgroupIOStat.Devices, func(a, b int) bool {
			return vm.CgroupIOStat.Devices[a].DeviceID < vm.CgroupIOStat.Devices[b].DeviceID
		})
		sort.Slice(vm.VirshDomstats.Disks, func(a, b int) bool {
			return vm.VirshDomstats.Disks[a].Target < vm.VirshDomstats.Disks[b].Target
		})
	}
	sort.Slice(report.VMs, func(i, j int) bool { return report.VMs[i].Name < report.VMs[j].Name })
	sort.Slice(report.HostDevices, func(i, j int) bool { return report.HostDevices[i].DeviceID < report.HostDevices[j].DeviceID })
	sort.Slice(report.UnavailableSections, func(i, j int) bool {
		left, right := report.UnavailableSections[i], report.UnavailableSections[j]
		if left.VM != right.VM {
			return left.VM < right.VM
		}
		if left.Section != right.Section {
			return left.Section < right.Section
		}
		return left.Status < right.Status
	})
	return report
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return append([]string(nil), values...)
}

func sortedUnique(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
