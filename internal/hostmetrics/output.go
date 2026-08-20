package hostmetrics

import (
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/safwen511/solis-io/internal/observability"
)

// WriteJSON renders one deterministic, privacy-safe HostStatus document.
func WriteJSON(dst io.Writer, status HostStatus) error {
	if !privacySafe(status.Privacy) {
		return errors.New("host status cannot record payload, secret, environment, process-argument, guest-file, query-text, or table-data collection")
	}
	normalizeHostStatus(&status)
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}

// normalizeHostStatus normalizes host status into its canonical representation.
func normalizeHostStatus(status *HostStatus) {
	if status.SchemaVersion == "" {
		status.SchemaVersion = SchemaVersion
	}
	status.Filesystems.Mounts = append([]FilesystemStatus(nil), status.Filesystems.Mounts...)
	status.Disks.Devices = append([]DiskStatus(nil), status.Disks.Devices...)
	status.NetworkInterfaces.Interfaces = append([]NetworkInterfaceStatus(nil), status.NetworkInterfaces.Interfaces...)
	status.QEMUProcesses.Processes = append([]QEMUProcessStatus(nil), status.QEMUProcesses.Processes...)
	if status.Filesystems.Mounts == nil {
		status.Filesystems.Mounts = []FilesystemStatus{}
	}
	if status.Disks.Devices == nil {
		status.Disks.Devices = []DiskStatus{}
	}
	if status.NetworkInterfaces.Interfaces == nil {
		status.NetworkInterfaces.Interfaces = []NetworkInterfaceStatus{}
	}
	if status.QEMUProcesses.Processes == nil {
		status.QEMUProcesses.Processes = []QEMUProcessStatus{}
	}
	sort.Slice(status.Filesystems.Mounts, func(i, j int) bool {
		return status.Filesystems.Mounts[i].Mountpoint < status.Filesystems.Mounts[j].Mountpoint
	})
	sort.Slice(status.Disks.Devices, func(i, j int) bool {
		return status.Disks.Devices[i].Name < status.Disks.Devices[j].Name
	})
	sort.Slice(status.NetworkInterfaces.Interfaces, func(i, j int) bool {
		return status.NetworkInterfaces.Interfaces[i].Interface < status.NetworkInterfaces.Interfaces[j].Interface
	})
	sort.Slice(status.QEMUProcesses.Processes, func(i, j int) bool {
		return status.QEMUProcesses.Processes[i].PID < status.QEMUProcesses.Processes[j].PID
	})
}

// privacySafe reports whether privacy safe.
func privacySafe(privacy observability.PrivacyFlags) bool {
	return !privacy.ProcessArgumentsCollected && !privacy.EnvironmentCollected &&
		!privacy.GuestFilesCollected && !privacy.QueryTextCollected &&
		!privacy.TableDataCollected && !privacy.RequestBodyCollected &&
		!privacy.ResponseBodyCollected && !privacy.SecretsCollected
}
