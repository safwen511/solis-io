package hoststorage

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type commandRunner func(name string, args ...string) ([]byte, error)

const defaultSysfsBlockPath = "/sys/class/block"

// Resolve maps a disk file to its containing filesystem and parent block device.
// Unavailable values are left empty for the caller to render as unknown.
func Resolve(diskPath string) Mapping {
	return resolveWithRunnerAndSysfs(diskPath, runCommand, defaultSysfsBlockPath)
}

func resolveWithRunner(diskPath string, run commandRunner) Mapping {
	return resolveWithRunnerAndSysfs(diskPath, run, defaultSysfsBlockPath)
}

func resolveWithRunnerAndSysfs(diskPath string, run commandRunner, sysfsBlockPath string) Mapping {
	diskPath = strings.TrimSpace(diskPath)
	mapping := Mapping{DiskPath: diskPath}
	if diskPath == "" {
		return mapping
	}

	out, err := run("findmnt", "-T", diskPath, "-no", "TARGET,SOURCE,FSTYPE")
	if err != nil {
		return mapping
	}
	mountpoint, source, filesystem, ok := parseFindmnt(out)
	if !ok {
		return mapping
	}
	mapping.Mountpoint = mountpoint
	mapping.SourceDevice = source
	mapping.Filesystem = filesystem

	blockSource := sourceForLSBLK(source)
	if !strings.HasPrefix(blockSource, "/dev/") {
		return mapping
	}
	out, err = run("lsblk", "-no", "PKNAME", blockSource)
	if err == nil {
		mapping.ParentDevice = parseDeviceList(out)
	}

	parents, physicalDisks := resolveSysfsTopology(blockSource, sysfsBlockPath)
	if len(parents) > 0 {
		mapping.ParentDevice = formatDeviceList(parents)
	}
	if len(physicalDisks) > 0 {
		mapping.PhysicalDisk = formatDeviceList(physicalDisks)
	}

	return mapping
}

func runCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func parseFindmnt(output []byte) (string, string, string, bool) {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			return fields[0], fields[1], fields[2], true
		}
	}

	return "", "", "", false
}

func sourceForLSBLK(source string) string {
	if index := strings.IndexByte(source, '['); index >= 0 {
		return source[:index]
	}
	return source
}

func parseDeviceList(output []byte) string {
	var devices []string
	for _, line := range strings.Split(string(output), "\n") {
		device := strings.TrimSpace(line)
		if device == "" || device == "-" {
			continue
		}
		devices = append(devices, device)
	}
	return formatDeviceList(devices)
}

func resolveSysfsTopology(source, sysfsBlockPath string) ([]string, []string) {
	kernelName := kernelBlockName(source, sysfsBlockPath)
	if kernelName == "" {
		return nil, nil
	}

	var parents []string
	if strings.HasPrefix(kernelName, "dm-") {
		parents = terminalSlaves(kernelName, sysfsBlockPath, make(map[string]bool))
	}
	physicalDisks := physicalDisksFor(kernelName, sysfsBlockPath, make(map[string]bool))

	return sortedUnique(parents), sortedUnique(physicalDisks)
}

func kernelBlockName(source, sysfsBlockPath string) string {
	if resolved, err := filepath.EvalSymlinks(source); err == nil {
		name := filepath.Base(resolved)
		if blockEntryExists(sysfsBlockPath, name) {
			return name
		}
	}

	name := filepath.Base(source)
	if blockEntryExists(sysfsBlockPath, name) {
		return name
	}
	if !strings.HasPrefix(source, "/dev/mapper/") {
		return ""
	}

	entries, err := os.ReadDir(sysfsBlockPath)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "dm-") {
			continue
		}
		value, err := os.ReadFile(filepath.Join(sysfsBlockPath, entry.Name(), "dm", "name"))
		if err == nil && strings.TrimSpace(string(value)) == name {
			return entry.Name()
		}
	}

	return ""
}

func terminalSlaves(name, sysfsBlockPath string, visited map[string]bool) []string {
	if visited[name] {
		return nil
	}
	visited[name] = true

	slaves := blockSlaves(name, sysfsBlockPath)
	if len(slaves) == 0 {
		if strings.HasPrefix(name, "dm-") {
			return nil
		}
		return []string{name}
	}

	var terminals []string
	for _, slave := range slaves {
		terminals = append(terminals, terminalSlaves(slave, sysfsBlockPath, visited)...)
	}
	return sortedUnique(terminals)
}

func physicalDisksFor(name, sysfsBlockPath string, visited map[string]bool) []string {
	if visited[name] {
		return nil
	}
	visited[name] = true

	slaves := blockSlaves(name, sysfsBlockPath)
	if len(slaves) > 0 {
		var disks []string
		for _, slave := range slaves {
			disks = append(disks, physicalDisksFor(slave, sysfsBlockPath, visited)...)
		}
		return sortedUnique(disks)
	}

	if parent := partitionParent(name, sysfsBlockPath); parent != "" {
		return physicalDisksFor(parent, sysfsBlockPath, visited)
	}
	if isVirtualBlockDevice(name) {
		return nil
	}
	return []string{name}
}

func blockSlaves(name, sysfsBlockPath string) []string {
	entries, err := os.ReadDir(filepath.Join(sysfsBlockPath, name, "slaves"))
	if err != nil {
		return nil
	}

	var slaves []string
	for _, entry := range entries {
		slaves = append(slaves, entry.Name())
	}
	sort.Strings(slaves)
	return slaves
}

func partitionParent(name, sysfsBlockPath string) string {
	if _, err := os.Stat(filepath.Join(sysfsBlockPath, name, "partition")); err != nil {
		return ""
	}

	resolved, err := filepath.EvalSymlinks(filepath.Join(sysfsBlockPath, name))
	if err != nil {
		return ""
	}
	parent := filepath.Base(filepath.Dir(resolved))
	if parent == name || !blockEntryExists(sysfsBlockPath, parent) {
		return ""
	}
	return parent
}

func blockEntryExists(sysfsBlockPath, name string) bool {
	_, err := os.Stat(filepath.Join(sysfsBlockPath, name))
	return err == nil
}

func isVirtualBlockDevice(name string) bool {
	return strings.HasPrefix(name, "dm-") ||
		strings.HasPrefix(name, "loop") ||
		strings.HasPrefix(name, "ram") ||
		strings.HasPrefix(name, "zram")
}

func formatDeviceList(devices []string) string {
	devices = sortedUnique(devices)
	for i, device := range devices {
		if !strings.HasPrefix(device, "/dev/") {
			devices[i] = "/dev/" + device
		}
	}
	return strings.Join(devices, ",")
}

func sortedUnique(values []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || value == "-" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
