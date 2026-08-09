package ebpf

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/safwen511/solis-io/internal/inventory"
)

const (
	defaultCgroupRoot = "/sys/fs/cgroup"
	defaultProcRoot   = "/proc"
)

// BuildVMCgroupMappings maps known QEMU PIDs to cgroup v2 inode IDs without
// reading process arguments, process environments, or process memory.
func BuildVMCgroupMappings(vms []inventory.VM) ([]VMBlockCgroupMapping, error) {
	return buildVMCgroupMappings(vms, defaultCgroupRoot, defaultProcRoot)
}

func buildVMCgroupMappings(vms []inventory.VM, cgroupRoot, procRoot string) ([]VMBlockCgroupMapping, error) {
	mappings := make([]VMBlockCgroupMapping, 0, len(vms))
	for _, vm := range vms {
		mapping := VMBlockCgroupMapping{
			Name:           vm.Name,
			Tenant:         vm.Tenant,
			Role:           vm.Role,
			Disk:           vm.Disk,
			CgroupPaths:    []string{},
			CgroupIDs:      []uint64{},
			MappingQuality: "unavailable",
		}
		pid, err := strconv.Atoi(strings.TrimSpace(vm.QEMUPID))
		if err != nil || pid <= 0 {
			mapping.MappingQuality = "missing_qemu_pid"
			mappings = append(mappings, mapping)
			continue
		}
		mapping.QEMUPID = pid
		processName, err := readSafeProcessName(procRoot, pid)
		if err != nil {
			mapping.MappingQuality = "stale_or_unreadable_qemu_pid"
			mappings = append(mappings, mapping)
			continue
		}
		if !isQEMUProcessName(processName) {
			mapping.MappingQuality = "non_qemu_pid"
			mappings = append(mappings, mapping)
			continue
		}

		data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
		if err != nil {
			mapping.MappingQuality = "cgroup_unreadable"
			mappings = append(mappings, mapping)
			continue
		}
		primary, err := parseUnifiedCgroupPath(string(data))
		if err != nil {
			mapping.MappingQuality = "cgroup_v2_path_missing"
			mappings = append(mappings, mapping)
			continue
		}
		mapping.PrimaryPath = primary

		paths, err := relatedLibvirtCgroupPaths(cgroupRoot, primary)
		if err != nil {
			mapping.MappingQuality = "not_libvirt_vm_cgroup"
			mappings = append(mappings, mapping)
			continue
		}
		confirmedName, err := readSafeProcessName(procRoot, pid)
		if err != nil || confirmedName != processName || !isQEMUProcessName(confirmedName) {
			mapping.MappingQuality = "stale_or_reused_qemu_pid"
			mappings = append(mappings, mapping)
			continue
		}
		confirmedCgroup, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
		if err != nil {
			mapping.MappingQuality = "stale_or_reused_qemu_pid"
			mappings = append(mappings, mapping)
			continue
		}
		confirmedPrimary, err := parseUnifiedCgroupPath(string(confirmedCgroup))
		if err != nil || confirmedPrimary != primary {
			mapping.MappingQuality = "stale_or_reused_qemu_pid"
			mappings = append(mappings, mapping)
			continue
		}
		for _, path := range paths {
			id, statErr := cgroupInode(cgroupRoot, path)
			if statErr != nil {
				continue
			}
			mapping.CgroupPaths = append(mapping.CgroupPaths, path)
			mapping.CgroupIDs = append(mapping.CgroupIDs, id)
			if path == primary {
				mapping.PrimaryID = id
			}
		}
		mapping.CgroupPaths = sortedUniqueStrings(mapping.CgroupPaths)
		mapping.CgroupIDs = sortedUniqueUint64(mapping.CgroupIDs)
		switch {
		case mapping.PrimaryID != 0 && len(mapping.CgroupIDs) > 1:
			mapping.MappingQuality = "cgroup_v2_inode_tree"
		case mapping.PrimaryID != 0:
			mapping.MappingQuality = "cgroup_v2_inode_partial"
		default:
			mapping.MappingQuality = "cgroup_inode_unavailable"
		}
		mappings = append(mappings, mapping)
	}

	sort.Slice(mappings, func(i, j int) bool { return mappings[i].Name < mappings[j].Name })
	if _, err := IndexVMCgroupMappings(mappings); err != nil {
		return nil, err
	}
	return mappings, nil
}

// IndexVMCgroupMappings constructs an unambiguous cgroup-ID-to-VM index.
func IndexVMCgroupMappings(mappings []VMBlockCgroupMapping) (map[uint64]int, error) {
	index := make(map[uint64]int)
	owners := make(map[uint64]string)
	for mappingIndex, mapping := range mappings {
		for _, id := range mapping.CgroupIDs {
			if id == 0 {
				continue
			}
			if owner, duplicate := owners[id]; duplicate && owner != mapping.Name {
				return nil, fmt.Errorf("cgroup ID %d maps to both VM %q and VM %q", id, owner, mapping.Name)
			}
			owners[id] = mapping.Name
			index[id] = mappingIndex
		}
	}
	return index, nil
}

func parseUnifiedCgroupPath(data string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[0] != "0" || fields[1] != "" {
			continue
		}
		path, err := cleanCgroupPath(fields[2])
		if err != nil {
			return "", err
		}
		return path, nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("unified cgroup v2 path not found")
}

func cleanCgroupPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("invalid cgroup path %q", path)
	}
	for _, component := range strings.Split(path, "/") {
		if component == ".." {
			return "", fmt.Errorf("unsafe cgroup path %q", path)
		}
	}
	cleaned := filepath.Clean(path)
	if cleaned == "/" || cleaned == "." || strings.HasPrefix(cleaned, "/../") {
		return "", fmt.Errorf("unsafe cgroup path %q", path)
	}
	return cleaned, nil
}

func relatedLibvirtCgroupPaths(cgroupRoot, primary string) ([]string, error) {
	primary, err := cleanCgroupPath(primary)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(primary, "/"), "/")
	scopeIndex := -1
	for index, part := range parts {
		if index > 0 && parts[index-1] == "machine.slice" && isLibvirtQEMUScope(part) {
			scopeIndex = index
			break
		}
	}
	if scopeIndex < 0 {
		return nil, errors.New("libvirt QEMU machine scope not found")
	}
	scope := "/" + filepath.Join(parts[:scopeIndex+1]...)
	scopeDiskPath, err := rootedCgroupPath(cgroupRoot, scope)
	if err != nil {
		return nil, err
	}

	paths := []string{scope, primary}
	for index := scopeIndex + 1; index < len(parts); index++ {
		paths = append(paths, "/"+filepath.Join(parts[:index+1]...))
	}
	err = filepath.WalkDir(scopeDiskPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		relative, relErr := filepath.Rel(scopeDiskPath, path)
		if relErr != nil {
			return nil
		}
		if relative == "." {
			return nil
		}
		depth := len(strings.Split(relative, string(filepath.Separator)))
		if depth > 4 {
			return filepath.SkipDir
		}
		paths = append(paths, filepath.Join(scope, relative))
		return nil
	})
	return sortedUniqueStrings(paths), err
}

func readSafeProcessName(procRoot string, pid int) (string, error) {
	processRoot := filepath.Join(procRoot, strconv.Itoa(pid))
	status, statusErr := os.ReadFile(filepath.Join(processRoot, "status"))
	if statusErr == nil {
		if name := parseProcessStatusName(string(status)); name != "" {
			return name, nil
		}
	}
	comm, commErr := os.ReadFile(filepath.Join(processRoot, "comm"))
	if commErr == nil {
		if name := strings.TrimSpace(string(comm)); name != "" {
			return name, nil
		}
	}
	if statusErr != nil {
		return "", statusErr
	}
	if commErr != nil {
		return "", commErr
	}
	return "", errors.New("process name unavailable")
}

func parseProcessStatusName(data string) string {
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if ok && strings.TrimSpace(key) == "Name" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func isQEMUProcessName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.HasPrefix(name, "qemu-system-") || name == "qemu-system" || name == "qemu-kvm"
}

func isLibvirtQEMUScope(component string) bool {
	component = strings.TrimSpace(component)
	if !strings.HasPrefix(component, "machine-qemu") || !strings.HasSuffix(component, ".scope") {
		return false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(component, "machine-qemu"), ".scope")
	return middle != ""
}

func cgroupInode(cgroupRoot, path string) (uint64, error) {
	diskPath, err := rootedCgroupPath(cgroupRoot, path)
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(diskPath)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return 0, errors.New("cgroup inode unavailable")
	}
	return stat.Ino, nil
}

func rootedCgroupPath(cgroupRoot, path string) (string, error) {
	cleaned, err := cleanCgroupPath(path)
	if err != nil {
		return "", err
	}
	root := filepath.Clean(cgroupRoot)
	joined := filepath.Join(root, strings.TrimPrefix(cleaned, "/"))
	relative, err := filepath.Rel(root, joined)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("cgroup path %q escapes root", path)
	}
	return joined, nil
}

func sortedUniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedUniqueUint64(values []uint64) []uint64 {
	seen := make(map[uint64]bool)
	result := make([]uint64, 0, len(values))
	for _, value := range values {
		if value == 0 || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
