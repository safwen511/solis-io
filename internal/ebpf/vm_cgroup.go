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

// QEMUProcessIdentity is the privacy-safe process identity used to bind
// counter samples to one known libvirt QEMU process. It deliberately excludes
// process arguments and environments.
type QEMUProcessIdentity struct {
	PID            int
	Name           string
	CgroupPath     string
	MachineScope   string
	StartTimeTicks uint64
}

// BuildVMCgroupMappings maps known QEMU PIDs to cgroup v2 inode IDs without
// reading process arguments, process environments, or process memory.
func BuildVMCgroupMappings(vms []inventory.VM) ([]VMBlockCgroupMapping, error) {
	return buildVMCgroupMappings(vms, defaultCgroupRoot, defaultProcRoot)
}

// buildVMCgroupMappings accepts only cgroup IDs tied to the current validated QEMU process identity.
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
		startTime, err := readProcessStartTime(procRoot, pid)
		if err != nil {
			mapping.MappingQuality = "stale_or_unreadable_qemu_pid"
			mappings = append(mappings, mapping)
			continue
		}

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
		confirmedStartTime, err := readProcessStartTime(procRoot, pid)
		if err != nil || confirmedStartTime != startTime {
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

// ValidateMappedQEMUProcess revalidates one mapped PID using only status or
// comm, cgroup, and stat start-time metadata. The PID must still name a QEMU
// process, remain in the same libvirt machine scope, and match the mapper's
// primary cgroup path.
func ValidateMappedQEMUProcess(mapping VMBlockCgroupMapping) (QEMUProcessIdentity, error) {
	return validateMappedQEMUProcess(mapping, defaultProcRoot)
}

// validateMappedQEMUProcess validates mapped qemu process against its required contract.
func validateMappedQEMUProcess(mapping VMBlockCgroupMapping, procRoot string) (QEMUProcessIdentity, error) {
	if mapping.QEMUPID <= 0 {
		return QEMUProcessIdentity{}, errors.New("QEMU PID is unavailable")
	}
	if mapping.MappingQuality != "cgroup_v2_inode_tree" && mapping.MappingQuality != "cgroup_v2_inode_partial" {
		return QEMUProcessIdentity{}, fmt.Errorf("QEMU PID mapping is not verified: %s", firstNonEmpty(mapping.MappingQuality, "unavailable"))
	}
	name, err := readSafeProcessName(procRoot, mapping.QEMUPID)
	if err != nil {
		return QEMUProcessIdentity{}, fmt.Errorf("read QEMU process identity: %w", err)
	}
	if !isQEMUProcessName(name) {
		return QEMUProcessIdentity{}, fmt.Errorf("PID %d is not a QEMU process", mapping.QEMUPID)
	}
	cgroupData, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(mapping.QEMUPID), "cgroup"))
	if err != nil {
		return QEMUProcessIdentity{}, fmt.Errorf("read QEMU cgroup identity: %w", err)
	}
	cgroupPath, err := parseUnifiedCgroupPath(string(cgroupData))
	if err != nil {
		return QEMUProcessIdentity{}, fmt.Errorf("read QEMU cgroup identity: %w", err)
	}
	machineScope, err := libvirtMachineScopeFromPath(cgroupPath)
	if err != nil {
		return QEMUProcessIdentity{}, fmt.Errorf("QEMU process is not in a libvirt machine scope: %w", err)
	}
	if cgroupPath != mapping.PrimaryPath || !containsExactString(mapping.CgroupPaths, cgroupPath) || !containsExactString(mapping.CgroupPaths, machineScope) {
		return QEMUProcessIdentity{}, fmt.Errorf("QEMU process cgroup %q no longer matches mapped libvirt scope", cgroupPath)
	}
	startTime, err := readProcessStartTime(procRoot, mapping.QEMUPID)
	if err != nil {
		return QEMUProcessIdentity{}, fmt.Errorf("read QEMU process start time: %w", err)
	}
	return QEMUProcessIdentity{
		PID: mapping.QEMUPID, Name: name, CgroupPath: cgroupPath,
		MachineScope: machineScope, StartTimeTicks: startTime,
	}, nil
}

// SameQEMUProcessIdentity reports whether two samples refer to the same
// process instance and libvirt cgroup identity.
func SameQEMUProcessIdentity(left, right QEMUProcessIdentity) bool {
	return left.PID > 0 && left.PID == right.PID && left.Name == right.Name &&
		left.CgroupPath == right.CgroupPath && left.MachineScope == right.MachineScope &&
		left.StartTimeTicks > 0 && left.StartTimeTicks == right.StartTimeTicks
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

// parseUnifiedCgroupPath parses and validates unified cgroup path.
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

// cleanCgroupPath accepts absolute normalized cgroup paths and rejects traversal or control bytes.
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

// relatedLibvirtCgroupPaths builds related libvirt cgroup paths and returns an error when
// validation or source access fails.
func relatedLibvirtCgroupPaths(cgroupRoot, primary string) ([]string, error) {
	primary, err := cleanCgroupPath(primary)
	if err != nil {
		return nil, err
	}
	scope, err := libvirtMachineScopeFromPath(primary)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(primary, "/"), "/")
	scopeIndex := len(strings.Split(strings.TrimPrefix(scope, "/"), "/")) - 1
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

// libvirtMachineScopeFromPath builds libvirt machine scope from path and returns an error when
// validation or source access fails.
func libvirtMachineScopeFromPath(path string) (string, error) {
	path, err := cleanCgroupPath(path)
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		if index > 0 && parts[index-1] == "machine.slice" && isLibvirtQEMUScope(part) {
			return "/" + filepath.Join(parts[:index+1]...), nil
		}
	}
	return "", errors.New("libvirt QEMU machine scope not found")
}

// readSafeProcessName reads only /proc/PID/comm; it never reads cmdline or environ.
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

// readProcessStartTime reads process start time from its configured source.
func readProcessStartTime(procRoot string, pid int) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	line := strings.TrimSpace(string(data))
	closing := strings.LastIndex(line, ")")
	if closing < 0 || closing+1 >= len(line) {
		return 0, errors.New("malformed process stat")
	}
	// The suffix starts at field 3 (state); starttime is field 22.
	fields := strings.Fields(line[closing+1:])
	const startTimeIndex = 22 - 3
	if len(fields) <= startTimeIndex {
		return 0, errors.New("process stat starttime unavailable")
	}
	value, err := strconv.ParseUint(fields[startTimeIndex], 10, 64)
	if err != nil || value == 0 {
		return 0, errors.New("invalid process stat starttime")
	}
	return value, nil
}

// parseProcessStatusName parses and validates process status name.
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

// isQEMUProcessName reports whether qemu process name.
func isQEMUProcessName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.HasPrefix(name, "qemu-system-") || name == "qemu-system" || name == "qemu-kvm"
}

// isLibvirtQEMUScope reports whether libvirt qemu scope.
func isLibvirtQEMUScope(component string) bool {
	component = strings.TrimSpace(component)
	if !strings.HasPrefix(component, "machine-qemu") || !strings.HasSuffix(component, ".scope") {
		return false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(component, "machine-qemu"), ".scope")
	return middle != ""
}

// containsExactString reports whether contains exact string.
func containsExactString(values []string, wanted string) bool {
	for _, value := range values {
		if filepath.Clean(value) == filepath.Clean(wanted) {
			return true
		}
	}
	return false
}

// cgroupInode returns the cgroup-v2 directory inode used for exact kernfs-ID matching.
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

// rootedCgroupPath builds rooted cgroup path and returns an error when validation or source access
// fails.
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

// sortedUniqueStrings sorts strings and removes duplicates for deterministic output.
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

// sortedUniqueUint64 sorts uint64 values and removes duplicates for deterministic output.
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
