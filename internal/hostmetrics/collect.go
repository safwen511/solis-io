package hostmetrics

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/safwen511/solis-io/internal/observability"
)

const (
	defaultProcRoot       = "/proc"
	defaultSysRoot        = "/sys"
	defaultSampleInterval = time.Second
	libvirtImagesPath     = "/var/lib/libvirt/images"
)

var errDisabled = errors.New("disabled by configuration")

// Options controls local collection. ProcRoot and Mountpoints primarily make
// fixture-based testing possible; the CLI uses fixed Linux defaults.
type Options struct {
	Interval       time.Duration
	CollectPSI     bool
	CollectNetwork bool
	Mountpoints    []string
	ProcRoot       string
	SysRoot        string
	WindowID       string
}

type dependencies struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	statfs   func(string, *syscall.Statfs_t) error
	hostname func() (string, error)
	now      func() time.Time
	sleep    func(time.Duration)
}

type filesystemTarget struct {
	path     string
	optional bool
}

// DefaultOptions enables local PSI and network counter collection over a
// one-second window. No privileged or remote access is performed.
func DefaultOptions() Options {
	return Options{
		Interval:       defaultSampleInterval,
		CollectPSI:     true,
		CollectNetwork: true,
		ProcRoot:       defaultProcRoot,
		SysRoot:        defaultSysRoot,
	}
}

// Collect reads fixed local procfs/statfs sources twice and returns a partial-
// failure-tolerant host snapshot. Only invalid options return an error.
func Collect(options Options) (HostStatus, error) {
	return collectWith(options, dependencies{
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statfs:   syscall.Statfs,
		hostname: os.Hostname,
		now:      time.Now,
		sleep:    time.Sleep,
	})
}

// collectWith collects with from the configured evidence sources.
func collectWith(options Options, deps dependencies) (HostStatus, error) {
	if options.Interval <= 0 {
		return HostStatus{}, errors.New("host metrics interval must be positive")
	}
	if strings.TrimSpace(options.ProcRoot) == "" {
		options.ProcRoot = defaultProcRoot
	}
	if strings.TrimSpace(options.SysRoot) == "" {
		options.SysRoot = defaultSysRoot
	}
	if deps.readFile == nil || deps.readDir == nil || deps.statfs == nil || deps.hostname == nil || deps.now == nil || deps.sleep == nil {
		return HostStatus{}, errors.New("host metrics dependencies are incomplete")
	}

	procStatPath := filepath.Join(options.ProcRoot, "stat")
	diskstatsPath := filepath.Join(options.ProcRoot, "diskstats")
	netDevPath := filepath.Join(options.ProcRoot, "net", "dev")

	previousCPU, previousCPUErr := readCPU(deps.readFile, procStatPath)
	previousDisks, previousDisksErr := readDisks(deps.readFile, diskstatsPath)
	var previousNetwork map[string]networkCounters
	var previousNetworkErr error
	if options.CollectNetwork {
		previousNetwork, previousNetworkErr = readNetwork(deps.readFile, netDevPath)
	}

	deps.sleep(options.Interval)

	status := HostStatus{
		SchemaVersion: SchemaVersion,
		ObservedAtUTC: deps.now().UTC().Format(time.RFC3339Nano),
		WindowID:      options.WindowID,
		Privacy:       observability.PrivacyFlags{},
	}
	status.Hostname, _ = deps.hostname()
	status.KernelRelease = readTrimmed(deps.readFile, filepath.Join(options.ProcRoot, "sys", "kernel", "osrelease"))
	status.CPU = collectCPU(deps.readFile, procStatPath, previousCPU, previousCPUErr)
	status.Memory = collectMemory(deps.readFile, filepath.Join(options.ProcRoot, "meminfo"))
	status.PSI = collectPSI(deps.readFile, options)
	status.Filesystems = collectFilesystems(options, deps.statfs)
	status.Disks = collectDisks(deps.readFile, deps.readDir, diskstatsPath, previousDisks, previousDisksErr, options)
	status.NetworkInterfaces = collectNetwork(deps.readFile, netDevPath, previousNetwork, previousNetworkErr, options)
	status.QEMUProcesses = collectQEMUProcesses(deps.readFile, deps.readDir, options.ProcRoot)
	status.Availability = hostAvailability(status)
	return status, nil
}

// readCPU reads cpu from its configured source.
func readCPU(readFile func(string) ([]byte, error), path string) (cpuCounters, error) {
	data, err := readFile(path)
	if err != nil {
		return cpuCounters{}, err
	}
	return parseProcStat(data)
}

// collectCPU collects cpu from the configured evidence sources.
func collectCPU(readFile func(string) ([]byte, error), path string, previous cpuCounters, previousErr error) CPUStatus {
	current, currentErr := readCPU(readFile, path)
	if err := firstError(previousErr, currentErr); err != nil {
		return CPUStatus{Availability: unavailable(path, err)}
	}
	status, err := calculateCPU(previous, current, path)
	if err != nil {
		return CPUStatus{Availability: unavailable(path, err)}
	}
	return status
}

// collectMemory collects memory from the configured evidence sources.
func collectMemory(readFile func(string) ([]byte, error), path string) MemoryStatus {
	data, err := readFile(path)
	if err != nil {
		return MemoryStatus{Availability: unavailable(path, err)}
	}
	status, err := parseMemInfo(data, path)
	if err != nil {
		return MemoryStatus{Availability: unavailable(path, err)}
	}
	return status
}

// collectPSI collects psi from the configured evidence sources.
func collectPSI(readFile func(string) ([]byte, error), options Options) PSIStatus {
	pressureRoot := filepath.Join(options.ProcRoot, "pressure")
	if !options.CollectPSI {
		return PSIStatus{Availability: disabled(pressureRoot)}
	}
	type resource struct {
		name string
		dst  *PSIResourceStatus
	}
	status := PSIStatus{}
	resources := []resource{{"cpu", &status.CPU}, {"memory", &status.Memory}, {"io", &status.IO}}
	var failures []string
	for _, item := range resources {
		path := filepath.Join(pressureRoot, item.name)
		data, err := readFile(path)
		if err == nil {
			*item.dst, err = parsePSI(data, path)
		}
		if err != nil {
			item.dst.Availability = unavailable(path, err)
			failures = append(failures, item.name+": "+strings.Join(strings.Fields(err.Error()), " "))
		}
	}
	if len(failures) == 0 {
		status.Availability = measured(pressureRoot)
	} else {
		status.Availability = unavailable(pressureRoot, errors.New(strings.Join(failures, "; ")))
	}
	return status
}

// filesystemTargets builds filesystem targets from validated inputs.
func filesystemTargets(options Options) []filesystemTarget {
	if options.Mountpoints != nil {
		targets := make([]filesystemTarget, 0, len(options.Mountpoints))
		for _, path := range options.Mountpoints {
			if path = strings.TrimSpace(path); path != "" {
				targets = append(targets, filesystemTarget{path: filepath.Clean(path)})
			}
		}
		return targets
	}
	return []filesystemTarget{{path: "/"}, {path: libvirtImagesPath, optional: true}}
}

// collectFilesystems collects filesystems from the configured evidence sources.
func collectFilesystems(options Options, statfs func(string, *syscall.Statfs_t) error) FilesystemSection {
	targets := filesystemTargets(options)
	section := FilesystemSection{Mounts: []FilesystemStatus{}}
	if len(targets) == 0 {
		section.Availability = unavailable("statfs", errors.New("no filesystem mountpoints configured"))
		return section
	}
	var failures []string
	for _, target := range targets {
		var stat syscall.Statfs_t
		if err := statfs(target.path, &stat); err != nil {
			if target.optional && errors.Is(err, os.ErrNotExist) {
				continue
			}
			section.Mounts = append(section.Mounts, FilesystemStatus{
				Mountpoint: target.path, Availability: unavailable(target.path, err),
			})
			failures = append(failures, target.path+": "+strings.Join(strings.Fields(err.Error()), " "))
			continue
		}
		status, err := filesystemStatusFromStatfs(target.path, stat)
		if err != nil {
			status = FilesystemStatus{Mountpoint: target.path, Availability: unavailable(target.path, err)}
			failures = append(failures, target.path+": "+err.Error())
		}
		section.Mounts = append(section.Mounts, status)
	}
	sort.Slice(section.Mounts, func(i, j int) bool { return section.Mounts[i].Mountpoint < section.Mounts[j].Mountpoint })
	if len(failures) == 0 {
		section.Availability = measured("statfs")
	} else {
		section.Availability = unavailable("statfs", errors.New(strings.Join(failures, "; ")))
	}
	return section
}

// readDisks reads disks from its configured source.
func readDisks(readFile func(string) ([]byte, error), path string) (map[string]diskCounters, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return parseDiskstats(data)
}

// collectDisks collects disks from the configured evidence sources.
func collectDisks(readFile func(string) ([]byte, error), readDir func(string) ([]os.DirEntry, error), path string, previous map[string]diskCounters, previousErr error, options Options) DiskSection {
	current, currentErr := readDisks(readFile, path)
	if currentErr != nil {
		return DiskSection{Availability: unavailable(path, currentErr), Devices: []DiskStatus{}}
	}
	sysBlockPath := filepath.Join(options.SysRoot, "class", "block")
	blockNames, sysfsErr := readBlockDeviceNames(readDir, sysBlockPath)
	if sysfsErr == nil {
		current = filterDiskCounters(current, blockNames)
		previous = filterDiskCounters(previous, blockNames)
	}
	section := DiskSection{Availability: measured(path), Devices: diskStatuses(previous, current, options.Interval, path)}
	if sysfsErr != nil {
		section.Availability.Error = "sysfs block inventory unavailable: " + strings.Join(strings.Fields(sysfsErr.Error()), " ")
	}
	if previousErr != nil {
		for index := range section.Devices {
			section.Devices[index].RateAvailability = unavailable(path, fmt.Errorf("previous disk sample: %w", previousErr))
		}
	}
	return section
}

// readBlockDeviceNames reads block device names from its configured source.
func readBlockDeviceNames(readDir func(string) ([]os.DirEntry, error), path string) (map[string]struct{}, error) {
	entries, err := readDir(path)
	if err != nil {
		return nil, err
	}
	names := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = struct{}{}
	}
	if len(names) == 0 {
		return nil, errors.New("sysfs block inventory is empty")
	}
	return names, nil
}

// filterDiskCounters filters disk counters according to the configured criteria.
func filterDiskCounters(counters map[string]diskCounters, names map[string]struct{}) map[string]diskCounters {
	filtered := make(map[string]diskCounters)
	for name, counter := range counters {
		if _, present := names[name]; present {
			filtered[name] = counter
		}
	}
	return filtered
}

// readNetwork reads network from its configured source.
func readNetwork(readFile func(string) ([]byte, error), path string) (map[string]networkCounters, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return parseNetDev(data)
}

// collectNetwork collects network from the configured evidence sources.
func collectNetwork(readFile func(string) ([]byte, error), path string, previous map[string]networkCounters, previousErr error, options Options) NetworkSection {
	if !options.CollectNetwork {
		return NetworkSection{Availability: disabled(path), Interfaces: []NetworkInterfaceStatus{}}
	}
	current, currentErr := readNetwork(readFile, path)
	if currentErr != nil {
		return NetworkSection{Availability: unavailable(path, currentErr), Interfaces: []NetworkInterfaceStatus{}}
	}
	section := NetworkSection{Availability: measured(path), Interfaces: networkStatuses(previous, current, options.Interval, path)}
	if previousErr != nil {
		for index := range section.Interfaces {
			section.Interfaces[index].RateAvailability = unavailable(path, fmt.Errorf("previous network sample: %w", previousErr))
		}
	}
	return section
}

// collectQEMUProcesses collects qemu processes from the configured evidence sources.
func collectQEMUProcesses(readFile func(string) ([]byte, error), readDir func(string) ([]os.DirEntry, error), procRoot string) QEMUProcessSection {
	entries, err := readDir(procRoot)
	if err != nil {
		return QEMUProcessSection{Availability: unavailable(procRoot, err), Processes: []QEMUProcessStatus{}}
	}
	processes := make([]QEMUProcessStatus, 0)
	for _, entry := range entries {
		pid, numeric := numericPID(entry.Name())
		if !numeric || !entry.IsDir() {
			continue
		}
		processRoot := filepath.Join(procRoot, entry.Name())
		commPath := filepath.Join(processRoot, "comm")
		comm, err := readFile(commPath)
		command, qemu := qemuCommand(comm)
		if err != nil || !qemu {
			continue
		}
		process := QEMUProcessStatus{PID: pid, Command: command, Availability: measured(commPath)}
		var partial []string
		if data, readErr := readFile(filepath.Join(processRoot, "status")); readErr != nil {
			partial = append(partial, "rss: "+readErr.Error())
		} else if rss, parseErr := parseRSSBytes(data); parseErr != nil {
			partial = append(partial, "rss: "+parseErr.Error())
		} else {
			process.RSSBytes = uint64Pointer(rss)
		}
		if data, readErr := readFile(filepath.Join(processRoot, "stat")); readErr != nil {
			partial = append(partial, "cpu ticks: "+readErr.Error())
		} else if ticks, parseErr := parseProcessCPUTicks(data); parseErr != nil {
			partial = append(partial, "cpu ticks: "+parseErr.Error())
		} else {
			process.CPUTicks = uint64Pointer(ticks)
		}
		if len(partial) > 0 {
			process.Availability.Error = strings.Join(partial, "; ")
		}
		processes = append(processes, process)
	}
	sort.Slice(processes, func(i, j int) bool { return processes[i].PID < processes[j].PID })
	return QEMUProcessSection{Availability: measured(procRoot), Processes: processes}
}

// hostAvailability builds host availability from validated inputs.
func hostAvailability(status HostStatus) observability.Availability {
	const source = "local Linux procfs/sysfs/statfs"
	available := status.CPU.Availability.Available || status.Memory.Availability.Available ||
		status.Filesystems.Availability.Available || status.Disks.Availability.Available ||
		status.NetworkInterfaces.Availability.Available || status.QEMUProcesses.Availability.Available
	if !available {
		return unavailable(source, errors.New("all host metric sections unavailable"))
	}
	return measured(source)
}

// readTrimmed reads trimmed from its configured source.
func readTrimmed(readFile func(string) ([]byte, error), path string) string {
	data, err := readFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// firstError completes first error and returns any failure to its caller.
func firstError(errorsToCheck ...error) error {
	for _, err := range errorsToCheck {
		if err != nil {
			return err
		}
	}
	return nil
}

// uint64Pointer builds uint64 pointer from validated inputs.
func uint64Pointer(value uint64) *uint64 {
	return &value
}
