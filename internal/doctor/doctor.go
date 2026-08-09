package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/safwen511/solis-io/internal/config"
	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
)

const (
	fioScriptPath      = "lab/scripts/run-fio-noise.sh"
	startVMRemedy      = "start VMs with virsh start <vm>"
	qemuSudoRemedy     = "run qemu io commands with sudo"
	buildRemedy        = "build with go build -o solis ./cmd/solis"
	writeExecuteAccess = 3
)

// Options controls product and optional lab readiness checks.
type Options struct {
	Root              string
	InventoryCSV      string
	CaptureOutputRoot string
	DefaultReportDir  string
	LibvirtURI        string
	ConfigSource      string
	SchemaVersion     string
	Observability     *config.ObservabilityConfig
	Lab               bool
	ProcPath          string
	SysPath           string
	Probes            *Probes
}

// Run performs all read-only readiness checks relative to the repository root.
func Run(root string) Report {
	defaults := config.DevelopmentDefaults().Settings
	return RunWithOptions(Options{
		Root:              root,
		InventoryCSV:      filepath.Join(root, defaults.InventoryCSV),
		CaptureOutputRoot: filepath.Join(root, defaults.CaptureOutputRoot),
		DefaultReportDir:  filepath.Join(root, defaults.DefaultReportDir),
		LibvirtURI:        defaults.LibvirtURI,
		ConfigSource:      config.BuiltInDefaultsSource,
		SchemaVersion:     defaults.SchemaVersion,
		Observability:     defaults.Observability,
	})
}

// RunWithOptions performs product checks and optional repository lab checks.
func RunWithOptions(options Options) Report {
	if strings.TrimSpace(options.Root) == "" {
		options.Root = "."
	}
	if strings.TrimSpace(options.ProcPath) == "" {
		options.ProcPath = "/proc"
	}
	if strings.TrimSpace(options.SysPath) == "" {
		options.SysPath = "/sys"
	}
	probes := effectiveProbes(options.Probes)
	report := Report{}
	report.Config = configurationChecks(options, probes)
	report.Host = hostChecks(options, probes)
	report.Observability = observabilityChecks(options.Observability)
	report.Privacy = privacyChecks()
	if options.Lab {
		report.Lab = labChecks(options)
	}

	vms, err := inventory.LoadFromConfig(options.InventoryCSV)
	if err != nil {
		report.Inventory = unavailableInventoryChecks(err, options.InventoryCSV)
		report.Storage = unavailableStorageChecks()
		report.QEMU = []Check{{Status: SKIP, Name: "QEMU process I/O permission", Detail: "VM inventory is unavailable"}}
		return report
	}

	report.Inventory, vms = inventoryChecks(vms, options.InventoryCSV, options.LibvirtURI)
	report.Storage = storageChecks(vms)
	report.QEMU = qemuChecks(vms)
	return report
}

func hostChecks(options Options, probes Probes) []Check {
	goos := probes.GOOS()
	checks := []Check{
		{Status: OK, Name: "OS is Linux", Detail: goos},
		directoryReadableCheck(probes, options.ProcPath, "/proc readable"),
		directoryReadableCheck(probes, options.SysPath, "/sys readable"),
	}
	if goos != "linux" {
		checks[0] = Check{Status: FAIL, Name: "OS is Linux", Detail: goos, Remediation: "run Solis on a Linux host"}
	}

	virsh := executableCheck(probes, "virsh", "virsh command", "install libvirt/virsh")
	checks = append(checks, virsh)
	checks = append(checks, libvirtAccessCheck(options.LibvirtURI, virsh.Status, probes))
	checks = append(checks,
		executableCheck(probes, "findmnt", "findmnt command", "install findmnt (util-linux)"),
		executableCheck(probes, "lsblk", "lsblk command", "install lsblk (util-linux)"),
		rootUsageCheck(probes.EffectiveUID()),
		Check{Status: SKIP, Name: "Go build", Detail: "not checked at runtime", Remediation: buildRemedy},
	)
	return checks
}

func labChecks(options Options) []Check {
	checks := []Check{
		pathCheck(options.InventoryCSV, options.InventoryCSV+" exists", false),
		pathCheck(filepath.Join(options.Root, fioScriptPath), fioScriptPath+" exists", false),
	}
	if strings.TrimSpace(options.DefaultReportDir) != "" {
		checks = append(checks, pathCheck(options.DefaultReportDir, options.DefaultReportDir+" exists", true))
	}
	return checks
}

func configurationChecks(options Options, probes Probes) []Check {
	source := valueOrDefault(options.ConfigSource, config.BuiltInDefaultsSource)
	schema := valueOrDefault(options.SchemaVersion, "unknown")
	schemaCheck := Check{Status: OK, Name: "Config schema version", Detail: schema}
	if schema != config.SchemaVersion && schema != config.SchemaVersion2 {
		schemaCheck = Check{Status: WARN, Name: "Config schema version", Detail: schema, Remediation: "use a supported schema_version"}
	}
	checks := []Check{
		{Status: OK, Name: "Config source", Detail: source},
		schemaCheck,
		fileReadableCheck(probes, options.InventoryCSV, "Inventory file"),
	}
	return append(checks, captureOutputChecks(probes, options.CaptureOutputRoot)...)
}

func fileReadableCheck(probes Probes, path, name string) Check {
	path = strings.TrimSpace(path)
	if path == "" {
		return Check{Status: FAIL, Name: name, Detail: "not configured", Remediation: "configure inventory_csv"}
	}
	info, err := probes.Stat(path)
	if err != nil {
		return Check{Status: FAIL, Name: name, Detail: err.Error(), Remediation: "verify " + path}
	}
	if !info.Mode().IsRegular() {
		return Check{Status: FAIL, Name: name, Detail: "not a regular file: " + path, Remediation: "verify " + path}
	}
	if err := probes.OpenReadable(path); err != nil {
		return Check{Status: FAIL, Name: name, Detail: err.Error(), Remediation: "grant read access to " + path}
	}
	return Check{Status: OK, Name: name, Detail: path}
}

func captureOutputChecks(probes Probes, configuredPath string) []Check {
	configuredPath = strings.TrimSpace(configuredPath)
	if configuredPath == "" {
		return []Check{
			{Status: WARN, Name: "Capture output writable", Detail: "not configured", Remediation: "configure capture_output_root"},
			{Status: SKIP, Name: "Capture output ownership", Detail: "not configured"},
			{Status: SKIP, Name: "Capture output permissions", Detail: "not configured"},
		}
	}
	checkedPath, info, err := nearestExistingDirectory(probes, configuredPath)
	if err != nil {
		return []Check{
			{Status: WARN, Name: "Capture output writable", Detail: err.Error(), Remediation: "verify capture_output_root and parent access"},
			{Status: SKIP, Name: "Capture output ownership", Detail: "directory unavailable"},
			{Status: SKIP, Name: "Capture output permissions", Detail: "directory unavailable"},
		}
	}
	detail := checkedPath
	if filepath.Clean(checkedPath) != filepath.Clean(configuredPath) {
		detail = "nearest existing parent: " + checkedPath
	}
	writable := Check{Status: OK, Name: "Capture output writable", Detail: detail}
	if err := probes.Access(checkedPath, writeExecuteAccess); err != nil {
		writable = Check{Status: WARN, Name: "Capture output writable", Detail: err.Error(), Remediation: "grant write and execute access to " + checkedPath}
	}

	ownership := Check{Status: SKIP, Name: "Capture output ownership", Detail: "ownership unavailable for " + checkedPath}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		owner := int(stat.Uid)
		ownership = Check{Status: OK, Name: "Capture output ownership", Detail: fmt.Sprintf("uid %d", owner)}
		if owner != probes.EffectiveUID() {
			ownership = Check{
				Status:      WARN,
				Name:        "Capture output ownership",
				Detail:      fmt.Sprintf("%s is owned by uid %d; current euid is %d", checkedPath, owner, probes.EffectiveUID()),
				Remediation: "use an operator-owned capture directory",
			}
		}
	}

	permissions := Check{Status: OK, Name: "Capture output permissions", Detail: fmt.Sprintf("%s mode %04o", checkedPath, info.Mode().Perm())}
	if info.Mode().Perm()&0o022 != 0 {
		permissions = Check{
			Status:      WARN,
			Name:        "Capture output permissions",
			Detail:      fmt.Sprintf("%s mode %04o is group/world writable", checkedPath, info.Mode().Perm()),
			Remediation: "remove unnecessary group/world write permission from the capture parent",
		}
	}
	return []Check{writable, ownership, permissions}
}

func nearestExistingDirectory(probes Probes, path string) (string, os.FileInfo, error) {
	candidate := filepath.Clean(path)
	for {
		info, err := probes.Stat(candidate)
		if err == nil {
			if !info.IsDir() {
				return "", nil, fmt.Errorf("capture output path is not a directory: %s", candidate)
			}
			return candidate, info, nil
		}
		if !os.IsNotExist(err) {
			return "", nil, fmt.Errorf("inspect capture output path %s: %w", candidate, err)
		}
		next := filepath.Dir(candidate)
		if next == candidate {
			return "", nil, fmt.Errorf("no existing parent for capture output path %s", path)
		}
		candidate = next
	}
}

func observabilityChecks(observability *config.ObservabilityConfig) []Check {
	if observability == nil {
		return []Check{
			{Status: SKIP, Name: "Host collector", Detail: "not configured"},
			{Status: SKIP, Name: "Guest collector", Detail: "disabled"},
			{Status: SKIP, Name: "Service definitions", Detail: "0 configured"},
			{Status: SKIP, Name: "Database definitions", Detail: "0 configured"},
		}
	}
	host := Check{Status: SKIP, Name: "Host collector", Detail: "disabled"}
	if observability.Host.Enabled {
		host = Check{Status: OK, Name: "Host collector", Detail: "enabled; interval " + valueOrDefault(observability.Host.Interval, "default")}
	}
	guest := Check{Status: SKIP, Name: "Guest collector", Detail: "disabled"}
	if observability.Guest.Enabled {
		guest = Check{Status: OK, Name: "Guest collector", Detail: fmt.Sprintf("enabled; transport %s; max_parallel %d", observability.Guest.Transport, observability.Guest.MaxParallel)}
	}
	services := Check{Status: SKIP, Name: "Service definitions", Detail: fmt.Sprintf("%d configured", len(observability.Services))}
	if len(observability.Services) > 0 {
		services.Status = OK
	}
	databases := Check{Status: SKIP, Name: "Database definitions", Detail: fmt.Sprintf("%d configured", len(observability.Databases))}
	if len(observability.Databases) > 0 {
		databases.Status = OK
	}
	return []Check{host, guest, services, databases}
}

func privacyChecks() []Check {
	return []Check{
		{Status: OK, Name: "Process arguments", Detail: "not collected by observability/capture paths"},
		{Status: OK, Name: "Environment variables", Detail: "not collected"},
		{Status: OK, Name: "Guest files", Detail: "not collected"},
		{Status: OK, Name: "Request bodies", Detail: "not collected"},
		{Status: OK, Name: "Response bodies", Detail: "not collected"},
		{Status: OK, Name: "SQL text", Detail: "not collected"},
		{Status: OK, Name: "Table data", Detail: "not collected"},
		{Status: OK, Name: "Secrets", Detail: "not collected"},
	}
}

func inventoryChecks(vms []inventory.VM, inventoryPath, libvirtURI string) ([]Check, []inventory.VM) {
	checks := []Check{{Status: OK, Name: "Can read configured VMs", Detail: inventoryPath}}
	configured := len(vms)
	if configured == 0 {
		checks = append(checks,
			Check{Status: FAIL, Name: "Configured VMs", Detail: "0", Remediation: "add VM rows to " + inventoryPath},
			Check{Status: SKIP, Name: "Running VMs", Detail: "no configured VMs"},
			Check{Status: SKIP, Name: "VMs with QEMU PID", Detail: "no configured VMs"},
			Check{Status: SKIP, Name: "VMs with lease IP", Detail: "no configured VMs"},
			Check{Status: SKIP, Name: "Stopped VMs", Detail: "no configured VMs"},
			Check{Status: SKIP, Name: "Missing QEMU PID VMs", Detail: "no configured VMs"},
			Check{Status: SKIP, Name: "Missing lease IP VMs", Detail: "no configured VMs"},
		)
		return checks, vms
	}

	checks = append(checks, Check{Status: OK, Name: "Configured VMs", Detail: fmt.Sprintf("%d", configured)})
	vms = inventory.EnrichWithOptions(vms, inventory.EnrichOptions{LibvirtURI: libvirtURI, SkipQEMUProcessArguments: true})
	checks = append(checks, inventoryRuntimeChecks(vms)...)
	return checks, vms
}

func inventoryRuntimeChecks(vms []inventory.VM) []Check {
	configured := len(vms)
	running, pids, leases := 0, 0, 0
	var stoppedVMs, missingPIDVMs, missingLeaseVMs []string
	for _, vm := range vms {
		if vm.State == "running" {
			running++
		} else {
			stoppedVMs = append(stoppedVMs, vm.Name)
		}
		if present(vm.QEMUPID) {
			pids++
		} else {
			missingPIDVMs = append(missingPIDVMs, vm.Name)
		}
		if present(vm.IPLease) {
			leases++
		} else {
			missingLeaseVMs = append(missingLeaseVMs, vm.Name)
		}
	}
	return []Check{
		countCheck("Running VMs", running, configured, true, startVMRemedy),
		countCheck("VMs with QEMU PID", pids, configured, true, "verify libvirt QEMU PID files and running processes"),
		countCheck("VMs with lease IP", leases, configured, false, "verify libvirt DHCP leases with virsh domifaddr <vm> --source lease"),
		missingVMCheck("Stopped VMs", stoppedVMs, startVMRemedy),
		missingVMCheck("Missing QEMU PID VMs", missingPIDVMs, "start VMs and verify libvirt QEMU PID files"),
		missingVMCheck("Missing lease IP VMs", missingLeaseVMs, "verify DHCP leases with virsh domifaddr <vm> --source lease"),
	}
}

func storageChecks(vms []inventory.VM) []Check {
	var selected *inventory.VM
	for i := range vms {
		if present(vms[i].Disk) {
			selected = &vms[i]
			break
		}
	}
	if selected == nil {
		return []Check{
			{Status: FAIL, Name: "Resolve a VM disk path", Detail: "no VM disk path resolved", Remediation: "verify with virsh domblklist <vm> --details"},
			{Status: SKIP, Name: "Resolve source device", Detail: "no VM disk path"},
			{Status: SKIP, Name: "Resolve parent device", Detail: "no VM disk path"},
			{Status: SKIP, Name: "Resolve physical disk", Detail: "no VM disk path"},
			{Status: SKIP, Name: "Read physical block statistics", Detail: "no physical disk"},
		}
	}

	mapping := hoststorage.Resolve(selected.Disk)
	checks := []Check{{Status: OK, Name: "Resolve a VM disk path", Detail: selected.Name + ": " + selected.Disk}}
	if present(mapping.SourceDevice) {
		checks = append(checks, Check{Status: OK, Name: "Resolve source device", Detail: mapping.SourceDevice})
	} else {
		checks = append(checks, Check{Status: FAIL, Name: "Resolve source device", Detail: "unresolved", Remediation: "verify findmnt can resolve the VM disk path"})
	}
	if present(mapping.ParentDevice) {
		checks = append(checks, Check{Status: OK, Name: "Resolve parent device", Detail: mapping.ParentDevice})
	} else {
		checks = append(checks, Check{Status: SKIP, Name: "Resolve parent device", Detail: "not available for this storage topology"})
	}
	if present(mapping.PhysicalDisk) {
		checks = append(checks, Check{Status: OK, Name: "Resolve physical disk", Detail: mapping.PhysicalDisk})
	} else {
		checks = append(checks,
			Check{Status: SKIP, Name: "Resolve physical disk", Detail: "not available for this storage topology"},
			Check{Status: SKIP, Name: "Read physical block statistics", Detail: "no physical disk"},
		)
		return checks
	}

	physical := firstDevice(mapping.PhysicalDisk)
	statPath := filepath.Join("/sys/class/block", filepath.Base(physical), "stat")
	data, err := os.ReadFile(statPath)
	if err != nil {
		checks = append(checks, Check{Status: FAIL, Name: "Read physical block statistics", Detail: err.Error(), Remediation: "verify access to " + statPath})
	} else if len(strings.Fields(string(data))) < 11 {
		checks = append(checks, Check{Status: FAIL, Name: "Read physical block statistics", Detail: "invalid block stat data", Remediation: "verify " + statPath})
	} else {
		checks = append(checks, Check{Status: OK, Name: "Read physical block statistics", Detail: statPath})
	}
	return checks
}

func qemuChecks(vms []inventory.VM) []Check {
	var running bool
	for _, vm := range vms {
		if vm.State != "running" {
			continue
		}
		running = true
		if !present(vm.QEMUPID) {
			continue
		}
		_, err := qemuio.ReadProcessIO(vm.QEMUPID)
		if err == nil {
			return []Check{{Status: OK, Name: "QEMU process I/O permission", Detail: fmt.Sprintf("read /proc/%s/io (%s)", vm.QEMUPID, vm.Name)}}
		}
		if qemuio.IsPermissionDenied(err) {
			return []Check{{
				Status:      WARN,
				Name:        "QEMU process I/O permission",
				Detail:      "qemu io-watch/io-summary require sudo on this host",
				Remediation: qemuSudoRemedy,
			}}
		}
		return []Check{{Status: WARN, Name: "QEMU process I/O permission", Detail: err.Error(), Remediation: "verify the QEMU process is still running"}}
	}
	if !running {
		return []Check{{Status: SKIP, Name: "QEMU process I/O permission", Detail: "no running VM", Remediation: startVMRemedy}}
	}
	return []Check{{Status: SKIP, Name: "QEMU process I/O permission", Detail: "no QEMU PID for a running VM", Remediation: "verify libvirt QEMU PID files"}}
}

func unavailableInventoryChecks(err error, inventoryPath string) []Check {
	return []Check{
		{Status: FAIL, Name: "Can read configured VMs", Detail: err.Error(), Remediation: "verify " + inventoryPath},
		{Status: SKIP, Name: "Configured VMs", Detail: "inventory unavailable"},
		{Status: SKIP, Name: "Running VMs", Detail: "inventory unavailable", Remediation: startVMRemedy},
		{Status: SKIP, Name: "VMs with QEMU PID", Detail: "inventory unavailable"},
		{Status: SKIP, Name: "VMs with lease IP", Detail: "inventory unavailable"},
	}
}

func unavailableStorageChecks() []Check {
	return []Check{
		{Status: SKIP, Name: "Resolve a VM disk path", Detail: "inventory unavailable"},
		{Status: SKIP, Name: "Resolve source device", Detail: "inventory unavailable"},
		{Status: SKIP, Name: "Resolve parent device", Detail: "inventory unavailable"},
		{Status: SKIP, Name: "Resolve physical disk", Detail: "inventory unavailable"},
		{Status: SKIP, Name: "Read physical block statistics", Detail: "inventory unavailable"},
	}
}

func executableCheck(probes Probes, name, checkName, remediation string) Check {
	path, err := probes.LookPath(name)
	if err != nil {
		return Check{Status: FAIL, Name: checkName, Detail: "not found in PATH", Remediation: remediation}
	}
	return Check{Status: OK, Name: checkName, Detail: path}
}

func directoryReadableCheck(probes Probes, path, checkName string) Check {
	info, err := probes.Stat(path)
	if err != nil {
		return Check{Status: FAIL, Name: checkName, Detail: err.Error(), Remediation: "restore or mount " + path}
	}
	if !info.IsDir() {
		return Check{Status: FAIL, Name: checkName, Detail: "not a directory", Remediation: "restore directory " + path}
	}
	if _, err := probes.ReadDir(path); err != nil {
		return Check{Status: FAIL, Name: checkName, Detail: err.Error(), Remediation: "grant read access to " + path}
	}
	return Check{Status: OK, Name: checkName, Detail: path}
}

func libvirtAccessCheck(uri string, virshStatus Status, probes Probes) Check {
	if virshStatus != OK {
		return Check{Status: SKIP, Name: "Read-only libvirt access", Detail: "virsh is unavailable", Remediation: "install libvirt/virsh"}
	}
	args := []string{"list", "--all", "--name"}
	if strings.TrimSpace(uri) != "" {
		args = append([]string{"-c", strings.TrimSpace(uri)}, args...)
	}
	output, err := probes.CommandOutput("virsh", args...)
	if err != nil {
		detail := err.Error()
		if message := oneLine(string(output)); message != "" {
			detail += ": " + message
		}
		return Check{
			Status:      WARN,
			Name:        "Read-only libvirt access",
			Detail:      detail,
			Remediation: "verify libvirt service state and access to " + valueOrDefault(uri, "the default URI"),
		}
	}
	return Check{Status: OK, Name: "Read-only libvirt access", Detail: valueOrDefault(uri, "default URI")}
}

func rootUsageCheck(euid int) Check {
	if euid == 0 {
		return Check{
			Status:      WARN,
			Name:        "Running as root",
			Detail:      "product doctor does not require root",
			Remediation: "run solis doctor as an unprivileged user",
		}
	}
	return Check{Status: OK, Name: "Running as root", Detail: "no"}
}

func pathCheck(path, checkName string, wantDirectory bool) Check {
	info, err := os.Stat(path)
	if err != nil {
		return Check{Status: FAIL, Name: checkName, Detail: err.Error(), Remediation: "restore or mount " + path}
	}
	if wantDirectory && !info.IsDir() {
		return Check{Status: FAIL, Name: checkName, Detail: "not a directory", Remediation: "restore directory " + path}
	}
	if !wantDirectory && !info.Mode().IsRegular() {
		return Check{Status: FAIL, Name: checkName, Detail: "not a regular file", Remediation: "restore file " + path}
	}
	return Check{Status: OK, Name: checkName, Detail: "exists"}
}

func countCheck(name string, count, total int, failIfZero bool, remediation string) Check {
	status := OK
	if count < total {
		status = WARN
	}
	if count == 0 && failIfZero {
		status = FAIL
	}
	return Check{Status: status, Name: name, Detail: fmt.Sprintf("%d of %d", count, total), Remediation: remediationIfNeeded(status, remediation)}
}

func missingVMCheck(name string, names []string, remediation string) Check {
	if len(names) == 0 {
		return Check{Status: OK, Name: name, Detail: "none"}
	}
	sort.Strings(names)
	return Check{Status: WARN, Name: name, Detail: strings.Join(names, ", "), Remediation: remediation}
}

func remediationIfNeeded(status Status, remediation string) string {
	if status == OK {
		return ""
	}
	return remediation
}

func present(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && value != "-"
}

func firstDevice(devices string) string {
	for _, device := range strings.Split(devices, ",") {
		if present(device) {
			return strings.TrimSpace(device)
		}
	}
	return ""
}

func valueOrDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
