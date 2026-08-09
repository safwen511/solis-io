package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	Lab               bool
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
	})
}

// RunWithOptions performs product checks and optional repository lab checks.
func RunWithOptions(options Options) Report {
	if strings.TrimSpace(options.Root) == "" {
		options.Root = "."
	}
	report := Report{}
	report.Host = hostChecks(options.Root)
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

func hostChecks(root string) []Check {
	checks := []Check{
		{Status: OK, Name: "OS is Linux", Detail: runtime.GOOS},
		{Status: SKIP, Name: "Go build", Detail: "not checked at runtime", Remediation: buildRemedy},
	}
	if runtime.GOOS != "linux" {
		checks[0] = Check{Status: FAIL, Name: "OS is Linux", Detail: runtime.GOOS, Remediation: "run Solis on a Linux host"}
	}

	virsh := executableCheck("virsh", "virsh exists", "install libvirt/virsh")
	findmnt := executableCheck("findmnt", "findmnt exists", "install findmnt (util-linux)")
	lsblk := executableCheck("lsblk", "lsblk exists", "install lsblk (util-linux)")
	checks = append(checks[:1], append([]Check{virsh}, checks[1:]...)...)
	checks = append(checks, findmnt, lsblk)
	checks = append(checks,
		pathCheck("/sys/class/block", "/sys/class/block exists", true),
		pathCheck("/proc", "/proc exists", true),
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
	if strings.TrimSpace(options.CaptureOutputRoot) != "" {
		checks = append(checks, directoryOutputCheck(options.CaptureOutputRoot, options.CaptureOutputRoot+" exists or can be created"))
	}
	return checks
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
	vms = inventory.EnrichWithOptions(vms, inventory.EnrichOptions{LibvirtURI: libvirtURI})
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

func executableCheck(name, checkName, remediation string) Check {
	path, err := exec.LookPath(name)
	if err != nil {
		return Check{Status: FAIL, Name: checkName, Detail: "not found in PATH", Remediation: remediation}
	}
	return Check{Status: OK, Name: checkName, Detail: path}
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

func directoryOutputCheck(path, checkName string) Check {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return Check{Status: OK, Name: checkName, Detail: "exists"}
		}
		return Check{Status: FAIL, Name: checkName, Detail: "path exists but is not a directory", Remediation: "replace with a directory: " + path}
	}
	if !os.IsNotExist(err) {
		return Check{Status: FAIL, Name: checkName, Detail: err.Error(), Remediation: "check permissions for " + path}
	}

	parent := filepath.Dir(path)
	for {
		parentInfo, parentErr := os.Stat(parent)
		if parentErr == nil {
			if !parentInfo.IsDir() {
				return Check{Status: FAIL, Name: checkName, Detail: "parent is not a directory: " + parent, Remediation: "repair " + parent}
			}
			if err := syscall.Access(parent, writeExecuteAccess); err != nil {
				return Check{Status: FAIL, Name: checkName, Detail: "parent is not writable: " + parent, Remediation: "grant write access to " + parent}
			}
			return Check{Status: OK, Name: checkName, Detail: "can be created under " + parent}
		}
		if !os.IsNotExist(parentErr) {
			return Check{Status: FAIL, Name: checkName, Detail: parentErr.Error(), Remediation: "check permissions for " + parent}
		}
		next := filepath.Dir(parent)
		if next == parent {
			return Check{Status: FAIL, Name: checkName, Detail: "no existing parent directory", Remediation: "create " + path}
		}
		parent = next
	}
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
