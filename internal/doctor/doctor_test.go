package doctor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/safwen511/solis-io/internal/config"
	"github.com/safwen511/solis-io/internal/inventory"
)

func TestProductDoctorDoesNotRequireLabArtifacts(t *testing.T) {
	report := RunWithOptions(Options{InventoryCSV: filepath.Join(t.TempDir(), "missing.csv")})
	if len(report.Lab) != 0 {
		t.Fatalf("product doctor lab checks = %#v, want none", report.Lab)
	}
}

func TestLabDoctorIncludesLabSpecificChecks(t *testing.T) {
	root := t.TempDir()
	report := RunWithOptions(Options{
		Root:              root,
		InventoryCSV:      filepath.Join(root, "missing.csv"),
		DefaultReportDir:  filepath.Join(root, "reports", "workload"),
		CaptureOutputRoot: filepath.Join(root, "reports", "captures"),
		Lab:               true,
	})
	if len(report.Lab) == 0 {
		t.Fatal("lab doctor did not include lab checks")
	}
}

func TestProductDoctorReportsHostConfigAndInventoryChecksWithFakeProbes(t *testing.T) {
	root := t.TempDir()
	procPath := filepath.Join(root, "proc")
	sysPath := filepath.Join(root, "sys")
	if err := os.Mkdir(procPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sysPath, 0o700); err != nil {
		t.Fatal(err)
	}
	inventoryPath := filepath.Join(root, "vms.csv")
	if err := os.WriteFile(inventoryPath, []byte("name,tenant,network,ip,memory_mb,vcpus,disk_gb,role\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	captureRoot := filepath.Join(root, "captures")
	if err := os.Mkdir(captureRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	var commands []string
	probes := effectiveProbes(&Probes{
		GOOS:         func() string { return "linux" },
		EffectiveUID: func() int { return os.Geteuid() },
		LookPath:     func(name string) (string, error) { return "/fake/bin/" + name, nil },
		CommandOutput: func(name string, args ...string) ([]byte, error) {
			commands = append(commands, strings.Join(append([]string{name}, args...), " "))
			return []byte("a-web\n"), nil
		},
	})
	options := Options{
		InventoryCSV:      inventoryPath,
		CaptureOutputRoot: captureRoot,
		LibvirtURI:        "qemu:///system",
		ConfigSource:      "/etc/solis/solis.json",
		SchemaVersion:     config.SchemaVersion2,
		ProcPath:          procPath,
		SysPath:           sysPath,
		Probes:            &probes,
	}

	report := RunWithOptions(options)
	configChecks := report.Config
	for _, expected := range []struct {
		name   string
		status Status
	}{
		{"Config source", OK},
		{"Config schema version", OK},
		{"Inventory file", OK},
		{"Capture output writable", OK},
	} {
		if got := checkByName(configChecks, expected.name); got.Status != expected.status {
			t.Errorf("%s = %#v, want %s", expected.name, got, expected.status)
		}
	}

	host := report.Host
	for _, name := range []string{"OS is Linux", "/proc readable", "/sys readable", "virsh command", "Read-only libvirt access"} {
		if got := checkByName(host, name); got.Status != OK {
			t.Errorf("%s = %#v, want OK", name, got)
		}
	}
	if len(commands) != 1 || commands[0] != "virsh -c qemu:///system list --all --name" {
		t.Fatalf("doctor commands = %v, want read-only virsh list only", commands)
	}
	for _, command := range commands {
		if strings.HasPrefix(command, "sudo ") || command == "sudo" {
			t.Fatalf("doctor invoked sudo: %v", commands)
		}
	}
}

func TestCaptureOutputWarnings(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	probes := effectiveProbes(&Probes{
		EffectiveUID: func() int { return os.Geteuid() },
		Access:       func(string, uint32) error { return errors.New("permission denied") },
	})
	checks := captureOutputChecks(probes, filepath.Join(parent, "captures"))
	if got := checkByName(checks, "Capture output writable"); got.Status != WARN {
		t.Fatalf("writable check = %#v, want WARN", got)
	}
	if got := checkByName(checks, "Capture output permissions"); got.Status != WARN || !strings.Contains(got.Detail, "group/world writable") {
		t.Fatalf("permissions check = %#v, want suspicious-permission WARN", got)
	}
}

func TestDoctorWarnsWhenRunAsRoot(t *testing.T) {
	check := rootUsageCheck(0)
	if check.Status != WARN || !strings.Contains(check.Detail, "does not require root") {
		t.Fatalf("root check = %#v, want unnecessary-root warning", check)
	}
}

func TestDoctorReportsOptionalObservabilityAndPrivacy(t *testing.T) {
	observability := &config.ObservabilityConfig{
		Host:      config.HostObservabilityConfig{Enabled: true, Interval: "1s"},
		Guest:     config.GuestObservabilityConfig{Enabled: true, Transport: "ssh", MaxParallel: 4},
		Services:  []config.ServiceObservabilityConfig{{VM: "a-web"}},
		Databases: []config.DatabaseObservabilityConfig{{VM: "a-db", Kind: "postgresql", Database: "postgres"}},
	}
	for _, check := range observabilityChecks(observability) {
		if check.Status != OK {
			t.Errorf("observability check = %#v, want OK", check)
		}
	}
	privacy := privacyChecks()
	if len(privacy) != 8 {
		t.Fatalf("privacy checks = %d, want 8", len(privacy))
	}
	for _, check := range privacy {
		if check.Status != OK || !strings.Contains(check.Detail, "not collected") {
			t.Errorf("privacy check = %#v", check)
		}
	}
}

func TestOverallResult(t *testing.T) {
	tests := []struct {
		name   string
		report Report
		want   string
	}{
		{"pass ignores skip", Report{Host: []Check{{Status: OK}, {Status: SKIP}}}, "PASS"},
		{"warning", Report{Lab: []Check{{Status: WARN}}}, "WARN"},
		{"failure overrides warning", Report{Host: []Check{{Status: WARN}}, Storage: []Check{{Status: FAIL}}}, "FAIL"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := OverallResult(test.report); got != test.want {
				t.Fatalf("OverallResult() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestWriteFormatsSectionsAndRemediation(t *testing.T) {
	report := Report{
		Config: []Check{{Status: OK, Name: "Config source", Detail: "built-in defaults"}},
		Host:   []Check{{Status: OK, Name: "OS is Linux", Detail: "linux"}},
		Inventory: []Check{{
			Status:      WARN,
			Name:        "Stopped VMs",
			Detail:      "b-client, b-db, b-web",
			Remediation: startVMRemedy,
		}},
		QEMU: []Check{{
			Status:      WARN,
			Name:        "QEMU process I/O permission",
			Detail:      "qemu io-watch/io-summary require sudo on this host",
			Remediation: qemuSudoRemedy,
		}},
		Privacy: privacyChecks(),
	}
	var output bytes.Buffer
	if err := Write(&output, report); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	for _, want := range []string{
		"Solis Doctor",
		"Product configuration:",
		"Host checks:",
		"Stopped VMs",
		"b-client, b-db, b-web",
		"QEMU I/O permission check:",
		"qemu io-watch/io-summary require sudo on this host",
		"run qemu io commands with sudo",
		"Privacy and safety:",
		"SQL text",
		"not collected",
		"Overall result:  WARN",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("doctor output missing %q:\n%s", want, output.String())
		}
	}
}

func TestInventoryRuntimeChecksListsAffectedVMsAlphabetically(t *testing.T) {
	vms := []inventory.VM{
		{Name: "b-web", State: "shut off", QEMUPID: "-", IPLease: "-"},
		{Name: "a-db", State: "running", QEMUPID: "200", IPLease: "192.168.130.30"},
		{Name: "b-client", State: "shut off"},
	}

	want := []Check{
		{Status: WARN, Name: "Running VMs", Detail: "1 of 3", Remediation: startVMRemedy},
		{Status: WARN, Name: "VMs with QEMU PID", Detail: "1 of 3", Remediation: "verify libvirt QEMU PID files and running processes"},
		{Status: WARN, Name: "VMs with lease IP", Detail: "1 of 3", Remediation: "verify libvirt DHCP leases with virsh domifaddr <vm> --source lease"},
		{Status: WARN, Name: "Stopped VMs", Detail: "b-client, b-web", Remediation: startVMRemedy},
		{Status: WARN, Name: "Missing QEMU PID VMs", Detail: "b-client, b-web", Remediation: "start VMs and verify libvirt QEMU PID files"},
		{Status: WARN, Name: "Missing lease IP VMs", Detail: "b-client, b-web", Remediation: "verify DHCP leases with virsh domifaddr <vm> --source lease"},
	}
	if got := inventoryRuntimeChecks(vms); !reflect.DeepEqual(got, want) {
		t.Fatalf("inventoryRuntimeChecks() = %#v, want %#v", got, want)
	}
}

func TestInventoryRuntimeChecksReportsNoneWhenComplete(t *testing.T) {
	vms := []inventory.VM{{
		Name: "a-db", State: "running", QEMUPID: "200", IPLease: "192.168.130.30",
	}}

	checks := inventoryRuntimeChecks(vms)
	for _, check := range checks[3:] {
		if check.Status != OK || check.Detail != "none" || check.Remediation != "" {
			t.Errorf("complete detail check = %#v, want OK/none/no remediation", check)
		}
	}
}

func checkByName(checks []Check, name string) Check {
	for _, check := range checks {
		if check.Name == name {
			return check
		}
	}
	return Check{Name: name, Detail: "missing"}
}
