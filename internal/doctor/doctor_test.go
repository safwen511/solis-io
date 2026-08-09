package doctor

import (
	"bytes"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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
		Host: []Check{{Status: OK, Name: "OS is Linux", Detail: "linux"}},
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
	}
	var output bytes.Buffer
	if err := Write(&output, report); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	for _, want := range []string{
		"Solis Doctor",
		"Host checks:",
		"Stopped VMs",
		"b-client, b-db, b-web",
		"QEMU I/O permission check:",
		"qemu io-watch/io-summary require sudo on this host",
		"run qemu io commands with sudo",
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
