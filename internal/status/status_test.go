package status

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
)

func TestNewReportIncludesVMIdentityAndStoragePath(t *testing.T) {
	report := NewReport(3*time.Second, time.Second, []Sample{{
		VM: inventory.VM{
			Name: "a-web", Tenant: "tenant-a", Role: "web", State: "running",
			IPPlan: "192.168.130.20", IPLease: "192.168.130.21", QEMUPID: "12345",
			Disk: "/images/a-web.qcow2",
		},
		Storage: hoststorage.Mapping{
			DiskPath:     "/images/a-web.qcow2",
			SourceDevice: "/dev/mapper/ubuntu--vg-ubuntu--lv",
			ParentDevice: "/dev/nvme0n1p3",
			PhysicalDisk: "/dev/nvme0n1",
		},
		QEMU: qemuio.VMSummary{Available: true},
	}})
	if report.SchemaVersion != "1" || report.Duration != "3s" || report.Interval != "1s" {
		t.Fatalf("report metadata = %#v", report)
	}
	if len(report.VMs) != 1 {
		t.Fatalf("VM count = %d, want 1", len(report.VMs))
	}
	vm := report.VMs[0]
	if vm.Name != "a-web" || vm.Tenant != "tenant-a" || vm.Role != "web" || vm.IP != "192.168.130.21" {
		t.Fatalf("VM identity = %#v", vm)
	}
	if vm.QEMUPID != 12345 || vm.Disk != "/images/a-web.qcow2" || vm.SourceDevice != "/dev/mapper/ubuntu--vg-ubuntu--lv" || vm.ParentDevice != "/dev/nvme0n1p3" || vm.PhysicalDisk != "/dev/nvme0n1" {
		t.Fatalf("VM topology = %#v", vm)
	}
}

func TestClassifyPressureUsesBytePressure(t *testing.T) {
	pressure, reason := ClassifyPressure(qemuio.VMSummary{
		Available:                true,
		AverageWriteMiBPerSecond: 50,
		AverageSyscwPerSecond:    1,
	})
	if pressure != PressureHigh || reason != "dominant byte write rate" {
		t.Fatalf("classification = %q, %q", pressure, reason)
	}
}

func TestClassifyPressureUsesSyscallFallback(t *testing.T) {
	pressure, reason := ClassifyPressure(qemuio.VMSummary{
		Available:             true,
		AverageSyscwPerSecond: 120000,
	})
	if pressure != PressureHigh || reason != "high syscall pressure" {
		t.Fatalf("classification = %q, %q", pressure, reason)
	}
}

func TestWriteJSONProducesStatusSchema(t *testing.T) {
	report := NewReport(3*time.Second, time.Second, []Sample{{
		VM: inventory.VM{Name: "a-web", State: "running", QEMUPID: "12345"},
		QEMU: qemuio.VMSummary{
			Available:                true,
			AverageWriteMiBPerSecond: 0.5,
			AverageSyscwPerSecond:    5,
		},
	}})
	var output bytes.Buffer
	if err := WriteJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		VMs           []struct {
			Name     string `json:"name"`
			Pressure string `json:"pressure"`
		} `json:"vms"`
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, output.String())
	}
	if decoded.SchemaVersion != "1" || len(decoded.VMs) != 1 || decoded.VMs[0].Name != "a-web" || decoded.VMs[0].Pressure != "low" {
		t.Fatalf("decoded status = %#v", decoded)
	}
}

func TestEligibleVMsIncludesOnlyRunningVMsWithPIDs(t *testing.T) {
	vms := eligibleVMs([]inventory.VM{
		{Name: "b-web", State: "running", QEMUPID: "22"},
		{Name: "a-web", State: "running", QEMUPID: "11"},
		{Name: "stopped", State: "shut off", QEMUPID: "33"},
		{Name: "missing-pid", State: "running"},
	})
	if len(vms) != 2 || vms[0].Name != "a-web" || vms[1].Name != "b-web" {
		t.Fatalf("eligible VMs = %#v", vms)
	}
}

func TestWriteHumanShowsRequiredColumns(t *testing.T) {
	report := NewReport(3*time.Second, time.Second, []Sample{{
		VM: inventory.VM{Name: "a-web", Tenant: "tenant-a", Role: "web", State: "running", QEMUPID: "12345"},
		Storage: hoststorage.Mapping{
			DiskPath: "/images/a-web.qcow2", PhysicalDisk: "/dev/nvme0n1",
		},
		QEMU: qemuio.VMSummary{Available: true},
	}})
	var output bytes.Buffer
	if err := WriteHuman(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"VM", "TENANT", "QEMU_PID", "QCOW2_DISK", "PHYSICAL_DISK", "AVG_WRITE_MIB/S", "AVG_SYSCW/S", "PRESSURE", "a-web"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}
