package traceplan

import (
	"bytes"
	"strings"
	"testing"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
)

// TestResolveTenantVictim verifies resolve tenant victim.
func TestResolveTenantVictim(t *testing.T) {
	plan, err := Resolve(testInventory(), "tenant-a", "b-stress")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !plan.VictimIsTenant {
		t.Fatal("VictimIsTenant = false, want true")
	}
	if len(plan.VictimTargets) != 3 {
		t.Fatalf("len(VictimTargets) = %d, want 3", len(plan.VictimTargets))
	}
	wantNames := []string{"a-client", "a-db", "a-web"}
	for i, want := range wantNames {
		if plan.VictimTargets[i].Name != want {
			t.Errorf("VictimTargets[%d].Name = %q, want %q", i, plan.VictimTargets[i].Name, want)
		}
	}
	if plan.SuspectTarget.Name != "b-stress" {
		t.Fatalf("SuspectTarget.Name = %q, want b-stress", plan.SuspectTarget.Name)
	}
}

// TestResolveVMVictim verifies resolve vm victim.
func TestResolveVMVictim(t *testing.T) {
	plan, err := Resolve(testInventory(), "a-db", "b-stress")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if plan.VictimIsTenant || len(plan.VictimTargets) != 1 || plan.VictimTargets[0].Name != "a-db" {
		t.Fatalf("victim resolution = %#v, want only a-db", plan)
	}
}

// TestResolveUnknownSuspect verifies resolve unknown suspect.
func TestResolveUnknownSuspect(t *testing.T) {
	_, err := Resolve(testInventory(), "tenant-a", "missing-vm")
	if err == nil || !strings.Contains(err.Error(), "suspect VM not found") {
		t.Fatalf("Resolve() error = %v, want suspect VM not found", err)
	}
}

// TestWriteIncludesPlanEvidenceAndInterpretation verifies write includes plan evidence and
// interpretation.
func TestWriteIncludesPlanEvidenceAndInterpretation(t *testing.T) {
	plan, err := Resolve(testInventory(), "tenant-a", "b-stress")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	plan.HostStorage = map[string]hoststorage.Mapping{
		"a-db": {
			DiskPath:     "/images/a-db.qcow2",
			Mountpoint:   "/var/lib/libvirt/images",
			SourceDevice: "/dev/mapper/vg-images",
			Filesystem:   "xfs",
			ParentDevice: "/dev/nvme0n1p3",
			PhysicalDisk: "/dev/nvme0n1",
		},
	}

	var output bytes.Buffer
	if err := Write(&output, plan); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	for _, expected := range []string{
		"Trace Plan",
		"Victim targets",
		"likely victim DB VM",
		"likely victim web VM",
		"Suspect target",
		"Host storage mapping",
		"/dev/mapper/vg-images",
		"/dev/nvme0n1p3",
		"/dev/nvme0n1",
		"Host block device backing qcow2 files",
		"block:block_rq_issue",
		"block:block_rq_complete",
		"probable noisy-neighbor storage interference",
		"likely guest/app/internal bottleneck",
		"shared infrastructure pressure",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("trace plan missing %q:\n%s", expected, output.String())
		}
	}
}

// testInventory builds test inventory from validated inputs.
func testInventory() []inventory.VM {
	return []inventory.VM{
		{Name: "a-web", Tenant: "tenant-a", Role: "web", IPPlan: "192.168.130.20"},
		{Name: "a-db", Tenant: "tenant-a", Role: "db", IPPlan: "192.168.130.30"},
		{Name: "a-client", Tenant: "tenant-a", Role: "client", IPPlan: "192.168.130.10"},
		{Name: "b-stress", Tenant: "tenant-b", Role: "stress", IPPlan: "192.168.140.40"},
	}
}
