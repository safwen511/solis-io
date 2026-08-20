package discovery

import (
	"testing"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
)

// TestResolveExcludesVictimAndFiltersSharedPhysicalDisk verifies resolve excludes victim and
// filters shared physical disk.
func TestResolveExcludesVictimAndFiltersSharedPhysicalDisk(t *testing.T) {
	vms := []inventory.VM{
		{Name: "a-web", State: "running", QEMUPID: "100", Disk: "/images/a-web.qcow2"},
		{Name: "a-db", State: "running", QEMUPID: "101", Disk: "/images/a-db.qcow2"},
		{Name: "b-stress", State: "running", QEMUPID: "200", Disk: "/images/b-stress.qcow2"},
		{Name: "other-disk", State: "running", QEMUPID: "300", Disk: "/images/other.qcow2"},
		{Name: "stopped", State: "shut off", QEMUPID: "", Disk: "/images/stopped.qcow2"},
	}
	resolver := func(path string) hoststorage.Mapping {
		physical := "/dev/nvme0n1"
		if path == "/images/other.qcow2" {
			physical = "/dev/sda"
		}
		return hoststorage.Mapping{DiskPath: path, PhysicalDisk: physical}
	}

	targets, err := resolveWith(vms, "a-web", resolver)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a-db", "b-stress"}
	if len(targets.CandidateTargets) != len(want) {
		t.Fatalf("candidates = %#v, want %v", targets.CandidateTargets, want)
	}
	for index, name := range want {
		if targets.CandidateTargets[index].VM.Name != name {
			t.Fatalf("candidate %d = %q, want %q", index, targets.CandidateTargets[index].VM.Name, name)
		}
		if targets.CandidateTargets[index].VM.Name == targets.Victim.Name {
			t.Fatal("victim was included as a suspect candidate")
		}
	}
}

// TestAnalyzeSelectsCandidateByWriteBytes verifies analyze selects candidate by write bytes.
func TestAnalyzeSelectsCandidateByWriteBytes(t *testing.T) {
	targets := testTargets()
	report := Analyze(targets, testSamples(
		qemuio.VMSummary{Available: true, AverageWriteMiBPerSecond: 5},
		qemuio.VMSummary{Available: true, AverageWriteMiBPerSecond: 4, AverageSyscwPerSecond: 20000},
		qemuio.VMSummary{Available: true, AverageWriteMiBPerSecond: 40, MaxWriteMiBPerSecond: 55},
	))
	if report.Selected == nil || report.Selected.VM.Name != "b-stress" {
		t.Fatalf("selected = %#v, want b-stress", report.Selected)
	}
	if report.Selected.Reason != "dominant byte write rate" {
		t.Fatalf("reason = %q", report.Selected.Reason)
	}
}

// TestAnalyzeSelectsCandidateBySyscallFallback verifies analyze selects candidate by syscall
// fallback.
func TestAnalyzeSelectsCandidateBySyscallFallback(t *testing.T) {
	targets := testTargets()
	report := Analyze(targets, testSamples(
		qemuio.VMSummary{Available: true, AverageSyscwPerSecond: 1000},
		qemuio.VMSummary{Available: true, AverageWriteMiBPerSecond: 0, AverageSyscwPerSecond: 2000},
		qemuio.VMSummary{Available: true, AverageWriteMiBPerSecond: 0, AverageSyscwPerSecond: 120000, MaxSyscwPerSecond: 141000},
	))
	if report.Selected == nil || report.Selected.VM.Name != "b-stress" {
		t.Fatalf("selected = %#v, want b-stress", report.Selected)
	}
	if report.Selected.Reason != "dominant syscall pressure" {
		t.Fatalf("reason = %q", report.Selected.Reason)
	}
}

// TestAnalyzeSelectsNoSuspectWhenCandidatesAreIdle verifies analyze selects no suspect when
// candidates are idle.
func TestAnalyzeSelectsNoSuspectWhenCandidatesAreIdle(t *testing.T) {
	targets := testTargets()
	report := Analyze(targets, testSamples(
		qemuio.VMSummary{Available: true},
		qemuio.VMSummary{Available: true, AverageWriteMiBPerSecond: 0.2, AverageSyscwPerSecond: 30},
		qemuio.VMSummary{Available: true, AverageWriteMiBPerSecond: 0.5, AverageSyscwPerSecond: 50},
	))
	if report.Selected != nil {
		t.Fatalf("selected = %#v, want nil", report.Selected)
	}
	if report.SelectionReason != "no dominant writer observed" {
		t.Fatalf("reason = %q", report.SelectionReason)
	}
}

// testTargets builds test targets from validated inputs.
func testTargets() Targets {
	return Targets{
		Victim:        inventory.VM{Name: "a-web"},
		VictimStorage: hoststorage.Mapping{PhysicalDisk: "/dev/nvme0n1"},
		CandidateTargets: []CandidateTarget{
			{VM: inventory.VM{Name: "a-db", Tenant: "tenant-a", Role: "db"}, Storage: hoststorage.Mapping{PhysicalDisk: "/dev/nvme0n1"}, SharedDisk: true},
			{VM: inventory.VM{Name: "b-stress", Tenant: "tenant-b", Role: "stress"}, Storage: hoststorage.Mapping{PhysicalDisk: "/dev/nvme0n1"}, SharedDisk: true},
		},
	}
}

// testSamples builds test samples from validated inputs.
func testSamples(victim, first, second qemuio.VMSummary) qemuio.SummaryReport {
	victim.Target = qemuio.Target{TargetType: "victim", VM: inventory.VM{Name: "a-web"}}
	first.Target = qemuio.Target{TargetType: "candidate", VM: inventory.VM{Name: "a-db"}}
	second.Target = qemuio.Target{TargetType: "candidate", VM: inventory.VM{Name: "b-stress"}}
	return qemuio.SummaryReport{VMs: []qemuio.VMSummary{victim, first, second}}
}
