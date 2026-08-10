package observe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/config"
	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/hostmetrics"
	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/observability"
	"github.com/safwen511/solis-io/internal/qemuio"
	"github.com/safwen511/solis-io/internal/servicehealth"
)

func TestVictimOnlySnapshotRendersDeterministicJSON(t *testing.T) {
	snapshot := collectFixture(t, Request{Victim: "a-web", Duration: 10 * time.Second, Interval: 2 * time.Second})
	if snapshot.SelectedSuspect != "-" || snapshot.SuspectMode != "victim-only" {
		t.Fatalf("unexpected victim-only identity: suspect=%q mode=%q", snapshot.SelectedSuspect, snapshot.SuspectMode)
	}
	first, second := render(t, snapshot), render(t, snapshot)
	if first != second {
		t.Fatal("observe JSON changed between identical renders")
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(first), &decoded); err != nil {
		t.Fatalf("observe JSON is invalid: %v", err)
	}
	if decoded["schema_version"] != SchemaVersion {
		t.Fatalf("schema_version = %#v", decoded["schema_version"])
	}
}

func TestPairwiseSnapshotIncludesSelectedSuspect(t *testing.T) {
	snapshot := collectFixture(t, Request{Victim: "a-web", Suspect: "b-stress", Duration: 10 * time.Second, Interval: 2 * time.Second})
	if snapshot.SelectedSuspect != "b-stress" || snapshot.SuspectMode != "pairwise" {
		t.Fatalf("unexpected pairwise identity: %#v", snapshot)
	}
	if !snapshot.StorageTopology.SharedPhysicalDisk {
		t.Fatal("expected shared storage topology")
	}
	if !snapshot.QEMUEvidence.MeaningfulSuspectPressure || !snapshot.QEMUEvidence.SuspectDominant {
		t.Fatalf("expected dominant suspect pressure: %#v", snapshot.QEMUEvidence)
	}
}

func TestDiscoverySnapshotIncludesSelectedSuspect(t *testing.T) {
	request := Request{Victim: "a-web", DiscoverSuspects: true, Duration: 10 * time.Second, Interval: 2 * time.Second}
	snapshot, err := Collect(context.Background(), request, fixtureVMs(), fixtureDependencies(true))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SelectedSuspect != "b-stress" || snapshot.Discovery.SelectedSuspect != "b-stress" {
		t.Fatalf("discovery did not select fixture suspect: %#v", snapshot.Discovery)
	}
	if len(snapshot.Discovery.Candidates) != 1 || snapshot.Discovery.Candidates[0].Score != "HIGH" {
		t.Fatalf("unexpected discovery candidates: %#v", snapshot.Discovery.Candidates)
	}
}

func TestOptionalDisabledAndNotConfiguredAreNonFatal(t *testing.T) {
	snapshot := collectFixture(t, Request{
		Victim: "a-web", Duration: 10 * time.Second, Interval: 2 * time.Second,
		IncludeGuest: true, IncludeDB: true, GuestEnabled: false,
		DatabaseConfigured: map[string]bool{},
	})
	assertUnavailableState(t, snapshot, "victim_guest_status", EvidenceDisabled)
	assertUnavailableState(t, snapshot, "victim_db_status", EvidenceNotConfigured)
	if snapshot.VictimGuestStatus != nil || snapshot.VictimDBStatus != nil {
		t.Fatal("disabled optional collectors should not populate status models")
	}
}

func TestPartialCollectorFailureIsRepresented(t *testing.T) {
	dependencies := fixtureDependencies(false)
	dependencies.Host = func(context.Context, string) (hostmetrics.HostStatus, error) {
		return hostmetrics.HostStatus{}, errors.New("fixture host failure")
	}
	snapshot, err := Collect(context.Background(), Request{Victim: "a-web", Duration: 10 * time.Second, Interval: 2 * time.Second}, fixtureVMs(), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	assertUnavailableState(t, snapshot, "host_status", EvidenceError)
	if snapshot.EvidenceQuality.Overall != EvidencePartial {
		t.Fatalf("overall quality = %q, want partial", snapshot.EvidenceQuality.Overall)
	}
}

func TestOptionalCollectorsShareSnapshotWindowID(t *testing.T) {
	dependencies := fixtureDependencies(false)
	dependencies.Guest = func(_ context.Context, vm inventory.VM, windowID string) (observability.GuestStatus, error) {
		return observability.GuestStatus{SchemaVersion: "1", WindowID: windowID, VM: observability.VMIdentity{Name: vm.Name}, Availability: measuredAvailability("fixture guest")}, nil
	}
	dependencies.Service = func(_ context.Context, vm inventory.VM, windowID string) (servicehealth.Report, error) {
		return servicehealth.Report{SchemaVersion: "1", WindowID: windowID, VM: observability.VMIdentity{Name: vm.Name}, Availability: measuredAvailability("fixture service"), Services: []observability.ServiceStatus{}}, nil
	}
	dependencies.Database = func(_ context.Context, vm inventory.VM, windowID string) (observability.DBStatus, error) {
		return observability.DBStatus{SchemaVersion: "1", WindowID: windowID, VM: observability.VMIdentity{Name: vm.Name}, Availability: measuredAvailability("fixture database")}, nil
	}
	request := Request{
		Victim: "a-web", Duration: 10 * time.Second, Interval: 2 * time.Second,
		GuestEnabled: true, IncludeGuest: true, IncludeServices: true, IncludeDB: true,
		ServiceConfigured: map[string]bool{"a-web": true}, DatabaseConfigured: map[string]bool{"a-web": true},
	}
	snapshot, err := Collect(context.Background(), request, fixtureVMs(), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.VictimGuestStatus == nil || snapshot.VictimServiceStatus == nil || snapshot.VictimDBStatus == nil {
		t.Fatalf("optional sections were not collected: %#v", snapshot.UnavailableSections)
	}
	for section, windowID := range map[string]string{
		"host": snapshot.HostStatus.WindowID, "guest": snapshot.VictimGuestStatus.WindowID,
		"service": snapshot.VictimServiceStatus.WindowID, "database": snapshot.VictimDBStatus.WindowID,
	} {
		if windowID != snapshot.WindowID {
			t.Errorf("%s window_id = %q, want %q", section, windowID, snapshot.WindowID)
		}
	}
}

func TestSnapshotPrivacyFlagsStayFalseAndUnsafeModelsAreRejected(t *testing.T) {
	snapshot := collectFixture(t, Request{Victim: "a-web", Duration: 10 * time.Second, Interval: 2 * time.Second})
	if !privacySafe(snapshot.Privacy) {
		t.Fatalf("top-level privacy flags are unsafe: %#v", snapshot.Privacy)
	}
	snapshot.Privacy.QueryTextCollected = true
	var output bytes.Buffer
	if err := WriteJSON(&output, snapshot); err == nil || !strings.Contains(err.Error(), "cannot contain") {
		t.Fatalf("unsafe privacy model was not rejected: %v", err)
	}
}

func TestCollectorRejectsUnsafeSubmodelPrivacy(t *testing.T) {
	dependencies := fixtureDependencies(false)
	dependencies.Guest = func(_ context.Context, vm inventory.VM, windowID string) (observability.GuestStatus, error) {
		return observability.GuestStatus{
			SchemaVersion: "1", WindowID: windowID, VM: observability.VMIdentity{Name: vm.Name},
			Availability: measuredAvailability("fixture guest"), Privacy: observability.PrivacyFlags{ProcessArgumentsCollected: true},
		}, nil
	}
	_, err := Collect(context.Background(), Request{
		Victim: "a-web", Duration: 10 * time.Second, Interval: 2 * time.Second,
		GuestEnabled: true, IncludeGuest: true,
	}, fixtureVMs(), dependencies)
	if err == nil || !strings.Contains(err.Error(), "cannot contain") {
		t.Fatalf("unsafe guest submodel was not rejected: %v", err)
	}
}

func TestCorrelationsDoNotOverstateCausality(t *testing.T) {
	snapshot := collectFixture(t, Request{Victim: "a-web", Suspect: "b-stress", Duration: 10 * time.Second, Interval: 2 * time.Second})
	output := strings.ToLower(render(t, snapshot))
	if strings.Contains(output, "probable noisy-neighbor") || strings.Contains(output, "confirmed application") {
		t.Fatalf("snapshot overstated causality: %s", output)
	}
	if !strings.Contains(output, "does not establish causality") {
		t.Fatalf("snapshot omitted causality caveat: %s", output)
	}
	foundHost := false
	for _, correlation := range snapshot.Correlations {
		if correlation.Name == "host_metrics_available" {
			foundHost = correlation.Present && correlation.Severity == "info"
		}
		if !correlation.Present && correlation.Severity == "likely" {
			t.Errorf("absent correlation %q has misleading likely severity", correlation.Name)
		}
	}
	if !foundHost {
		t.Fatalf("host metrics availability correlation missing: %#v", snapshot.Correlations)
	}
}

func TestExistingVMAttributionIsProjectedWithoutRuntimeDiagnostics(t *testing.T) {
	report := fixtureVMAttribution("available")
	report.Diagnostics.RawError = "forbidden 0xffff request_pointer /proc/123/cmdline"
	snapshot, err := Collect(context.Background(), Request{
		Victim: "a-web", Suspect: "b-stress", Duration: 10 * time.Second, Interval: 2 * time.Second,
		IncludeEBPFLatency: true, EBPFVMAttribution: &report, EBPFSourceWindow: "noisy_neighbor_diagnosis_window",
	}, fixtureVMs(), fixtureDependencies(false))
	if err != nil {
		t.Fatal(err)
	}
	evidence := snapshot.EBPFVMAttribution
	if evidence == nil || !evidence.Available || evidence.Quality != "available" {
		t.Fatalf("VM attribution = %#v", evidence)
	}
	if evidence.VictimTotalOps != 4 || evidence.SuspectTotalOps != 96 || evidence.UnattributedPercent != 1 {
		t.Fatalf("VM attribution selection = %#v", evidence)
	}
	assertSectionState(t, snapshot, "ebpf_vm_attribution", EvidenceMeasured)
	for _, name := range []string{"host_storage_latency_available", "vm_ebpf_attribution_available", "suspect_vm_attributed_io_observed"} {
		correlation, ok := findCorrelation(snapshot, name)
		if !ok || !correlation.Present {
			t.Errorf("correlation %q = %#v, present=%v", name, correlation, ok)
		}
	}
	raw := strings.ToLower(render(t, snapshot))
	for _, forbidden := range []string{"request_pointer", "0xffff", "/proc/", "cmdline"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("observe projection leaked %q", forbidden)
		}
	}
	if !strings.Contains(raw, "does not establish causality") {
		t.Fatal("observe projection omitted causality caveat")
	}
}

func TestDegradedVMAttributionIsPartialAndUnavailableIsNotFabricated(t *testing.T) {
	degraded := fixtureVMAttribution("degraded")
	snapshot, err := Collect(context.Background(), Request{
		Victim: "a-web", Suspect: "b-stress", Duration: 10 * time.Second, Interval: 2 * time.Second,
		IncludeEBPFLatency: true, EBPFVMAttribution: &degraded,
	}, fixtureVMs(), fixtureDependencies(false))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.EBPFVMAttribution == nil || !snapshot.EBPFVMAttribution.Available || snapshot.EBPFVMAttribution.Quality != "degraded" {
		t.Fatalf("degraded attribution = %#v", snapshot.EBPFVMAttribution)
	}
	assertSectionState(t, snapshot, "ebpf_vm_attribution", EvidencePartial)
	if snapshot.EvidenceQuality.Overall != EvidencePartial {
		t.Fatalf("overall quality = %q, want partial", snapshot.EvidenceQuality.Overall)
	}

	unavailable := fixtureVMAttribution("unavailable")
	unavailable.Availability = ebpf.VMBlockLatencyAvailability{Available: false, Status: "permission_denied", Error: "raw detail must not be projected"}
	snapshot, err = Collect(context.Background(), Request{
		Victim: "a-web", Suspect: "b-stress", Duration: 10 * time.Second, Interval: 2 * time.Second,
		IncludeEBPFLatency: true, EBPFVMAttribution: &unavailable,
	}, fixtureVMs(), fixtureDependencies(false))
	if err != nil {
		t.Fatal(err)
	}
	evidence := snapshot.EBPFVMAttribution
	if evidence == nil || evidence.Available || evidence.AttributedOps != 0 || evidence.VictimTotalOps != 0 || evidence.SuspectTotalOps != 0 || len(evidence.VMs) != 0 {
		t.Fatalf("unavailable attribution was fabricated: %#v", evidence)
	}
	assertSectionState(t, snapshot, "ebpf_vm_attribution", EvidenceUnavailable)
	if strings.Contains(render(t, snapshot), "raw detail") {
		t.Fatal("raw collector error was projected into observe JSON")
	}
}

func TestVMAttributionPrivacyViolationIsRejected(t *testing.T) {
	report := fixtureVMAttribution("available")
	report.Privacy.EnvironmentCollected = true
	_, err := Collect(context.Background(), Request{
		Victim: "a-web", Suspect: "b-stress", Duration: 10 * time.Second, Interval: 2 * time.Second,
		IncludeEBPFLatency: true, EBPFVMAttribution: &report,
	}, fixtureVMs(), fixtureDependencies(false))
	if err == nil || !strings.Contains(err.Error(), "cannot contain") {
		t.Fatalf("unsafe eBPF privacy flags were not rejected: %v", err)
	}
}

func TestUnknownVictimAndSuspectAreRejected(t *testing.T) {
	dependencies := fixtureDependencies(false)
	_, err := Collect(context.Background(), Request{Victim: "missing", Duration: time.Second, Interval: time.Second}, fixtureVMs(), dependencies)
	if err == nil || !strings.Contains(err.Error(), "victim VM not found") {
		t.Fatalf("unknown victim error = %v", err)
	}
	_, err = Collect(context.Background(), Request{Victim: "a-web", Suspect: "missing", Duration: time.Second, Interval: time.Second}, fixtureVMs(), dependencies)
	if err == nil || !strings.Contains(err.Error(), "suspect VM not found") {
		t.Fatalf("unknown suspect error = %v", err)
	}
}

func collectFixture(t *testing.T, request Request) ObserveSnapshot {
	t.Helper()
	snapshot, err := Collect(context.Background(), request, fixtureVMs(), fixtureDependencies(false))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func fixtureVMs() []inventory.VM {
	return []inventory.VM{
		{Name: "a-web", Tenant: "tenant-a", Role: "web", State: "running", IPPlan: "192.0.2.10", QEMUPID: "101", Disk: "/images/a-web.qcow2"},
		{Name: "b-stress", Tenant: "tenant-b", Role: "stress", State: "running", IPPlan: "192.0.2.20", QEMUPID: "102", Disk: "/images/b-stress.qcow2"},
	}
}

func fixtureDependencies(withDiscovery bool) Dependencies {
	vms := fixtureVMs()
	dependencies := Dependencies{
		Now: func() time.Time { return time.Date(2026, 8, 9, 10, 11, 12, 123, time.UTC) },
		Host: func(_ context.Context, windowID string) (hostmetrics.HostStatus, error) {
			return hostmetrics.HostStatus{SchemaVersion: "1", ObservedAtUTC: "2026-08-09T10:11:12Z", WindowID: windowID,
				Availability: measuredAvailability("fixture host")}, nil
		},
		QEMU: func(_ context.Context, plan qemuio.Plan, duration, interval time.Duration) (qemuio.SummaryReport, error) {
			byName := map[string]qemuio.VMSummary{
				"a-web":    {Available: true, AverageWriteMiBPerSecond: 1, AverageSyscwPerSecond: 10},
				"b-stress": {Available: true, AverageWriteMiBPerSecond: 25, MaxWriteMiBPerSecond: 30, AverageSyscwPerSecond: 25000, MaxSyscwPerSecond: 30000},
			}
			report := qemuio.SummaryReport{Plan: plan, Duration: duration, Interval: interval, Thresholds: config.DefaultThresholds(), VMs: []qemuio.VMSummary{}}
			for _, target := range plan.Targets {
				summary := byName[target.VM.Name]
				summary.Target = target
				report.VMs = append(report.VMs, summary)
			}
			return report, nil
		},
		Storage: func(path string) hoststorage.Mapping {
			return hoststorage.Mapping{DiskPath: path, Mountpoint: "/images", SourceDevice: "/dev/mapper/vg-vms", ParentDevice: "/dev/nvme0n1p3", PhysicalDisk: "/dev/nvme0n1"}
		},
	}
	if withDiscovery {
		dependencies.Discovery = func(_ []inventory.VM, _ string, sampled qemuio.SummaryReport) (discovery.Report, error) {
			candidateSummary := sampled.VMs[1]
			candidate := discovery.Candidate{VM: vms[1], SharedDisk: true, Summary: candidateSummary, Score: "HIGH", Reason: "dominant byte write rate"}
			return discovery.Report{Victim: vms[0], VictimStorage: dependencies.Storage(vms[0].Disk), Candidates: []discovery.Candidate{candidate}, Selected: &candidate, SelectionReason: candidate.Reason}, nil
		}
	}
	return dependencies
}

func measuredAvailability(source string) observability.Availability {
	return observability.Availability{Available: true, Source: source, Quality: observability.EvidenceQualityMeasured}
}

func fixtureVMAttribution(quality string) ebpf.VMBlockLatencyReport {
	return ebpf.VMBlockLatencyReport{
		SchemaVersion: "1", ObservedAtUTC: "2026-08-09T10:11:12Z", Duration: "10s", Interval: "2s",
		Mode: "experimental", CollectionMode: "typed_btf_vm_attributed_latency",
		AttributionMethod: "blkcg_cgroup_id_to_libvirt_vm", AttributionQuality: quality,
		Availability:       ebpf.VMBlockLatencyAvailability{Available: true, Status: "available"},
		HostSummary:        ebpf.VMBlockLatencySummary{TotalOps: 101, LatencyP95MS: 2.5},
		AttributionSummary: ebpf.VMBlockAttributionSummary{AttributedOps: 100, UnattributedOps: 1, AttributedPercent: 99, MatchedVMCount: 2},
		Unattributed:       ebpf.VMBlockLatencyUnattributed{TotalUnattributedOps: 1, UnattributedPercent: 1},
		VMs: []ebpf.VMBlockLatencyVM{
			{Name: "a-web", Tenant: "tenant-a", Role: "web", ReadOps: 4, TotalOps: 4, LatencyP95MS: 1.25, AttributionQuality: quality},
			{Name: "b-stress", Tenant: "tenant-b", Role: "stress", WriteOps: 96, TotalOps: 96, LatencyP95MS: 2.5, AttributionQuality: quality},
		},
		Caveats: []string{"experimental exact-match cgroup attribution"},
	}
}

func assertSectionState(t *testing.T, snapshot ObserveSnapshot, section string, state EvidenceState) {
	t.Helper()
	for _, value := range snapshot.EvidenceQuality.Sections {
		if value.Section == section {
			if value.State != state {
				t.Fatalf("section %s state = %s, want %s", section, value.State, state)
			}
			return
		}
	}
	t.Fatalf("section %s missing from evidence quality", section)
}

func findCorrelation(snapshot ObserveSnapshot, name string) (Correlation, bool) {
	for _, correlation := range snapshot.Correlations {
		if correlation.Name == name {
			return correlation, true
		}
	}
	return Correlation{}, false
}

func render(t *testing.T, snapshot ObserveSnapshot) string {
	t.Helper()
	var output bytes.Buffer
	if err := WriteJSON(&output, snapshot); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func assertUnavailableState(t *testing.T, snapshot ObserveSnapshot, section string, state EvidenceState) {
	t.Helper()
	for _, unavailable := range snapshot.UnavailableSections {
		if unavailable.Section == section {
			if unavailable.State != state {
				t.Fatalf("section %s state = %s, want %s", section, unavailable.State, state)
			}
			return
		}
	}
	t.Fatalf("section %s missing from unavailable sections", section)
}
