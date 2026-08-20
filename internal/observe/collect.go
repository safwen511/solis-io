package observe

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/hostmetrics"
	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/observability"
	"github.com/safwen511/solis-io/internal/qemuio"
	"github.com/safwen511/solis-io/internal/servicehealth"
	statusview "github.com/safwen511/solis-io/internal/status"
)

type Request struct {
	Victim             string
	Suspect            string
	DiscoverSuspects   bool
	Duration           time.Duration
	Interval           time.Duration
	ConfigSource       string
	IncludeGuest       bool
	IncludeServices    bool
	IncludeDB          bool
	IncludeEBPFLatency bool
	GuestEnabled       bool
	ServiceConfigured  map[string]bool
	DatabaseConfigured map[string]bool
	EBPFVMAttribution  *ebpf.VMBlockLatencyReport
	EBPFSourceWindow   string
}

type Dependencies struct {
	Now       func() time.Time
	Host      func(context.Context, string) (hostmetrics.HostStatus, error)
	QEMU      func(context.Context, qemuio.Plan, time.Duration, time.Duration) (qemuio.SummaryReport, error)
	Guest     func(context.Context, inventory.VM, string) (observability.GuestStatus, error)
	Service   func(context.Context, inventory.VM, string) (servicehealth.Report, error)
	Database  func(context.Context, inventory.VM, string) (observability.DBStatus, error)
	Storage   func(string) hoststorage.Mapping
	Discovery func([]inventory.VM, string, qemuio.SummaryReport) (discovery.Report, error)
}

type hostResult struct {
	status hostmetrics.HostStatus
	err    error
}
type qemuResult struct {
	report qemuio.SummaryReport
	err    error
}

type optionalResult struct{ snapshot ObserveSnapshot }

// Collect collects bounded evidence from the configured source and propagates source failures.
func Collect(ctx context.Context, request Request, vms []inventory.VM, dependencies Dependencies) (ObserveSnapshot, error) {
	if strings.TrimSpace(request.Victim) == "" {
		return ObserveSnapshot{}, errors.New("victim is required")
	}
	if request.Suspect != "" && request.DiscoverSuspects {
		return ObserveSnapshot{}, errors.New("suspect and discover-suspects are mutually exclusive")
	}
	if request.Duration <= 0 || request.Interval <= 0 {
		return ObserveSnapshot{}, errors.New("duration and interval must be positive")
	}
	if request.Interval > request.Duration {
		return ObserveSnapshot{}, fmt.Errorf("interval %s cannot exceed duration %s", request.Interval, request.Duration)
	}
	victim, ok := inventory.FindByName(vms, request.Victim)
	if !ok {
		return ObserveSnapshot{}, fmt.Errorf("victim VM not found: %s", request.Victim)
	}
	var explicitSuspect *inventory.VM
	if request.Suspect != "" {
		resolved, found := inventory.FindByName(vms, request.Suspect)
		if !found {
			return ObserveSnapshot{}, fmt.Errorf("suspect VM not found: %s", request.Suspect)
		}
		explicitSuspect = resolved
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	if dependencies.Storage == nil {
		dependencies.Storage = func(string) hoststorage.Mapping { return hoststorage.Mapping{} }
	}
	started := dependencies.Now().UTC()
	windowID := "observe-" + started.Format("20060102T150405.000000000Z")
	snapshot := ObserveSnapshot{
		SchemaVersion: SchemaVersion, ObservedAtUTC: started.Format(time.RFC3339Nano), WindowID: windowID,
		Duration: request.Duration.String(), Interval: request.Interval.String(), ConfigSource: valueOrDefault(request.ConfigSource, "built-in defaults"),
		Victim: targetFromVM(*victim), SelectedSuspect: "-", SuspectMode: suspectMode(request),
		Discovery: DiscoveryEvidence{Enabled: request.DiscoverSuspects, Victim: victim.Name, VictimPhysicalDisk: "-", SelectedSuspect: "-",
			SelectionReason: "not requested", Candidates: []DiscoveryCandidate{}},
		Correlations: []Correlation{}, UnavailableSections: []UnavailableSection{}, Caveats: []string{},
	}
	if request.DiscoverSuspects {
		snapshot.Discovery.SelectionReason = "-"
	}

	plan := allRunningPlan(vms)
	hostChannel := make(chan hostResult, 1)
	qemuChannel := make(chan qemuResult, 1)
	victimOptionalChannel := startTargetOptionals(ctx, "victim", *victim, request, windowID, dependencies)
	var suspectOptionalChannel <-chan optionalResult
	if explicitSuspect != nil {
		suspectOptionalChannel = startTargetOptionals(ctx, "suspect", *explicitSuspect, request, windowID, dependencies)
	}
	go func() {
		if dependencies.Host == nil {
			hostChannel <- hostResult{err: errors.New("host collector is unavailable")}
			return
		}
		status, err := dependencies.Host(ctx, windowID)
		hostChannel <- hostResult{status: status, err: err}
	}()
	go func() {
		if dependencies.QEMU == nil {
			qemuChannel <- qemuResult{err: errors.New("QEMU collector is unavailable")}
			return
		}
		report, err := dependencies.QEMU(ctx, plan, request.Duration, request.Interval)
		qemuChannel <- qemuResult{report: report, err: err}
	}()
	hostEvidence, qemuEvidence := <-hostChannel, <-qemuChannel

	if hostEvidence.err != nil {
		addSection(&snapshot, "host_status", EvidenceError, "local host collector", hostEvidence.err.Error())
	} else {
		snapshot.HostStatus = &hostEvidence.status
		state := stateForAvailability(hostEvidence.status.Availability)
		addSection(&snapshot, "host_status", state, hostEvidence.status.Availability.Source, hostEvidence.status.Availability.Error)
	}

	baseQEMU := qemuEvidence.report
	if qemuEvidence.err != nil {
		baseQEMU = unavailableQEMUReport(plan, request.Duration, request.Interval, qemuEvidence.err)
	}
	snapshot.VMStatus = buildVMStatus(vms, baseQEMU, request.Duration, request.Interval, dependencies.Storage)
	vmState := EvidenceMeasured
	if qemuEvidence.err != nil || vmReportPartial(snapshot.VMStatus) {
		vmState = EvidencePartial
	}
	addSection(&snapshot, "vm_status", vmState, "inventory, storage topology, and QEMU process counters", errorString(qemuEvidence.err))

	selected := explicitSuspect
	if request.DiscoverSuspects {
		if dependencies.Discovery == nil {
			addSection(&snapshot, "discovery", EvidenceError, "suspect discovery", "discovery collector is unavailable")
		} else if report, err := dependencies.Discovery(vms, victim.Name, baseQEMU); err != nil {
			addSection(&snapshot, "discovery", EvidenceError, "suspect discovery", err.Error())
		} else {
			snapshot.Discovery = discoveryEvidence(report)
			addSection(&snapshot, "discovery", EvidenceDerived, "same-storage QEMU writer ranking", "")
			if report.Selected != nil {
				candidate := report.Selected.VM
				selected = &candidate
			}
		}
	} else {
		addSection(&snapshot, "discovery", EvidenceDisabled, "suspect discovery", "discovery was not requested")
	}
	if selected != nil {
		snapshot.SelectedSuspect = selected.Name
	}

	pairQEMU := qemuForTargets(baseQEMU, *victim, selected)
	snapshot.QEMUEvidence = sanitizeQEMU(pairQEMU)
	qemuState := EvidenceMeasured
	if !snapshot.QEMUEvidence.Available {
		qemuState = EvidenceUnavailable
	}
	addSection(&snapshot, "qemu_evidence", qemuState, "per-QEMU /proc PID I/O counters", qemuAvailabilityError(pairQEMU))
	snapshot.StorageTopology = buildStorage(*victim, selected, dependencies.Storage)
	storageState := EvidenceDerived
	if !snapshot.StorageTopology.Available {
		storageState = EvidenceUnavailable
	}
	addSection(&snapshot, "storage_topology", storageState, "inventory disk and host block mapping", storageError(snapshot.StorageTopology))

	mergeOptionalResult(&snapshot, <-victimOptionalChannel)
	if suspectOptionalChannel != nil {
		mergeOptionalResult(&snapshot, <-suspectOptionalChannel)
	} else if selected != nil {
		// Discovery depends on the completed QEMU window, so a newly selected
		// suspect cannot be sampled until ranking has finished. Its own model
		// timestamp makes that offset explicit.
		partial := ObserveSnapshot{}
		collectTargetOptionals(ctx, "suspect", *selected, request, windowID, dependencies, &partial)
		mergeOptionalResult(&snapshot, optionalResult{snapshot: partial})
	}
	if request.EBPFVMAttribution != nil {
		ApplyEBPFVMAttribution(&snapshot, request.EBPFVMAttribution, request.EBPFSourceWindow)
	} else if request.IncludeEBPFLatency {
		addSection(&snapshot, "ebpf_vm_attribution", EvidenceUnsupported, "typed-BTF VM block-latency attribution", "no existing VM-attribution report was supplied to the observe collector")
	} else {
		addSection(&snapshot, "ebpf_vm_attribution", EvidenceDisabled, "typed-BTF VM block-latency attribution", "not requested")
	}
	buildCorrelations(&snapshot)
	snapshot.Caveats = append(snapshot.Caveats, "Snapshot records correlation candidates only; it does not establish causality or a customer-impact verdict.")
	if snapshot.VictimServiceStatus == nil || snapshot.VictimDBStatus == nil ||
		(snapshot.VictimServiceStatus != nil && !snapshot.VictimServiceStatus.Availability.Available) ||
		(snapshot.VictimDBStatus != nil && !snapshot.VictimDBStatus.Availability.Available) {
		snapshot.Caveats = append(snapshot.Caveats, "Application/DB impact evidence unavailable; snapshot can show infrastructure pressure only.")
	}
	finalizeQuality(&snapshot)
	if err := validateSnapshotPrivacy(snapshot); err != nil {
		return ObserveSnapshot{}, err
	}
	return snapshot, nil
}

// startTargetOptionals starts target optionals and returns its initial state.
func startTargetOptionals(ctx context.Context, prefix string, vm inventory.VM, request Request, windowID string, dependencies Dependencies) <-chan optionalResult {
	result := make(chan optionalResult, 1)
	go func() {
		partial := ObserveSnapshot{}
		collectTargetOptionals(ctx, prefix, vm, request, windowID, dependencies, &partial)
		result <- optionalResult{snapshot: partial}
	}()
	return result
}

// mergeOptionalResult merges optional result while preserving explicit availability.
func mergeOptionalResult(snapshot *ObserveSnapshot, result optionalResult) {
	partial := result.snapshot
	if partial.VictimGuestStatus != nil {
		snapshot.VictimGuestStatus = partial.VictimGuestStatus
	}
	if partial.VictimServiceStatus != nil {
		snapshot.VictimServiceStatus = partial.VictimServiceStatus
	}
	if partial.VictimDBStatus != nil {
		snapshot.VictimDBStatus = partial.VictimDBStatus
	}
	if partial.SuspectGuestStatus != nil {
		snapshot.SuspectGuestStatus = partial.SuspectGuestStatus
	}
	if partial.SuspectServiceStatus != nil {
		snapshot.SuspectServiceStatus = partial.SuspectServiceStatus
	}
	if partial.SuspectDBStatus != nil {
		snapshot.SuspectDBStatus = partial.SuspectDBStatus
	}
	snapshot.EvidenceQuality.Sections = append(snapshot.EvidenceQuality.Sections, partial.EvidenceQuality.Sections...)
	snapshot.UnavailableSections = append(snapshot.UnavailableSections, partial.UnavailableSections...)
}

// collectTargetOptionals collects target optionals from the configured evidence sources.
func collectTargetOptionals(ctx context.Context, prefix string, vm inventory.VM, request Request, windowID string, dependencies Dependencies, snapshot *ObserveSnapshot) {
	guestName, serviceName, dbName := prefix+"_guest_status", prefix+"_service_status", prefix+"_db_status"
	if !request.GuestEnabled {
		addSection(snapshot, guestName, EvidenceDisabled, "allowlisted guest collector", "guest collection is disabled in configuration")
	} else if !request.IncludeGuest {
		addSection(snapshot, guestName, EvidenceDisabled, "allowlisted guest collector", "guest collection was not requested")
	} else if dependencies.Guest == nil {
		addSection(snapshot, guestName, EvidenceError, "allowlisted guest collector", "guest collector is unavailable")
	} else if status, err := dependencies.Guest(ctx, vm, windowID); err != nil {
		addSection(snapshot, guestName, EvidenceError, "allowlisted guest collector", err.Error())
	} else {
		if prefix == "victim" {
			snapshot.VictimGuestStatus = &status
		} else {
			snapshot.SuspectGuestStatus = &status
		}
		addSection(snapshot, guestName, stateForAvailability(status.Availability), status.Availability.Source, status.Availability.Error)
	}

	if !request.ServiceConfigured[vm.Name] {
		addSection(snapshot, serviceName, EvidenceNotConfigured, "configured service collector", "no services configured for VM")
	} else if !request.IncludeServices {
		addSection(snapshot, serviceName, EvidenceDisabled, "configured service collector", "service collection was not requested")
	} else if !request.GuestEnabled {
		addSection(snapshot, serviceName, EvidenceDisabled, "configured service collector", "guest collection is disabled in configuration")
	} else if dependencies.Service == nil {
		addSection(snapshot, serviceName, EvidenceError, "configured service collector", "service collector is unavailable")
	} else if status, err := dependencies.Service(ctx, vm, windowID); err != nil {
		addSection(snapshot, serviceName, EvidenceError, "configured service collector", err.Error())
	} else {
		if prefix == "victim" {
			snapshot.VictimServiceStatus = &status
		} else {
			snapshot.SuspectServiceStatus = &status
		}
		addSection(snapshot, serviceName, stateForAvailability(status.Availability), status.Availability.Source, status.Availability.Error)
	}

	if !request.DatabaseConfigured[vm.Name] {
		addSection(snapshot, dbName, EvidenceNotConfigured, "configured PostgreSQL statistics collector", "no database configured for VM")
	} else if !request.IncludeDB {
		addSection(snapshot, dbName, EvidenceDisabled, "configured PostgreSQL statistics collector", "database collection was not requested")
	} else if dependencies.Database == nil {
		addSection(snapshot, dbName, EvidenceError, "configured PostgreSQL statistics collector", "database collector is unavailable")
	} else if status, err := dependencies.Database(ctx, vm, windowID); err != nil {
		addSection(snapshot, dbName, EvidenceError, "configured PostgreSQL statistics collector", err.Error())
	} else {
		if prefix == "victim" {
			snapshot.VictimDBStatus = &status
		} else {
			snapshot.SuspectDBStatus = &status
		}
		addSection(snapshot, dbName, stateForAvailability(status.Availability), status.Availability.Source, status.Availability.Error)
	}
}

// allRunningPlan builds all running plan from validated inputs.
func allRunningPlan(vms []inventory.VM) qemuio.Plan {
	plan := qemuio.Plan{VictimSelector: "observe-status"}
	for _, vm := range vms {
		if strings.EqualFold(strings.TrimSpace(vm.State), "running") && positivePID(vm.QEMUPID) {
			plan.Targets = append(plan.Targets, qemuio.Target{TargetType: "status", VM: vm})
		}
	}
	sort.Slice(plan.Targets, func(i, j int) bool { return plan.Targets[i].VM.Name < plan.Targets[j].VM.Name })
	return plan
}

// unavailableQEMUReport builds unavailable QEMU report from validated inputs.
func unavailableQEMUReport(plan qemuio.Plan, duration, interval time.Duration, err error) qemuio.SummaryReport {
	report := qemuio.SummaryReport{Plan: plan, Duration: duration, Interval: interval}
	for _, target := range plan.Targets {
		report.VMs = append(report.VMs, qemuio.VMSummary{Target: target, Error: errorString(err)})
	}
	return report
}

// buildVMStatus builds vm status from validated inputs.
func buildVMStatus(vms []inventory.VM, report qemuio.SummaryReport, duration, interval time.Duration, resolve func(string) hoststorage.Mapping) statusview.Report {
	byName := make(map[string]qemuio.VMSummary, len(report.VMs))
	for _, summary := range report.VMs {
		byName[summary.Target.VM.Name] = summary
	}
	samples := make([]statusview.Sample, 0)
	for _, target := range allRunningPlan(vms).Targets {
		samples = append(samples, statusview.Sample{VM: target.VM, Storage: resolve(target.VM.Disk), QEMU: byName[target.VM.Name]})
	}
	return statusview.NewReportWithThresholds(duration, interval, samples, report.Thresholds)
}

// qemuForTargets builds QEMU for targets from validated inputs.
func qemuForTargets(base qemuio.SummaryReport, victim inventory.VM, suspect *inventory.VM) qemuio.SummaryReport {
	plan := qemuio.Plan{VictimSelector: victim.Name, Targets: []qemuio.Target{{TargetType: "victim", VM: victim}}}
	if suspect != nil {
		plan.SuspectSelector = suspect.Name
		plan.Targets = append(plan.Targets, qemuio.Target{TargetType: "suspect", VM: *suspect})
	}
	return qemuio.SummaryForPlan(base, plan)
}

// sanitizeQEMU sanitizes qemu for safe output.
func sanitizeQEMU(report qemuio.SummaryReport) QEMUEvidence {
	evidence := QEMUEvidence{
		VMs: []QEMUVM{}, VictimAverageWriteMiBS: report.VictimAverageWriteMiBPerSecond,
		SuspectAverageWriteMiBS: report.SuspectAverageWriteMiBPerSecond, VictimAverageSyscwS: report.VictimAverageSyscwPerSecond,
		SuspectAverageSyscwS:      report.SuspectAverageSyscwPerSecond,
		MeaningfulSuspectPressure: report.MeaningfulSuspectWritePressure || report.MeaningfulSuspectSyscwPressure,
		SuspectDominant:           report.SuspectDominant || report.SuspectSyscwDominant, DominantWriter: valueOrDash(report.DominantWriter),
		DominantWriteSyscallSource: valueOrDash(report.DominantWriteSyscallSource), Conclusion: report.Conclusion,
	}
	for _, summary := range report.VMs {
		if summary.Available {
			evidence.Available = true
		}
		evidence.VMs = append(evidence.VMs, QEMUVM{TargetType: summary.Target.TargetType, VM: summary.Target.VM.Name, Available: summary.Available,
			AverageReadMiBS: summary.AverageReadMiBPerSecond, AverageWriteMiBS: summary.AverageWriteMiBPerSecond,
			MaxWriteMiBS: summary.MaxWriteMiBPerSecond, AverageSyscrS: summary.AverageSyscrPerSecond,
			AverageSyscwS: summary.AverageSyscwPerSecond, MaxSyscwS: summary.MaxSyscwPerSecond, Error: oneLine(summary.Error)})
	}
	if strings.TrimSpace(report.Plan.SuspectSelector) == "" {
		if evidence.Available {
			evidence.Conclusion = "Victim QEMU process I/O counters measured; no suspect comparison was requested."
		} else {
			evidence.Conclusion = "Victim QEMU process I/O counters were unavailable."
		}
	}
	return evidence
}

// discoveryEvidence builds discovery evidence from validated inputs.
func discoveryEvidence(report discovery.Report) DiscoveryEvidence {
	evidence := DiscoveryEvidence{Enabled: true, Available: true, Victim: report.Victim.Name, VictimPhysicalDisk: valueOrDash(report.VictimStorage.PhysicalDisk), SelectedSuspect: "-", SelectionReason: report.SelectionReason, Candidates: []DiscoveryCandidate{}}
	if report.Selected != nil {
		evidence.SelectedSuspect = report.Selected.VM.Name
	}
	for _, candidate := range report.Candidates {
		evidence.Candidates = append(evidence.Candidates, DiscoveryCandidate{Name: candidate.VM.Name, Tenant: candidate.VM.Tenant, Role: candidate.VM.Role,
			SharedDisk: candidate.SharedDisk, AverageWriteMiBS: candidate.Summary.AverageWriteMiBPerSecond, MaxWriteMiBS: candidate.Summary.MaxWriteMiBPerSecond,
			AverageSyscwS: candidate.Summary.AverageSyscwPerSecond, MaxSyscwS: candidate.Summary.MaxSyscwPerSecond, Score: candidate.Score, Reason: candidate.Reason})
	}
	return evidence
}

// buildStorage builds storage from validated inputs.
func buildStorage(victim inventory.VM, suspect *inventory.VM, resolve func(string) hoststorage.Mapping) StorageTopology {
	victimMapping := resolve(victim.Disk)
	topology := StorageTopology{Available: mappingAvailable(victimMapping), PhysicalDisk: valueOrDash(victimMapping.PhysicalDisk), Targets: []StorageTarget{storageTarget("victim", victim, victimMapping)}}
	if suspect != nil {
		suspectMapping := resolve(suspect.Disk)
		topology.Targets = append(topology.Targets, storageTarget("suspect", *suspect, suspectMapping))
		topology.SharedPhysicalDisk, topology.PhysicalDisk = sharedPhysicalDisk(victimMapping.PhysicalDisk, suspectMapping.PhysicalDisk)
		topology.Available = topology.Available && mappingAvailable(suspectMapping)
	}
	return topology
}

// storageTarget builds storage target from validated inputs.
func storageTarget(kind string, vm inventory.VM, mapping hoststorage.Mapping) StorageTarget {
	return StorageTarget{TargetType: kind, VM: vm.Name, Disk: valueOrDash(firstNonEmpty(mapping.DiskPath, vm.Disk)), Mountpoint: valueOrDash(mapping.Mountpoint), SourceDevice: valueOrDash(mapping.SourceDevice), ParentDevice: valueOrDash(mapping.ParentDevice), PhysicalDisk: valueOrDash(mapping.PhysicalDisk)}
}

// targetFromVM builds target from VM from validated inputs.
func targetFromVM(vm inventory.VM) Target {
	pid, _ := strconv.Atoi(strings.TrimSpace(vm.QEMUPID))
	ip := vm.IPLease
	if strings.TrimSpace(ip) == "" {
		ip = vm.IPPlan
	}
	return Target{Name: vm.Name, Tenant: vm.Tenant, Role: vm.Role, State: valueOrDash(vm.State), IP: valueOrDash(ip), QEMUPID: pid, Disk: valueOrDash(vm.Disk)}
}

// positivePID reports whether positive pid.
func positivePID(value string) bool {
	pid, err := strconv.Atoi(strings.TrimSpace(value))
	return err == nil && pid > 0
}

// suspectMode derives stable operator-facing text for suspect mode.
func suspectMode(request Request) string {
	if request.DiscoverSuspects {
		return "discover-suspects"
	}
	if request.Suspect != "" {
		return "pairwise"
	}
	return "victim-only"
}

// stateForAvailability builds state for availability from validated inputs.
func stateForAvailability(value observability.Availability) EvidenceState {
	if value.Available && value.Error != "" {
		return EvidencePartial
	}
	if value.Available {
		return EvidenceMeasured
	}
	return EvidenceUnavailable
}

// mappingAvailable maps mapping available into its corresponding evidence identity.
func mappingAvailable(mapping hoststorage.Mapping) bool {
	return strings.TrimSpace(mapping.PhysicalDisk) != "" && strings.TrimSpace(mapping.PhysicalDisk) != "-"
}

// valueOrDefault returns the trimmed value or the supplied fallback when it is empty.
func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// valueOrDash trims a value and substitutes a dash when no value is available.
func valueOrDash(value string) string { return valueOrDefault(value, "-") }

// firstNonEmpty returns the first non-empty string in argument order.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// oneLine collapses whitespace so diagnostic text cannot break line-oriented output.
func oneLine(value string) string { return strings.Join(strings.Fields(value), " ") }

// errorString derives stable operator-facing text for error string.
func errorString(err error) string {
	if err == nil {
		return ""
	}
	return oneLine(err.Error())
}

// vmReportPartial reports whether vm report partial.
func vmReportPartial(report statusview.Report) bool {
	for _, vm := range report.VMs {
		if !vm.IOAvailable {
			return true
		}
	}
	return false
}

// qemuAvailabilityError derives stable operator-facing text for QEMU availability error.
func qemuAvailabilityError(report qemuio.SummaryReport) string {
	var values []string
	for _, vm := range report.VMs {
		if !vm.Available {
			values = append(values, vm.Target.VM.Name+": "+valueOrDefault(oneLine(vm.Error), "unavailable"))
		}
	}
	return strings.Join(values, "; ")
}

// storageError derives stable operator-facing text for storage error.
func storageError(topology StorageTopology) string {
	if topology.Available {
		return ""
	}
	return "physical storage mapping unavailable for one or more targets"
}

// sharedPhysicalDisk builds shared physical disk from validated inputs.
func sharedPhysicalDisk(left, right string) (bool, string) {
	leftSet := make(map[string]bool)
	for _, item := range strings.Split(left, ",") {
		item = strings.TrimSpace(item)
		if item != "" && item != "-" {
			leftSet[item] = true
		}
	}
	var shared []string
	for _, item := range strings.Split(right, ",") {
		item = strings.TrimSpace(item)
		if leftSet[item] {
			shared = append(shared, item)
		}
	}
	sort.Strings(shared)
	if len(shared) == 0 {
		return false, "-"
	}
	return true, strings.Join(shared, ",")
}
