package observe

import (
	"sort"
	"strings"

	"github.com/safwen511/solis-io/internal/observability"
	"github.com/safwen511/solis-io/internal/servicehealth"
)

func addSection(snapshot *ObserveSnapshot, name string, state EvidenceState, source, detail string) {
	detail = oneLine(detail)
	snapshot.EvidenceQuality.Sections = append(snapshot.EvidenceQuality.Sections, SectionQuality{Section: name, State: state, Source: oneLine(source), Error: detail})
	if state == EvidenceUnavailable || state == EvidencePartial || state == EvidenceDisabled || state == EvidenceNotConfigured || state == EvidenceUnsupported || state == EvidenceError {
		snapshot.UnavailableSections = append(snapshot.UnavailableSections, UnavailableSection{Section: name, State: state, Reason: detail})
	}
}

func finalizeQuality(snapshot *ObserveSnapshot) {
	overall := EvidenceMeasured
	baseAvailable := false
	for _, section := range snapshot.EvidenceQuality.Sections {
		if section.Section == "host_status" || section.Section == "vm_status" || section.Section == "qemu_evidence" || section.Section == "storage_topology" {
			if section.State == EvidenceMeasured || section.State == EvidenceDerived || section.State == EvidencePartial {
				baseAvailable = true
			}
			if section.State == EvidenceUnavailable || section.State == EvidenceError {
				overall = EvidencePartial
			}
		}
		if section.State == EvidencePartial || section.State == EvidenceError {
			overall = EvidencePartial
		}
	}
	if !baseAvailable {
		overall = EvidenceUnavailable
	}
	snapshot.EvidenceQuality.Overall = overall
}

func buildCorrelations(snapshot *ObserveSnapshot) {
	hostAvailable := snapshot.HostStatus != nil && snapshot.HostStatus.Availability.Available
	addCorrelation(snapshot, Correlation{
		Name: "host_metrics_available", Present: hostAvailable, Severity: "info",
		Explanation:  "Availability of provider-side host CPU, memory, PSI, filesystem, disk, network, and sanitized QEMU process metadata.",
		EvidenceRefs: []string{"host_status"},
	})
	addCorrelation(snapshot, Correlation{
		Name: "victim_and_suspect_share_physical_disk", Present: snapshot.SelectedSuspect != "-" && snapshot.StorageTopology.SharedPhysicalDisk,
		Severity: "info", Explanation: "Victim and selected suspect resolve to the same physical storage device; this is topology context, not proof of interference.",
		EvidenceRefs: []string{"storage_topology"},
	})
	qemuPressure := snapshot.SelectedSuspect != "-" && snapshot.QEMUEvidence.MeaningfulSuspectPressure && snapshot.QEMUEvidence.SuspectDominant
	addCorrelation(snapshot, Correlation{
		Name: "suspect_qemu_write_pressure_high", Present: qemuPressure,
		Severity: severity(qemuPressure, "likely"), Explanation: "Selected suspect shows dominant QEMU write-byte or write-syscall pressure during the shared observation window; this does not establish guest impact.",
		EvidenceRefs: []string{"qemu_evidence"},
	})
	upsertVMAttributionCorrelations(snapshot)
	addCorrelation(snapshot, availabilityCorrelation("victim_guest_available", snapshot.VictimGuestStatus != nil && snapshot.VictimGuestStatus.Availability.Available, "victim_guest_status"))
	serviceAvailable := snapshot.VictimServiceStatus != nil && snapshot.VictimServiceStatus.Availability.Available
	addCorrelation(snapshot, availabilityCorrelation("victim_service_available", serviceAvailable, "victim_service_status"))
	dbAvailable := snapshot.VictimDBStatus != nil && snapshot.VictimDBStatus.Availability.Available
	addCorrelation(snapshot, availabilityCorrelation("victim_db_available", dbAvailable, "victim_db_status"))
	dbWaits := dbAvailable && snapshot.VictimDBStatus.Activity.WaitingSessions > 0
	addCorrelation(snapshot, Correlation{Name: "db_waits_observed", Present: dbWaits, Severity: severity(dbWaits, "warning"), Explanation: "Non-idle PostgreSQL sessions reported wait events; no SQL text or table data was collected.", EvidenceRefs: []string{"victim_db_status.activity"}})
	healthError := serviceHealthError(snapshot.VictimServiceStatus)
	addCorrelation(snapshot, Correlation{Name: "service_health_error_observed", Present: healthError, Severity: severity(healthError, "warning"), Explanation: "A configured health endpoint returned an error status or could not be checked; response bodies were not collected.", EvidenceRefs: []string{"victim_service_status.services.health_checks"}})
}

func availabilityCorrelation(name string, present bool, ref string) Correlation {
	return Correlation{Name: name, Present: present, Severity: "info", Explanation: "Availability of sanitized victim-side metadata for cautious cross-layer correlation.", EvidenceRefs: []string{ref}}
}

func addCorrelation(snapshot *ObserveSnapshot, correlation Correlation) {
	correlation.EvidenceRefs = append([]string(nil), correlation.EvidenceRefs...)
	sort.Strings(correlation.EvidenceRefs)
	snapshot.Correlations = append(snapshot.Correlations, correlation)
}

func severity(present bool, whenPresent string) string {
	if present {
		return whenPresent
	}
	return "info"
}

func upsertVMAttributionCorrelations(snapshot *ObserveSnapshot) {
	removeCorrelations(snapshot,
		"host_storage_latency_available",
		"vm_ebpf_attribution_available",
		"suspect_vm_attributed_io_observed",
	)
	evidence := snapshot.EBPFVMAttribution
	attributionAvailable := evidence != nil && evidence.Available
	hostLatencyAvailable := attributionAvailable && evidence.HostTotalOps > 0
	addCorrelation(snapshot, Correlation{
		Name: "host_storage_latency_available", Present: hostLatencyAvailable, Severity: "info",
		Explanation:  "Availability of host block request issue/completion latency from the embedded typed-BTF VM-attribution evidence; this does not establish application impact.",
		EvidenceRefs: []string{"ebpf_vm_attribution.host_total_ops", "ebpf_vm_attribution.host_p95_ms"},
	})
	addCorrelation(snapshot, Correlation{
		Name: "vm_ebpf_attribution_available", Present: attributionAvailable, Severity: "info",
		Explanation:  "Availability of experimental exact-match blkcg/cgroup-ID evidence for local libvirt VMs; quality and unattributed work remain explicit.",
		EvidenceRefs: []string{"ebpf_vm_attribution"},
	})
	suspectIO := attributionAvailable && snapshot.SelectedSuspect != "-" && evidence.SuspectTotalOps > 0
	addCorrelation(snapshot, Correlation{
		Name: "suspect_vm_attributed_io_observed", Present: suspectIO,
		Severity:     severity(suspectIO, "warning"),
		Explanation:  "Block operations were attributed to the selected suspect during the embedded evidence window; this is correlation evidence, not proof of victim impact or root cause.",
		EvidenceRefs: []string{"ebpf_vm_attribution.suspect_total_ops", "ebpf_vm_attribution.unattributed_percent"},
	})
}

func removeCorrelations(snapshot *ObserveSnapshot, names ...string) {
	remove := make(map[string]bool, len(names))
	for _, name := range names {
		remove[name] = true
	}
	kept := snapshot.Correlations[:0]
	for _, correlation := range snapshot.Correlations {
		if !remove[correlation.Name] {
			kept = append(kept, correlation)
		}
	}
	snapshot.Correlations = kept
}

func serviceHealthError(report *servicehealth.Report) bool {
	if report == nil {
		return false
	}
	for _, service := range report.Services {
		for _, health := range service.HealthChecks {
			if !health.Availability.Available || health.StatusCode >= 400 {
				return true
			}
		}
	}
	return false
}

func privacySafe(flags observability.PrivacyFlags) bool {
	return !flags.ProcessArgumentsCollected && !flags.EnvironmentCollected && !flags.GuestFilesCollected &&
		!flags.QueryTextCollected && !flags.TableDataCollected && !flags.RequestBodyCollected &&
		!flags.ResponseBodyCollected && !flags.SecretsCollected
}

func qualityForAvailability(availability observability.Availability) EvidenceState {
	if availability.Available && strings.TrimSpace(availability.Error) != "" {
		return EvidencePartial
	}
	if availability.Available {
		return EvidenceMeasured
	}
	return EvidenceUnavailable
}
