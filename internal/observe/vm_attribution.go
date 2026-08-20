package observe

import (
	"strings"

	"github.com/safwen511/solis-io/internal/ebpf"
)

const defaultEBPFVMAttributionSourceWindow = "existing_evidence_window"

// ApplyEBPFVMAttribution adds an already-collected report to a snapshot. It
// never loads or attaches eBPF programs and deliberately projects away loader
// diagnostics, cgroup paths and IDs, and detailed raw histograms.
func ApplyEBPFVMAttribution(snapshot *ObserveSnapshot, report *ebpf.VMBlockLatencyReport, sourceWindow string) {
	removeEvidenceSection(snapshot, "ebpf_latency")
	removeEvidenceSection(snapshot, "ebpf_vm_attribution")
	if report == nil {
		snapshot.EBPFVMAttribution = nil
		addSection(snapshot, "ebpf_vm_attribution", EvidenceDisabled, "typed-BTF VM block-latency attribution", "not requested")
		upsertVMAttributionCorrelations(snapshot)
		finalizeQuality(snapshot)
		return
	}

	if strings.TrimSpace(sourceWindow) == "" {
		sourceWindow = defaultEBPFVMAttributionSourceWindow
	}
	quality := strings.TrimSpace(report.AttributionQuality)
	if quality == "" {
		quality = "unavailable"
	}
	status := strings.TrimSpace(report.Availability.Status)
	if status == "" {
		status = "unavailable"
	}
	available := report.Availability.Available && report.AttributionSummary.AttributedOps > 0 &&
		(quality == "available" || quality == "degraded")
	if report.Availability.Available && !available {
		if report.AttributionSummary.AttributedOps == 0 {
			status = "no_attributed_events"
		} else {
			status = "attribution_unavailable"
		}
	}

	projected := &EBPFVMAttribution{
		Available:         available,
		Status:            status,
		ObservedAtUTC:     report.ObservedAtUTC,
		Duration:          report.Duration,
		SourceWindow:      sourceWindow,
		CollectionMode:    report.CollectionMode,
		AttributionMethod: report.AttributionMethod,
		Quality:           quality,
		VMs:               []EBPFVMAttributionVM{},
		Caveats:           []string{},
		Privacy:           report.Privacy,
	}
	for _, caveat := range report.Caveats {
		if value := oneLine(caveat); value != "" {
			projected.Caveats = append(projected.Caveats, value)
		}
	}
	projected.Caveats = append(projected.Caveats,
		"VM attribution is experimental and must be interpreted with its quality and unattributed percentage.",
	)
	if sourceWindow != snapshot.WindowID {
		projected.Caveats = append(projected.Caveats,
			"This report was reused from an existing evidence window; compare its observed_at_utc and duration before cross-signal interpretation.",
		)
	}

	if available {
		projected.AttributedOps = report.AttributionSummary.AttributedOps
		projected.UnattributedOps = report.AttributionSummary.UnattributedOps
		projected.AttributedPercent = report.AttributionSummary.AttributedPercent
		projected.UnattributedPercent = report.Unattributed.UnattributedPercent
		projected.MatchedVMCount = report.AttributionSummary.MatchedVMCount
		projected.HostTotalOps = report.HostSummary.TotalOps
		projected.HostP95MS = report.HostSummary.LatencyP95MS
		for _, vm := range report.VMs {
			projected.VMs = append(projected.VMs, EBPFVMAttributionVM{
				Name: vm.Name, Tenant: vm.Tenant, Role: vm.Role,
				ReadOps: vm.ReadOps, WriteOps: vm.WriteOps, FlushOps: vm.FlushOps,
				DiscardOps: vm.DiscardOps, UnknownOps: vm.UnknownOps, TotalOps: vm.TotalOps,
				LatencyP95MS: vm.LatencyP95MS, AttributionQuality: vm.AttributionQuality,
			})
			if vm.Name == snapshot.Victim.Name {
				projected.VictimTotalOps += vm.TotalOps
				if vm.LatencyP95MS > projected.VictimP95MS {
					projected.VictimP95MS = vm.LatencyP95MS
				}
			}
			if vm.Name == snapshot.SelectedSuspect {
				projected.SuspectTotalOps += vm.TotalOps
				if vm.LatencyP95MS > projected.SuspectP95MS {
					projected.SuspectP95MS = vm.LatencyP95MS
				}
			}
		}
	}
	snapshot.EBPFVMAttribution = projected

	state, detail := EvidenceUnavailable, "collector status: "+status
	switch {
	case available && quality == "available":
		state, detail = EvidenceMeasured, ""
	case available && quality == "degraded":
		state, detail = EvidencePartial, "attribution quality is degraded; unmatched work remains explicit"
	}
	addSection(snapshot, "ebpf_vm_attribution", state, "typed-BTF blkcg/cgroup-ID VM attribution from "+sourceWindow, detail)
	upsertVMAttributionCorrelations(snapshot)
	finalizeQuality(snapshot)
}

// removeEvidenceSection removes evidence section from the owned collection.
func removeEvidenceSection(snapshot *ObserveSnapshot, section string) {
	qualities := snapshot.EvidenceQuality.Sections[:0]
	for _, value := range snapshot.EvidenceQuality.Sections {
		if value.Section != section {
			qualities = append(qualities, value)
		}
	}
	snapshot.EvidenceQuality.Sections = qualities
	unavailable := snapshot.UnavailableSections[:0]
	for _, value := range snapshot.UnavailableSections {
		if value.Section != section {
			unavailable = append(unavailable, value)
		}
	}
	snapshot.UnavailableSections = unavailable
}
