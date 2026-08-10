package observe

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/safwen511/solis-io/internal/observability"
	"github.com/safwen511/solis-io/internal/servicehealth"
	statusview "github.com/safwen511/solis-io/internal/status"
)

// MarshalJSON returns one deterministic compact JSON document suitable for
// JSON Lines output. It applies the same privacy validation as WriteJSON.
func MarshalJSON(snapshot ObserveSnapshot) ([]byte, error) {
	if err := validateSnapshotPrivacy(snapshot); err != nil {
		return nil, err
	}
	normalizeSnapshot(&snapshot)
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(snapshot); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}

func WriteJSON(dst io.Writer, snapshot ObserveSnapshot) error {
	if err := validateSnapshotPrivacy(snapshot); err != nil {
		return err
	}
	normalizeSnapshot(&snapshot)
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(snapshot)
}

func validateSnapshotPrivacy(snapshot ObserveSnapshot) error {
	flags := []observability.PrivacyFlags{snapshot.Privacy}
	if snapshot.HostStatus != nil {
		flags = append(flags, snapshot.HostStatus.Privacy)
	}
	if snapshot.EBPFVMAttribution != nil {
		flags = append(flags, snapshot.EBPFVMAttribution.Privacy)
	}
	if snapshot.VictimGuestStatus != nil {
		flags = append(flags, snapshot.VictimGuestStatus.Privacy)
	}
	if snapshot.SuspectGuestStatus != nil {
		flags = append(flags, snapshot.SuspectGuestStatus.Privacy)
	}
	if snapshot.VictimDBStatus != nil {
		flags = append(flags, snapshot.VictimDBStatus.Privacy)
		if snapshot.VictimDBStatus.PGStatStatements.QueryTextCollected {
			return errors.New("observe snapshot cannot contain PostgreSQL query text")
		}
	}
	if snapshot.SuspectDBStatus != nil {
		flags = append(flags, snapshot.SuspectDBStatus.Privacy)
		if snapshot.SuspectDBStatus.PGStatStatements.QueryTextCollected {
			return errors.New("observe snapshot cannot contain PostgreSQL query text")
		}
	}
	for _, report := range []*servicehealth.Report{snapshot.VictimServiceStatus, snapshot.SuspectServiceStatus} {
		if report == nil {
			continue
		}
		flags = append(flags, report.Privacy)
		for _, service := range report.Services {
			flags = append(flags, service.Privacy)
			for _, health := range service.HealthChecks {
				if health.BodyCollected {
					return errors.New("observe snapshot cannot contain HTTP response bodies")
				}
			}
		}
	}
	for _, value := range flags {
		if !privacySafe(value) {
			return errors.New("observe snapshot cannot contain payload, secret, environment, process-argument, guest-file, query-text, or table-data collection")
		}
	}
	return nil
}

func normalizeSnapshot(snapshot *ObserveSnapshot) {
	if snapshot.SchemaVersion == "" {
		snapshot.SchemaVersion = SchemaVersion
	}
	if snapshot.SelectedSuspect == "" {
		snapshot.SelectedSuspect = "-"
	}
	snapshot.VMStatus.VMs = append([]statusview.VMStatus(nil), snapshot.VMStatus.VMs...)
	if snapshot.VMStatus.VMs == nil {
		snapshot.VMStatus.VMs = []statusview.VMStatus{}
	}
	sort.Slice(snapshot.VMStatus.VMs, func(i, j int) bool { return snapshot.VMStatus.VMs[i].Name < snapshot.VMStatus.VMs[j].Name })
	snapshot.StorageTopology.Targets = append([]StorageTarget(nil), snapshot.StorageTopology.Targets...)
	snapshot.QEMUEvidence.VMs = append([]QEMUVM(nil), snapshot.QEMUEvidence.VMs...)
	snapshot.Discovery.Candidates = append([]DiscoveryCandidate(nil), snapshot.Discovery.Candidates...)
	snapshot.Correlations = append([]Correlation(nil), snapshot.Correlations...)
	snapshot.EvidenceQuality.Sections = append([]SectionQuality(nil), snapshot.EvidenceQuality.Sections...)
	snapshot.UnavailableSections = append([]UnavailableSection(nil), snapshot.UnavailableSections...)
	snapshot.Caveats = append([]string(nil), snapshot.Caveats...)
	if snapshot.EBPFVMAttribution != nil {
		snapshot.EBPFVMAttribution.VMs = append([]EBPFVMAttributionVM(nil), snapshot.EBPFVMAttribution.VMs...)
		snapshot.EBPFVMAttribution.Caveats = append([]string(nil), snapshot.EBPFVMAttribution.Caveats...)
		if snapshot.EBPFVMAttribution.VMs == nil {
			snapshot.EBPFVMAttribution.VMs = []EBPFVMAttributionVM{}
		}
		if snapshot.EBPFVMAttribution.Caveats == nil {
			snapshot.EBPFVMAttribution.Caveats = []string{}
		}
		sort.Slice(snapshot.EBPFVMAttribution.VMs, func(i, j int) bool {
			return snapshot.EBPFVMAttribution.VMs[i].Name < snapshot.EBPFVMAttribution.VMs[j].Name
		})
		sort.Strings(snapshot.EBPFVMAttribution.Caveats)
	}
	if snapshot.StorageTopology.Targets == nil {
		snapshot.StorageTopology.Targets = []StorageTarget{}
	}
	if snapshot.QEMUEvidence.VMs == nil {
		snapshot.QEMUEvidence.VMs = []QEMUVM{}
	}
	if snapshot.Discovery.Candidates == nil {
		snapshot.Discovery.Candidates = []DiscoveryCandidate{}
	}
	if snapshot.Correlations == nil {
		snapshot.Correlations = []Correlation{}
	}
	if snapshot.EvidenceQuality.Sections == nil {
		snapshot.EvidenceQuality.Sections = []SectionQuality{}
	}
	if snapshot.UnavailableSections == nil {
		snapshot.UnavailableSections = []UnavailableSection{}
	}
	if snapshot.Caveats == nil {
		snapshot.Caveats = []string{}
	}
	sort.Slice(snapshot.StorageTopology.Targets, func(i, j int) bool {
		if snapshot.StorageTopology.Targets[i].TargetType != snapshot.StorageTopology.Targets[j].TargetType {
			return snapshot.StorageTopology.Targets[i].TargetType < snapshot.StorageTopology.Targets[j].TargetType
		}
		return snapshot.StorageTopology.Targets[i].VM < snapshot.StorageTopology.Targets[j].VM
	})
	sort.Slice(snapshot.QEMUEvidence.VMs, func(i, j int) bool { return snapshot.QEMUEvidence.VMs[i].VM < snapshot.QEMUEvidence.VMs[j].VM })
	sort.Slice(snapshot.Discovery.Candidates, func(i, j int) bool {
		return snapshot.Discovery.Candidates[i].Name < snapshot.Discovery.Candidates[j].Name
	})
	sort.Slice(snapshot.Correlations, func(i, j int) bool { return snapshot.Correlations[i].Name < snapshot.Correlations[j].Name })
	for index := range snapshot.Correlations {
		snapshot.Correlations[index].EvidenceRefs = append([]string(nil), snapshot.Correlations[index].EvidenceRefs...)
		if snapshot.Correlations[index].EvidenceRefs == nil {
			snapshot.Correlations[index].EvidenceRefs = []string{}
		}
		sort.Strings(snapshot.Correlations[index].EvidenceRefs)
	}
	sort.Slice(snapshot.EvidenceQuality.Sections, func(i, j int) bool {
		return snapshot.EvidenceQuality.Sections[i].Section < snapshot.EvidenceQuality.Sections[j].Section
	})
	sort.Slice(snapshot.UnavailableSections, func(i, j int) bool {
		return snapshot.UnavailableSections[i].Section < snapshot.UnavailableSections[j].Section
	})
	sort.Strings(snapshot.Caveats)
	normalizeGuest(snapshot.VictimGuestStatus)
	normalizeGuest(snapshot.SuspectGuestStatus)
	normalizeService(snapshot.VictimServiceStatus)
	normalizeService(snapshot.SuspectServiceStatus)
	normalizeDB(snapshot.VictimDBStatus)
	normalizeDB(snapshot.SuspectDBStatus)
}

func normalizeGuest(status *observability.GuestStatus) {
	if status == nil {
		return
	}
	sort.Slice(status.Filesystems, func(i, j int) bool { return status.Filesystems[i].Mountpoint < status.Filesystems[j].Mountpoint })
	sort.Slice(status.Network, func(i, j int) bool { return status.Network[i].Interface < status.Network[j].Interface })
	sort.Strings(status.ServiceRefs)
	sort.Slice(status.ListeningPorts, func(i, j int) bool {
		if status.ListeningPorts[i].Protocol != status.ListeningPorts[j].Protocol {
			return status.ListeningPorts[i].Protocol < status.ListeningPorts[j].Protocol
		}
		if status.ListeningPorts[i].Address != status.ListeningPorts[j].Address {
			return status.ListeningPorts[i].Address < status.ListeningPorts[j].Address
		}
		return status.ListeningPorts[i].Port < status.ListeningPorts[j].Port
	})
	sort.Slice(status.ProcessPressure, func(i, j int) bool { return status.ProcessPressure[i].PID < status.ProcessPressure[j].PID })
}

func normalizeService(report *servicehealth.Report) {
	if report == nil {
		return
	}
	sort.Slice(report.Services, func(i, j int) bool { return report.Services[i].Name < report.Services[j].Name })
	for index := range report.Services {
		service := &report.Services[index]
		sort.Slice(service.Units, func(i, j int) bool { return service.Units[i].ID < service.Units[j].ID })
		sort.Slice(service.ListeningPorts, func(i, j int) bool {
			if service.ListeningPorts[i].Protocol != service.ListeningPorts[j].Protocol {
				return service.ListeningPorts[i].Protocol < service.ListeningPorts[j].Protocol
			}
			if service.ListeningPorts[i].Address != service.ListeningPorts[j].Address {
				return service.ListeningPorts[i].Address < service.ListeningPorts[j].Address
			}
			return service.ListeningPorts[i].Port < service.ListeningPorts[j].Port
		})
		sort.Slice(service.HealthChecks, func(i, j int) bool { return service.HealthChecks[i].Name < service.HealthChecks[j].Name })
	}
}

func normalizeDB(status *observability.DBStatus) {
	if status == nil {
		return
	}
	sort.Slice(status.Databases, func(i, j int) bool { return status.Databases[i].Name < status.Databases[j].Name })
	sort.Slice(status.Activity.WaitEvents, func(i, j int) bool {
		if status.Activity.WaitEvents[i].Type != status.Activity.WaitEvents[j].Type {
			return status.Activity.WaitEvents[i].Type < status.Activity.WaitEvents[j].Type
		}
		return status.Activity.WaitEvents[i].Event < status.Activity.WaitEvents[j].Event
	})
	sort.Strings(status.Extensions)
	sort.Slice(status.PGStatStatements.Entries, func(i, j int) bool {
		return status.PGStatStatements.Entries[i].QueryID < status.PGStatStatements.Entries[j].QueryID
	})
}
