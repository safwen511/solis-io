package observability

import (
	"encoding/json"
	"errors"
	"io"
	"sort"
)

// WriteGuestStatus writes one deterministic, privacy-safe JSON document.
func WriteGuestStatus(dst io.Writer, status GuestStatus) error {
	if err := validatePrivacy(status.Privacy); err != nil {
		return err
	}
	normalizeGuestStatus(&status)
	return writeJSON(dst, status)
}

// WriteDBStatus writes one deterministic, privacy-safe JSON document.
func WriteDBStatus(dst io.Writer, status DBStatus) error {
	if err := validatePrivacy(status.Privacy); err != nil {
		return err
	}
	if status.PGStatStatements.QueryTextCollected {
		return errors.New("observability database status cannot record query text collection")
	}
	normalizeDBStatus(&status)
	return writeJSON(dst, status)
}

// WriteServiceStatus writes one deterministic, privacy-safe JSON document.
func WriteServiceStatus(dst io.Writer, status ServiceStatus) error {
	if err := validatePrivacy(status.Privacy); err != nil {
		return err
	}
	for _, health := range status.HealthChecks {
		if health.BodyCollected {
			return errors.New("observability service status cannot record response body collection")
		}
	}
	normalizeServiceStatus(&status)
	return writeJSON(dst, status)
}

// WriteIncidentTimeline writes one deterministic, privacy-safe JSON document.
func WriteIncidentTimeline(dst io.Writer, timeline IncidentTimeline) error {
	if err := validatePrivacy(timeline.Privacy); err != nil {
		return err
	}
	normalizeIncidentTimeline(&timeline)
	return writeJSON(dst, timeline)
}

// writeJSON renders JSON in the package's stable operator-facing format.
func writeJSON(dst io.Writer, value any) error {
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// validatePrivacy validates privacy against its required contract.
func validatePrivacy(privacy PrivacyFlags) error {
	if privacy.ProcessArgumentsCollected || privacy.EnvironmentCollected ||
		privacy.GuestFilesCollected || privacy.QueryTextCollected ||
		privacy.TableDataCollected || privacy.RequestBodyCollected ||
		privacy.ResponseBodyCollected || privacy.SecretsCollected {
		return errors.New("observability models cannot record payload, secret, environment, process-argument, guest-file, query-text, or table-data collection")
	}
	return nil
}

// normalizeGuestStatus normalizes guest status into its canonical representation.
func normalizeGuestStatus(status *GuestStatus) {
	status.SchemaVersion = normalizedSchema(status.SchemaVersion)
	status.Filesystems = append([]FilesystemStatus(nil), status.Filesystems...)
	status.Network = append([]NetworkStatus(nil), status.Network...)
	status.ServiceRefs = append([]string(nil), status.ServiceRefs...)
	status.ListeningPorts = append([]ListeningPort(nil), status.ListeningPorts...)
	status.ProcessPressure = append([]ProcessPressure(nil), status.ProcessPressure...)
	if status.Filesystems == nil {
		status.Filesystems = []FilesystemStatus{}
	}
	if status.Network == nil {
		status.Network = []NetworkStatus{}
	}
	if status.ServiceRefs == nil {
		status.ServiceRefs = []string{}
	}
	if status.ListeningPorts == nil {
		status.ListeningPorts = []ListeningPort{}
	}
	if status.ProcessPressure == nil {
		status.ProcessPressure = []ProcessPressure{}
	}
	sort.Slice(status.Filesystems, func(i, j int) bool {
		return status.Filesystems[i].Mountpoint < status.Filesystems[j].Mountpoint
	})
	sort.Slice(status.Network, func(i, j int) bool {
		return status.Network[i].Interface < status.Network[j].Interface
	})
	sort.Strings(status.ServiceRefs)
	sortListeningPorts(status.ListeningPorts)
	sort.Slice(status.ProcessPressure, func(i, j int) bool {
		if status.ProcessPressure[i].PID == status.ProcessPressure[j].PID {
			return status.ProcessPressure[i].Command < status.ProcessPressure[j].Command
		}
		return status.ProcessPressure[i].PID < status.ProcessPressure[j].PID
	})
}

// normalizeDBStatus normalizes db status into its canonical representation.
func normalizeDBStatus(status *DBStatus) {
	status.SchemaVersion = normalizedSchema(status.SchemaVersion)
	status.Databases = append([]DatabaseCounters(nil), status.Databases...)
	status.Activity.WaitEvents = append([]WaitEventCount(nil), status.Activity.WaitEvents...)
	status.Extensions = append([]string(nil), status.Extensions...)
	status.PGStatStatements.Entries = append([]StatementStatistics(nil), status.PGStatStatements.Entries...)
	if status.Databases == nil {
		status.Databases = []DatabaseCounters{}
	}
	if status.Activity.WaitEvents == nil {
		status.Activity.WaitEvents = []WaitEventCount{}
	}
	if status.Extensions == nil {
		status.Extensions = []string{}
	}
	if status.PGStatStatements.Entries == nil {
		status.PGStatStatements.Entries = []StatementStatistics{}
	}
	sort.Slice(status.Databases, func(i, j int) bool {
		return status.Databases[i].Name < status.Databases[j].Name
	})
	sort.Slice(status.Activity.WaitEvents, func(i, j int) bool {
		left, right := status.Activity.WaitEvents[i], status.Activity.WaitEvents[j]
		if left.Type != right.Type {
			return left.Type < right.Type
		}
		return left.Event < right.Event
	})
	sort.Strings(status.Extensions)
	sort.Slice(status.PGStatStatements.Entries, func(i, j int) bool {
		return status.PGStatStatements.Entries[i].QueryID < status.PGStatStatements.Entries[j].QueryID
	})
}

// normalizeServiceStatus normalizes service status into its canonical representation.
func normalizeServiceStatus(status *ServiceStatus) {
	status.SchemaVersion = normalizedSchema(status.SchemaVersion)
	status.Units = append([]SystemdUnitStatus(nil), status.Units...)
	status.ListeningPorts = append([]ListeningPort(nil), status.ListeningPorts...)
	status.HealthChecks = append([]AppHealthStatus(nil), status.HealthChecks...)
	if status.Units == nil {
		status.Units = []SystemdUnitStatus{}
	}
	if status.ListeningPorts == nil {
		status.ListeningPorts = []ListeningPort{}
	}
	if status.HealthChecks == nil {
		status.HealthChecks = []AppHealthStatus{}
	}
	sort.Slice(status.Units, func(i, j int) bool { return status.Units[i].ID < status.Units[j].ID })
	sortListeningPorts(status.ListeningPorts)
	sort.Slice(status.HealthChecks, func(i, j int) bool {
		return status.HealthChecks[i].Name < status.HealthChecks[j].Name
	})
}

// sortListeningPorts sorts listening ports into stable output order.
func sortListeningPorts(ports []ListeningPort) {
	sort.Slice(ports, func(i, j int) bool {
		left, right := ports[i], ports[j]
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		return left.Process < right.Process
	})
}

// normalizeIncidentTimeline normalizes incident timeline into its canonical representation.
func normalizeIncidentTimeline(timeline *IncidentTimeline) {
	timeline.SchemaVersion = normalizedSchema(timeline.SchemaVersion)
	timeline.Events = append([]TimelineEvent(nil), timeline.Events...)
	timeline.Verdict.Caveats = append([]string(nil), timeline.Verdict.Caveats...)
	timeline.EvidenceRefs = append([]string(nil), timeline.EvidenceRefs...)
	if timeline.Events == nil {
		timeline.Events = []TimelineEvent{}
	}
	if timeline.Verdict.Caveats == nil {
		timeline.Verdict.Caveats = []string{}
	}
	if timeline.EvidenceRefs == nil {
		timeline.EvidenceRefs = []string{}
	}
	sort.Slice(timeline.Events, func(i, j int) bool {
		left, right := timeline.Events[i], timeline.Events[j]
		if left.OffsetMS != right.OffsetMS {
			return left.OffsetMS < right.OffsetMS
		}
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		if left.Scope != right.Scope {
			return left.Scope < right.Scope
		}
		return left.Metric < right.Metric
	})
	sort.Strings(timeline.Verdict.Caveats)
	sort.Strings(timeline.EvidenceRefs)
}

// normalizedSchema normalizes schema into its canonical representation.
func normalizedSchema(schema string) string {
	if schema == "" {
		return SchemaVersion
	}
	return schema
}
