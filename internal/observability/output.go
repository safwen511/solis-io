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
	normalizeDBStatus(&status)
	return writeJSON(dst, status)
}

// WriteServiceStatus writes one deterministic, privacy-safe JSON document.
func WriteServiceStatus(dst io.Writer, status ServiceStatus) error {
	if err := validatePrivacy(status.Privacy); err != nil {
		return err
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

func writeJSON(dst io.Writer, value any) error {
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func validatePrivacy(privacy PrivacyFlags) error {
	if privacy.ProcessArgumentsCollected || privacy.EnvironmentCollected ||
		privacy.GuestFilesCollected || privacy.QueryTextCollected ||
		privacy.TableDataCollected || privacy.RequestBodyCollected ||
		privacy.ResponseBodyCollected || privacy.SecretsCollected {
		return errors.New("observability models cannot record payload, secret, environment, process-argument, guest-file, query-text, or table-data collection")
	}
	return nil
}

func normalizeGuestStatus(status *GuestStatus) {
	status.SchemaVersion = normalizedSchema(status.SchemaVersion)
	status.Filesystems = append([]FilesystemStatus(nil), status.Filesystems...)
	status.Network = append([]NetworkStatus(nil), status.Network...)
	status.ProcessPressure = append([]ProcessPressure(nil), status.ProcessPressure...)
	if status.Filesystems == nil {
		status.Filesystems = []FilesystemStatus{}
	}
	if status.Network == nil {
		status.Network = []NetworkStatus{}
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
	sort.Slice(status.ProcessPressure, func(i, j int) bool {
		if status.ProcessPressure[i].PID == status.ProcessPressure[j].PID {
			return status.ProcessPressure[i].Command < status.ProcessPressure[j].Command
		}
		return status.ProcessPressure[i].PID < status.ProcessPressure[j].PID
	})
}

func normalizeDBStatus(status *DBStatus) {
	status.SchemaVersion = normalizedSchema(status.SchemaVersion)
	status.Databases = append([]DatabaseCounters(nil), status.Databases...)
	status.Activity.WaitEvents = append([]string(nil), status.Activity.WaitEvents...)
	status.Extensions = append([]string(nil), status.Extensions...)
	status.StatementStatistics = append([]StatementStatistics(nil), status.StatementStatistics...)
	if status.Databases == nil {
		status.Databases = []DatabaseCounters{}
	}
	if status.Activity.WaitEvents == nil {
		status.Activity.WaitEvents = []string{}
	}
	if status.Extensions == nil {
		status.Extensions = []string{}
	}
	if status.StatementStatistics == nil {
		status.StatementStatistics = []StatementStatistics{}
	}
	sort.Slice(status.Databases, func(i, j int) bool {
		return status.Databases[i].Name < status.Databases[j].Name
	})
	sort.Strings(status.Activity.WaitEvents)
	sort.Strings(status.Extensions)
	sort.Slice(status.StatementStatistics, func(i, j int) bool {
		return status.StatementStatistics[i].QueryID < status.StatementStatistics[j].QueryID
	})
}

func normalizeServiceStatus(status *ServiceStatus) {
	status.SchemaVersion = normalizedSchema(status.SchemaVersion)
	status.ListeningPorts = append([]ListeningPort(nil), status.ListeningPorts...)
	status.HealthChecks = append([]AppHealthStatus(nil), status.HealthChecks...)
	if status.ListeningPorts == nil {
		status.ListeningPorts = []ListeningPort{}
	}
	if status.HealthChecks == nil {
		status.HealthChecks = []AppHealthStatus{}
	}
	sort.Slice(status.ListeningPorts, func(i, j int) bool {
		left, right := status.ListeningPorts[i], status.ListeningPorts[j]
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		return left.Port < right.Port
	})
	sort.Slice(status.HealthChecks, func(i, j int) bool {
		return status.HealthChecks[i].Name < status.HealthChecks[j].Name
	})
}

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

func normalizedSchema(schema string) string {
	if schema == "" {
		return SchemaVersion
	}
	return schema
}
