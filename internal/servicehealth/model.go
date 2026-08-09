// Package servicehealth collects configured unit and endpoint health metadata
// without response bodies, payloads, or arbitrary commands.
package servicehealth

import (
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/safwen511/solis-io/internal/observability"
)

type Report struct {
	SchemaVersion string                        `json:"schema_version"`
	ObservedAtUTC string                        `json:"observed_at_utc"`
	WindowID      string                        `json:"window_id"`
	VM            observability.VMIdentity      `json:"vm"`
	Availability  observability.Availability    `json:"availability"`
	Services      []observability.ServiceStatus `json:"services"`
	Privacy       observability.PrivacyFlags    `json:"privacy"`
}

func WriteJSON(dst io.Writer, report Report) error {
	if !privacySafe(report.Privacy) {
		return errors.New("service status cannot record payload, secret, environment, process-argument, guest-file, query-text, or table-data collection")
	}
	if report.SchemaVersion == "" {
		report.SchemaVersion = observability.SchemaVersion
	}
	report.Services = append([]observability.ServiceStatus(nil), report.Services...)
	if report.Services == nil {
		report.Services = []observability.ServiceStatus{}
	}
	for index := range report.Services {
		service := &report.Services[index]
		if !privacySafe(service.Privacy) {
			return errors.New("service status cannot record payload, secret, environment, process-argument, guest-file, query-text, or table-data collection")
		}
		if service.SchemaVersion == "" {
			service.SchemaVersion = observability.SchemaVersion
		}
		service.Units = append([]observability.SystemdUnitStatus(nil), service.Units...)
		service.ListeningPorts = append([]observability.ListeningPort(nil), service.ListeningPorts...)
		service.HealthChecks = append([]observability.AppHealthStatus(nil), service.HealthChecks...)
		if service.Units == nil {
			service.Units = []observability.SystemdUnitStatus{}
		}
		if service.ListeningPorts == nil {
			service.ListeningPorts = []observability.ListeningPort{}
		}
		if service.HealthChecks == nil {
			service.HealthChecks = []observability.AppHealthStatus{}
		}
		for _, health := range service.HealthChecks {
			if health.BodyCollected {
				return errors.New("service status cannot record response body collection")
			}
		}
		sort.Slice(service.Units, func(i, j int) bool { return service.Units[i].ID < service.Units[j].ID })
		sort.Slice(service.ListeningPorts, func(i, j int) bool {
			left, right := service.ListeningPorts[i], service.ListeningPorts[j]
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
		sort.Slice(service.HealthChecks, func(i, j int) bool { return service.HealthChecks[i].Name < service.HealthChecks[j].Name })
	}
	sort.Slice(report.Services, func(i, j int) bool { return report.Services[i].Name < report.Services[j].Name })
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func privacySafe(flags observability.PrivacyFlags) bool {
	return !flags.ProcessArgumentsCollected && !flags.EnvironmentCollected &&
		!flags.GuestFilesCollected && !flags.QueryTextCollected && !flags.TableDataCollected &&
		!flags.RequestBodyCollected && !flags.ResponseBodyCollected && !flags.SecretsCollected
}
