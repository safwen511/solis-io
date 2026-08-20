package servicehealth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	solisconfig "github.com/safwen511/solis-io/internal/config"
	"github.com/safwen511/solis-io/internal/guest"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/observability"
)

const source = "configured allowlisted service metadata"

type Options struct {
	CommandTimeout time.Duration
	HealthTimeout  time.Duration
	WindowID       string
	Now            func() time.Time
	HTTPClient     *http.Client
}

// DefaultOptions returns the default options.
func DefaultOptions() Options {
	return Options{CommandTimeout: 10 * time.Second, HealthTimeout: 5 * time.Second, Now: time.Now}
}

// Collect collects bounded evidence from the configured source and propagates source failures.
func Collect(ctx context.Context, runner guest.Runner, target guest.Target, vm inventory.VM, services []solisconfig.ServiceObservabilityConfig, options Options) (Report, error) {
	if runner == nil {
		return Report{}, errors.New("guest runner is required")
	}
	if target.VMName() != vm.Name {
		return Report{}, errors.New("guest target does not match inventory VM")
	}
	if options.CommandTimeout <= 0 || options.HealthTimeout <= 0 {
		return Report{}, errors.New("service command and health timeouts must be positive")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	report := Report{
		SchemaVersion: observability.SchemaVersion,
		ObservedAtUTC: options.Now().UTC().Format(time.RFC3339Nano),
		WindowID:      options.WindowID,
		VM:            observability.VMIdentity{Name: vm.Name, Tenant: vm.Tenant, Role: vm.Role},
		Services:      []observability.ServiceStatus{},
	}
	if len(services) == 0 {
		report.Availability = unavailable(errors.New("no services configured for VM"))
		return report, nil
	}

	ports, portAvailability := collectPorts(ctx, runner, target, options.CommandTimeout)
	for _, configured := range services {
		if configured.VM != vm.Name {
			continue
		}
		service := observability.ServiceStatus{
			SchemaVersion: observability.SchemaVersion, ObservedAtUTC: report.ObservedAtUTC,
			WindowID: options.WindowID, VM: report.VM, Name: serviceIdentity(configured), Units: []observability.SystemdUnitStatus{},
			ListeningPorts: append([]observability.ListeningPort(nil), ports...), PortAvailability: portAvailability,
			HealthChecks: []observability.AppHealthStatus{},
		}
		var failures []string
		if !portAvailability.Available {
			failures = append(failures, "listening ports: "+portAvailability.Error)
		}
		for _, unit := range configured.Units {
			command, err := guest.SystemdUnitCommand(unit)
			if err != nil {
				service.Units = append(service.Units, observability.SystemdUnitStatus{ID: unit, Availability: unavailable(err)})
				failures = append(failures, unit+": "+err.Error())
				continue
			}
			commandContext, cancel := context.WithTimeout(ctx, options.CommandTimeout)
			result, runErr := runner.Run(commandContext, target, command)
			cancel()
			if runErr != nil {
				service.Units = append(service.Units, observability.SystemdUnitStatus{ID: unit, Availability: unavailable(runErr)})
				failures = append(failures, unit+": "+runErr.Error())
				continue
			}
			status, parseErr := guest.ParseSystemdUnit(result.Output)
			if parseErr == nil && status.ID != unit {
				parseErr = errors.New("systemd output unit does not match configured unit")
			}
			if parseErr != nil {
				status.ID = unit
				status.Availability = unavailable(parseErr)
				failures = append(failures, unit+": "+parseErr.Error())
			} else {
				status.Availability = measured()
			}
			service.Units = append(service.Units, status)
		}
		for _, health := range configured.HealthChecks {
			status := checkHealth(ctx, target.Host(), health, options)
			service.HealthChecks = append(service.HealthChecks, status)
			if !status.Availability.Available {
				failures = append(failures, health.Name+": "+status.Availability.Error)
			}
		}
		sort.Slice(service.Units, func(i, j int) bool { return service.Units[i].ID < service.Units[j].ID })
		sort.Slice(service.HealthChecks, func(i, j int) bool { return service.HealthChecks[i].Name < service.HealthChecks[j].Name })
		service.Availability = measured()
		if len(failures) > 0 {
			if len(failures) == len(configured.Units)+len(configured.HealthChecks)+1 {
				service.Availability = unavailable(errors.New(strings.Join(failures, "; ")))
			} else {
				service.Availability.Error = "partial: " + strings.Join(failures, "; ")
			}
		}
		report.Services = append(report.Services, service)
	}
	if len(report.Services) == 0 {
		report.Availability = unavailable(errors.New("no services configured for VM"))
	} else {
		report.Availability = measured()
		for _, service := range report.Services {
			if !service.Availability.Available || service.Availability.Error != "" {
				report.Availability.Error = "one or more service sections are partial or unavailable"
				break
			}
		}
	}
	return report, nil
}

// collectPorts collects ports from the configured evidence sources.
func collectPorts(ctx context.Context, runner guest.Runner, target guest.Target, timeout time.Duration) ([]observability.ListeningPort, observability.Availability) {
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := runner.Run(commandContext, target, guest.ListeningPortsCommand())
	if err != nil {
		return []observability.ListeningPort{}, unavailable(err)
	}
	ports, err := guest.ParseListeningPorts(result.Output)
	if err != nil {
		return []observability.ListeningPort{}, unavailable(err)
	}
	return ports, measured()
}

// checkHealth checks health and reports any failed requirement.
func checkHealth(ctx context.Context, host string, health solisconfig.HealthCheckConfig, options Options) observability.AppHealthStatus {
	status := observability.AppHealthStatus{Name: health.Name, Path: health.Path, Checked: true, BodyCollected: false}
	endpoint := url.URL{Scheme: "http", Host: net.JoinHostPort(host, fmt.Sprintf("%d", health.Port)), Path: health.Path}
	requestContext, cancel := context.WithTimeout(ctx, options.HealthTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		status.Availability = unavailable(err)
		status.Error = status.Availability.Error
		return status
	}
	client := httpClient(options)
	started := time.Now()
	response, err := client.Do(request)
	status.LatencyMS = float64(time.Since(started).Microseconds()) / 1000
	if err != nil {
		status.Availability = unavailable(sanitizeHTTPError(err))
		status.Error = status.Availability.Error
		return status
	}
	// Never read the body. Closing it immediately prevents payload collection.
	_ = response.Body.Close()
	status.StatusCode = response.StatusCode
	status.Availability = measured()
	return status
}

// httpClient builds http client from validated inputs.
func httpClient(options Options) *http.Client {
	base := options.HTTPClient
	client := &http.Client{Timeout: options.HealthTimeout}
	if base != nil {
		*client = *base
		client.Timeout = options.HealthTimeout
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

// sanitizeHTTPError sanitizes http error for safe output.
func sanitizeHTTPError(err error) error {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		if errors.Is(urlError.Err, context.DeadlineExceeded) {
			return errors.New("health check timed out")
		}
		return errors.New("health check request failed")
	}
	return errors.New("health check request failed")
}

// serviceIdentity builds the stable service identity used to correlate configured health checks.
func serviceIdentity(service solisconfig.ServiceObservabilityConfig) string {
	if strings.TrimSpace(service.ID) != "" {
		return strings.TrimSpace(service.ID)
	}
	return service.VM
}

// measured constructs availability metadata for a successfully measured value.
func measured() observability.Availability {
	return observability.Availability{Available: true, Source: source, Quality: observability.EvidenceQualityMeasured}
}

// unavailable constructs unavailable metadata with a bounded reason.
func unavailable(err error) observability.Availability {
	detail := "unavailable"
	if err != nil {
		detail = strings.Join(strings.Fields(err.Error()), " ")
	}
	return observability.Availability{Source: source, Quality: observability.EvidenceQualityUnavailable, Error: detail}
}
