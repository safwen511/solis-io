package guest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/observability"
)

const source = "allowlisted SSH guest metadata"

type CollectOptions struct {
	CommandTimeout time.Duration
	WindowID       string
	ServiceRefs    []string
	Now            func() time.Time
}

func DefaultCollectOptions() CollectOptions {
	return CollectOptions{CommandTimeout: 10 * time.Second, Now: time.Now}
}

// Collect returns a partial snapshot when individual commands fail. Only an
// invalid collector configuration aborts collection.
func Collect(ctx context.Context, runner Runner, target Target, vm inventory.VM, options CollectOptions) (observability.GuestStatus, error) {
	if runner == nil {
		return observability.GuestStatus{}, errors.New("guest runner is required")
	}
	if target.VMName() != vm.Name {
		return observability.GuestStatus{}, errors.New("guest target does not match inventory VM")
	}
	if options.CommandTimeout <= 0 {
		return observability.GuestStatus{}, errors.New("guest command timeout must be positive")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	status := observability.GuestStatus{
		SchemaVersion: observability.SchemaVersion,
		ObservedAtUTC: options.Now().UTC().Format(time.RFC3339Nano),
		WindowID:      options.WindowID,
		VM:            observability.VMIdentity{Name: vm.Name, Tenant: vm.Tenant, Role: vm.Role},
		Filesystems:   []observability.FilesystemStatus{}, Network: []observability.NetworkStatus{},
		ServiceRefs:    append([]string(nil), options.ServiceRefs...),
		ListeningPorts: []observability.ListeningPort{}, ProcessPressure: []observability.ProcessPressure{},
	}
	sort.Strings(status.ServiceRefs)
	var failures []string
	successes := 0

	identityErrors := make([]string, 0, 3)
	if output, err := run(ctx, runner, target, HostnameCommand(), options.CommandTimeout); err != nil {
		identityErrors = append(identityErrors, "hostname: "+err.Error())
	} else if value, err := parseSingleLine(output, "hostname"); err != nil {
		identityErrors = append(identityErrors, "hostname: "+err.Error())
	} else {
		status.Hostname = value
		successes++
	}
	if output, err := run(ctx, runner, target, KernelReleaseCommand(), options.CommandTimeout); err != nil {
		identityErrors = append(identityErrors, "kernel: "+err.Error())
	} else if value, err := parseSingleLine(output, "kernel"); err != nil {
		identityErrors = append(identityErrors, "kernel: "+err.Error())
	} else {
		status.KernelRelease = value
		successes++
	}
	if output, err := run(ctx, runner, target, UptimeCommand(), options.CommandTimeout); err != nil {
		identityErrors = append(identityErrors, "uptime: "+err.Error())
	} else if value, err := parseUptime(output); err != nil {
		identityErrors = append(identityErrors, "uptime: "+err.Error())
	} else {
		status.UptimeSeconds = value
		successes++
	}
	status.Sections.Identity = sectionAvailability(identityErrors, 3)
	appendFailures(&failures, "identity", identityErrors)

	if output, err := run(ctx, runner, target, LoadCommand(), options.CommandTimeout); err != nil {
		status.Sections.CPU = unavailable(err)
		failures = append(failures, "cpu: "+err.Error())
	} else if value, err := parseLoad(output); err != nil {
		status.Sections.CPU = unavailable(err)
		failures = append(failures, "cpu: "+err.Error())
	} else {
		status.CPU = value
		status.Sections.CPU = measured()
		successes++
	}

	if output, err := run(ctx, runner, target, MemoryCommand(), options.CommandTimeout); err != nil {
		status.Sections.Memory = unavailable(err)
		failures = append(failures, "memory: "+err.Error())
	} else if value, err := parseMemory(output); err != nil {
		status.Sections.Memory = unavailable(err)
		failures = append(failures, "memory: "+err.Error())
	} else {
		status.Memory = value
		status.Sections.Memory = measured()
		successes++
	}

	if output, err := run(ctx, runner, target, FilesystemsCommand(), options.CommandTimeout); err != nil {
		status.Sections.Filesystems = unavailable(err)
		failures = append(failures, "filesystems: "+err.Error())
	} else if value, err := parseFilesystems(output); err != nil {
		status.Sections.Filesystems = unavailable(err)
		failures = append(failures, "filesystems: "+err.Error())
	} else {
		status.Filesystems = value
		status.Sections.Filesystems = measured()
		successes++
	}

	addresses := make(map[string]string)
	counters := make(map[string]observability.NetworkStatus)
	networkErrors := make([]string, 0, 2)
	if output, err := run(ctx, runner, target, NetworkAddressCommand(), options.CommandTimeout); err != nil {
		networkErrors = append(networkErrors, "addresses: "+err.Error())
	} else {
		addresses = parseNetworkAddresses(output)
		successes++
	}
	if output, err := run(ctx, runner, target, NetworkCountersCommand(), options.CommandTimeout); err != nil {
		networkErrors = append(networkErrors, "counters: "+err.Error())
	} else if value, err := parseNetworkCounters(output); err != nil {
		networkErrors = append(networkErrors, "counters: "+err.Error())
	} else {
		counters = value
		successes++
	}
	status.Network = mergeNetwork(addresses, counters)
	status.Sections.Network = sectionAvailability(networkErrors, 2)
	appendFailures(&failures, "network", networkErrors)

	if output, err := run(ctx, runner, target, ListeningPortsCommand(), options.CommandTimeout); err != nil {
		status.Sections.ListeningPorts = unavailable(err)
		failures = append(failures, "listening ports: "+err.Error())
	} else if value, err := parseListeningPorts(output); err != nil {
		status.Sections.ListeningPorts = unavailable(err)
		failures = append(failures, "listening ports: "+err.Error())
	} else {
		status.ListeningPorts = value
		status.Sections.ListeningPorts = measured()
		successes++
	}

	if output, err := run(ctx, runner, target, ProcessPressureCommand(), options.CommandTimeout); err != nil {
		status.Sections.ProcessPressure = unavailable(err)
		failures = append(failures, "process pressure: "+err.Error())
	} else if value, err := parseProcessPressure(output); err != nil {
		status.Sections.ProcessPressure = unavailable(err)
		failures = append(failures, "process pressure: "+err.Error())
	} else {
		status.ProcessPressure = value
		status.Sections.ProcessPressure = measured()
		successes++
	}

	if successes == 0 {
		status.Availability = unavailable(errors.New(strings.Join(failures, "; ")))
	} else {
		status.Availability = measured()
		if len(failures) > 0 {
			status.Availability.Error = "partial: " + strings.Join(failures, "; ")
		}
	}
	return status, nil
}

func run(ctx context.Context, runner Runner, target Target, command CommandSpec, timeout time.Duration) (string, error) {
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := runner.Run(commandContext, target, command)
	if err != nil {
		return "", err
	}
	return result.Output, nil
}

func measured() observability.Availability {
	return observability.Availability{Available: true, Source: source, Quality: observability.EvidenceQualityMeasured}
}

func unavailable(err error) observability.Availability {
	detail := "unavailable"
	if err != nil {
		detail = strings.Join(strings.Fields(err.Error()), " ")
	}
	return observability.Availability{Source: source, Quality: observability.EvidenceQualityUnavailable, Error: detail}
}

func sectionAvailability(failures []string, expected int) observability.Availability {
	if len(failures) == expected {
		return unavailable(errors.New(strings.Join(failures, "; ")))
	}
	availability := measured()
	if len(failures) > 0 {
		availability.Error = "partial: " + strings.Join(failures, "; ")
	}
	return availability
}

func appendFailures(destination *[]string, section string, failures []string) {
	if len(failures) > 0 {
		*destination = append(*destination, fmt.Sprintf("%s: %s", section, strings.Join(failures, ", ")))
	}
}
