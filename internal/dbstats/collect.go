package dbstats

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	solisconfig "github.com/safwen511/solis-io/internal/config"
	"github.com/safwen511/solis-io/internal/guest"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/observability"
)

const source = "fixed read-only PostgreSQL statistics queries"

type Options struct {
	CommandTimeout time.Duration
	WindowID       string
	Now            func() time.Time
}

// DefaultOptions returns the default options.
func DefaultOptions() Options { return Options{CommandTimeout: 10 * time.Second, Now: time.Now} }

// Collect collects bounded evidence from the configured source and propagates source failures.
func Collect(ctx context.Context, runner guest.Runner, target guest.Target, vm inventory.VM, database solisconfig.DatabaseObservabilityConfig, options Options) (observability.DBStatus, error) {
	if runner == nil {
		return observability.DBStatus{}, errors.New("database runner is required")
	}
	if target.VMName() != vm.Name {
		return observability.DBStatus{}, errors.New("database target does not match inventory VM")
	}
	if strings.TrimSpace(database.VM) != vm.Name {
		return observability.DBStatus{}, errors.New("database configuration does not match inventory VM")
	}
	if strings.TrimSpace(database.Kind) != "postgresql" {
		return observability.DBStatus{}, fmt.Errorf("unsupported database kind %q; supported kind is postgresql", database.Kind)
	}
	if options.CommandTimeout <= 0 {
		return observability.DBStatus{}, errors.New("database command timeout must be positive")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	status := observability.DBStatus{
		SchemaVersion: observability.SchemaVersion, ObservedAtUTC: options.Now().UTC().Format(time.RFC3339Nano), WindowID: options.WindowID,
		VM: observability.VMIdentity{Name: vm.Name, Tenant: vm.Tenant, Role: vm.Role}, Engine: "postgresql",
		Databases: []observability.DatabaseCounters{}, Activity: observability.DatabaseActivity{WaitEvents: []observability.WaitEventCount{}},
		Extensions: []string{}, PGStatStatements: observability.PGStatStatementsStatus{Entries: []observability.StatementStatistics{}},
	}
	commands, err := fixedCommands(database.Database)
	if err != nil {
		return observability.DBStatus{}, err
	}
	var failures []string
	successes := 0

	if output, err := run(ctx, runner, target, commands.version, options.CommandTimeout); err != nil {
		status.Sections.Version = unavailable(err)
		failures = append(failures, "version: "+err.Error())
	} else if value, err := parseVersion(output); err != nil {
		status.Sections.Version = unavailable(err)
		failures = append(failures, "version: "+err.Error())
	} else {
		status.Version = value
		status.Sections.Version = measured()
		successes++
	}

	if output, err := run(ctx, runner, target, commands.databases, options.CommandTimeout); err != nil {
		status.Sections.Databases = unavailable(err)
		failures = append(failures, "databases: "+err.Error())
	} else if value, err := parseDatabaseCounters(output); err != nil {
		status.Sections.Databases = unavailable(err)
		failures = append(failures, "databases: "+err.Error())
	} else {
		status.Databases = value
		status.Sections.Databases = measured()
		successes++
	}

	if output, err := run(ctx, runner, target, commands.activity, options.CommandTimeout); err != nil {
		status.Sections.Activity = unavailable(err)
		failures = append(failures, "activity: "+err.Error())
	} else if value, err := parseActivity(output); err != nil {
		status.Sections.Activity = unavailable(err)
		failures = append(failures, "activity: "+err.Error())
	} else {
		status.Activity = value
		status.Sections.Activity = measured()
		successes++
	}

	extensionsAvailable := false
	if output, err := run(ctx, runner, target, commands.extensions, options.CommandTimeout); err != nil {
		status.Sections.Extensions = unavailable(err)
		failures = append(failures, "extensions: "+err.Error())
	} else if value, err := parseExtensions(output); err != nil {
		status.Sections.Extensions = unavailable(err)
		failures = append(failures, "extensions: "+err.Error())
	} else {
		status.Extensions = value
		status.Sections.Extensions = measured()
		extensionsAvailable = true
		successes++
	}

	collectStatements(ctx, runner, target, database, commands.statements, options.CommandTimeout, extensionsAvailable, &status, &failures, &successes)
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

type commandSet struct{ version, databases, activity, extensions, statements guest.CommandSpec }

// fixedCommands builds fixed commands and returns an error when validation or source access fails.
func fixedCommands(database string) (commandSet, error) {
	var result commandSet
	constructors := []struct {
		destination *guest.CommandSpec
		create      func(string) (guest.CommandSpec, error)
	}{
		{&result.version, guest.PostgreSQLVersionCommand}, {&result.databases, guest.PostgreSQLDatabasesCommand},
		{&result.activity, guest.PostgreSQLActivityCommand}, {&result.extensions, guest.PostgreSQLExtensionsCommand},
		{&result.statements, guest.PostgreSQLStatementsCommand},
	}
	for _, constructor := range constructors {
		command, err := constructor.create(database)
		if err != nil {
			return commandSet{}, err
		}
		*constructor.destination = command
	}
	return result, nil
}

// collectStatements collects statements from the configured evidence sources.
func collectStatements(ctx context.Context, runner guest.Runner, target guest.Target, database solisconfig.DatabaseObservabilityConfig, command guest.CommandSpec, timeout time.Duration, extensionsAvailable bool, status *observability.DBStatus, failures *[]string, successes *int) {
	if !database.CollectPGStatStatements {
		availability := unavailable(errors.New("collection disabled in configuration"))
		status.Sections.PGStatStatements = availability
		status.PGStatStatements.Availability = availability
		return
	}
	if !extensionsAvailable {
		availability := unavailable(errors.New("extension availability could not be determined"))
		status.Sections.PGStatStatements = availability
		status.PGStatStatements.Availability = availability
		*failures = append(*failures, "pg_stat_statements: "+availability.Error)
		return
	}
	index := sort.SearchStrings(status.Extensions, "pg_stat_statements")
	if index >= len(status.Extensions) || status.Extensions[index] != "pg_stat_statements" {
		availability := unavailable(errors.New("pg_stat_statements extension is not installed"))
		status.Sections.PGStatStatements = availability
		status.PGStatStatements.Availability = availability
		return
	}
	output, err := run(ctx, runner, target, command, timeout)
	if err == nil {
		status.PGStatStatements.Entries, err = parseStatementStatistics(output)
	}
	if err != nil {
		availability := unavailable(err)
		status.Sections.PGStatStatements = availability
		status.PGStatStatements.Availability = availability
		*failures = append(*failures, "pg_stat_statements: "+availability.Error)
		return
	}
	availability := measured()
	status.Sections.PGStatStatements = availability
	status.PGStatStatements.Availability = availability
	status.PGStatStatements.Available = true
	(*successes)++
}

// run executes one allowlisted collection step and propagates source failures.
func run(ctx context.Context, runner guest.Runner, target guest.Target, command guest.CommandSpec, timeout time.Duration) (string, error) {
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := runner.Run(commandContext, target, command)
	if err != nil {
		return "", err
	}
	return result.Output, nil
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
