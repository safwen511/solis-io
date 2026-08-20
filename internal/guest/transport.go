// Package guest collects privacy-safe guest metadata through a strict,
// allowlisted transport boundary.
package guest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/safwen511/solis-io/internal/inventory"
)

// Runner executes one command selected from the internal command allowlist.
// CommandSpec cannot contain caller-supplied shell text.
type Runner interface {
	Run(ctx context.Context, target Target, command CommandSpec) (Result, error)
}

// Result is bounded command output for an internal parser. It is never
// rendered directly to an operator.
type Result struct {
	Output string
}

// Target is an inventory-derived SSH destination. Its fields are deliberately
// private so callers cannot construct arbitrary destinations.
type Target struct {
	vmName string
	host   string
	user   string
}

// TargetForVM resolves a destination from a validated inventory VM.
func TargetForVM(vm inventory.VM, user string) (Target, error) {
	host := strings.TrimSpace(vm.IPLease)
	if host == "" {
		host = strings.TrimSpace(vm.IPPlan)
	}
	if net.ParseIP(host) == nil {
		return Target{}, fmt.Errorf("VM %q has no valid inventory IP", vm.Name)
	}
	user = strings.TrimSpace(user)
	if user == "" || !safeUserPattern.MatchString(user) {
		return Target{}, errors.New("configured guest SSH user is empty or invalid")
	}
	return Target{vmName: vm.Name, host: host, user: user}, nil
}

// VMName returns the inventory identity used to create the target.
func (target Target) VMName() string { return target.vmName }

// Host returns the inventory-resolved IP for fixed health checks.
func (target Target) Host() string { return target.host }

type CommandKind string

const (
	CommandHostname             CommandKind = "hostname"
	CommandKernelRelease        CommandKind = "kernel-release"
	CommandUptime               CommandKind = "uptime"
	CommandLoad                 CommandKind = "load"
	CommandMemory               CommandKind = "memory"
	CommandFilesystems          CommandKind = "filesystems"
	CommandNetworkAddress       CommandKind = "network-addresses"
	CommandNetworkCounters      CommandKind = "network-counters"
	CommandListeningPorts       CommandKind = "listening-ports"
	CommandProcessPressure      CommandKind = "process-pressure"
	CommandSystemdUnit          CommandKind = "systemd-unit"
	CommandPostgreSQLVersion    CommandKind = "postgresql-version"
	CommandPostgreSQLDatabases  CommandKind = "postgresql-databases"
	CommandPostgreSQLActivity   CommandKind = "postgresql-activity"
	CommandPostgreSQLExtensions CommandKind = "postgresql-extensions"
	CommandPostgreSQLStatements CommandKind = "postgresql-stat-statements"
)

// CommandSpec identifies one fixed command. Dynamic values are limited to a
// validated systemd unit or PostgreSQL connection database name; SQL is never
// accepted from callers.
type CommandSpec struct {
	kind     CommandKind
	unit     string
	database string
}

// HostnameCommand selects the fixed hostname metadata command.
func HostnameCommand() CommandSpec { return CommandSpec{kind: CommandHostname} }

// KernelReleaseCommand selects the fixed kernel-release metadata command.
func KernelReleaseCommand() CommandSpec { return CommandSpec{kind: CommandKernelRelease} }

// UptimeCommand selects the fixed uptime metadata command.
func UptimeCommand() CommandSpec { return CommandSpec{kind: CommandUptime} }

// LoadCommand selects the fixed load-average metadata command.
func LoadCommand() CommandSpec { return CommandSpec{kind: CommandLoad} }

// MemoryCommand selects the fixed memory-counter metadata command.
func MemoryCommand() CommandSpec { return CommandSpec{kind: CommandMemory} }

// FilesystemsCommand selects the fixed filesystem-capacity metadata command.
func FilesystemsCommand() CommandSpec { return CommandSpec{kind: CommandFilesystems} }

// NetworkAddressCommand selects the fixed interface-address metadata command.
func NetworkAddressCommand() CommandSpec { return CommandSpec{kind: CommandNetworkAddress} }

// NetworkCountersCommand selects the fixed interface-counter metadata command.
func NetworkCountersCommand() CommandSpec { return CommandSpec{kind: CommandNetworkCounters} }

// ListeningPortsCommand selects the fixed listening-socket metadata command.
func ListeningPortsCommand() CommandSpec { return CommandSpec{kind: CommandListeningPorts} }

// ProcessPressureCommand selects comm-only process pressure metadata without arguments or environments.
func ProcessPressureCommand() CommandSpec { return CommandSpec{kind: CommandProcessPressure} }

// SystemdUnitCommand builds systemd unit command and returns an error when validation or source
// access fails.
func SystemdUnitCommand(unit string) (CommandSpec, error) {
	unit = strings.TrimSpace(unit)
	if !safeUnitPattern.MatchString(unit) || !strings.HasSuffix(unit, ".service") {
		return CommandSpec{}, fmt.Errorf("invalid allowlisted systemd unit %q", unit)
	}
	return CommandSpec{kind: CommandSystemdUnit, unit: unit}, nil
}

// PostgreSQL statistic commands are fixed in code. The database argument is a
// validated connection target, never SQL supplied by a caller.
func PostgreSQLVersionCommand(database string) (CommandSpec, error) {
	return postgreSQLCommand(CommandPostgreSQLVersion, database)
}

// PostgreSQLDatabasesCommand builds PostgreSQL databases command and returns an error when
// validation or source access fails.
func PostgreSQLDatabasesCommand(database string) (CommandSpec, error) {
	return postgreSQLCommand(CommandPostgreSQLDatabases, database)
}

// PostgreSQLActivityCommand builds PostgreSQL activity command and returns an error when validation
// or source access fails.
func PostgreSQLActivityCommand(database string) (CommandSpec, error) {
	return postgreSQLCommand(CommandPostgreSQLActivity, database)
}

// PostgreSQLExtensionsCommand builds PostgreSQL extensions command and returns an error when
// validation or source access fails.
func PostgreSQLExtensionsCommand(database string) (CommandSpec, error) {
	return postgreSQLCommand(CommandPostgreSQLExtensions, database)
}

// PostgreSQLStatementsCommand builds PostgreSQL statements command and returns an error when
// validation or source access fails.
func PostgreSQLStatementsCommand(database string) (CommandSpec, error) {
	return postgreSQLCommand(CommandPostgreSQLStatements, database)
}

// postgreSQLCommand builds PostgreSQL command and returns an error when validation or source access
// fails.
func postgreSQLCommand(kind CommandKind, database string) (CommandSpec, error) {
	database = strings.TrimSpace(database)
	if !safeDatabasePattern.MatchString(database) {
		return CommandSpec{}, errors.New("configured PostgreSQL database name is empty or invalid")
	}
	return CommandSpec{kind: kind, database: database}, nil
}

// Key is a non-executable stable identity useful for tests and diagnostics.
func (command CommandSpec) Key() string {
	if command.unit != "" {
		return string(command.kind) + ":" + command.unit
	}
	if command.database != "" {
		return string(command.kind) + ":" + command.database
	}
	return string(command.kind)
}

// argv expands an allowlisted guest command into an argument vector without invoking a shell.
func (command CommandSpec) argv() ([]string, error) {
	switch command.kind {
	case CommandHostname:
		return []string{"hostname"}, nil
	case CommandKernelRelease:
		return []string{"uname", "-r"}, nil
	case CommandUptime:
		return []string{"cat", "/proc/uptime"}, nil
	case CommandLoad:
		return []string{"cat", "/proc/loadavg"}, nil
	case CommandMemory:
		return []string{"cat", "/proc/meminfo"}, nil
	case CommandFilesystems:
		return []string{"df", "-B1", "-P"}, nil
	case CommandNetworkAddress:
		return []string{"ip", "-br", "addr"}, nil
	case CommandNetworkCounters:
		return []string{"cat", "/proc/net/dev"}, nil
	case CommandListeningPorts:
		return []string{"ss", "-H", "-lntup"}, nil
	case CommandProcessPressure:
		return []string{"ps", "-eo", "pid=,ppid=,comm=,%cpu=,%mem=", "--sort=-%cpu"}, nil
	case CommandSystemdUnit:
		if !safeUnitPattern.MatchString(command.unit) || !strings.HasSuffix(command.unit, ".service") {
			return nil, fmt.Errorf("invalid allowlisted systemd unit %q", command.unit)
		}
		return []string{"systemctl", "show", command.unit, "--no-pager", "--property=Id,ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestamp"}, nil
	case CommandPostgreSQLVersion, CommandPostgreSQLDatabases, CommandPostgreSQLActivity,
		CommandPostgreSQLExtensions, CommandPostgreSQLStatements:
		if !safeDatabasePattern.MatchString(command.database) {
			return nil, errors.New("configured PostgreSQL database name is empty or invalid")
		}
		query, ok := postgreSQLQueries[command.kind]
		if !ok {
			return nil, fmt.Errorf("guest command kind %q is not allowlisted", command.kind)
		}
		return []string{
			"sudo", "-n", "-u", "postgres", "--", "psql",
			"--no-psqlrc", "--csv", "--tuples-only", "--set", "ON_ERROR_STOP=1",
			"--dbname", command.database, "--command", query,
		}, nil
	default:
		return nil, fmt.Errorf("guest command kind %q is not allowlisted", command.kind)
	}
}

var (
	safeUserPattern     = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	safeUnitPattern     = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+$`)
	safeDatabasePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

var postgreSQLQueries = map[CommandKind]string{
	CommandPostgreSQLVersion: `SELECT version();`,
	CommandPostgreSQLDatabases: `SELECT datname, numbackends, xact_commit, xact_rollback,
       blks_read, blks_hit, deadlocks
FROM pg_stat_database;`,
	CommandPostgreSQLActivity: `SELECT pid, usename, datname, state, wait_event_type,
       wait_event, now() - query_start AS age
FROM pg_stat_activity
WHERE state <> 'idle';`,
	CommandPostgreSQLExtensions: `SELECT extname FROM pg_extension;`,
	CommandPostgreSQLStatements: `SELECT queryid, calls, total_exec_time, mean_exec_time, rows
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 10;`,
}
