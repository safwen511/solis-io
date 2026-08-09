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
	CommandHostname        CommandKind = "hostname"
	CommandKernelRelease   CommandKind = "kernel-release"
	CommandUptime          CommandKind = "uptime"
	CommandLoad            CommandKind = "load"
	CommandMemory          CommandKind = "memory"
	CommandFilesystems     CommandKind = "filesystems"
	CommandNetworkAddress  CommandKind = "network-addresses"
	CommandNetworkCounters CommandKind = "network-counters"
	CommandListeningPorts  CommandKind = "listening-ports"
	CommandProcessPressure CommandKind = "process-pressure"
	CommandSystemdUnit     CommandKind = "systemd-unit"
)

// CommandSpec identifies one fixed command. The only dynamic value supported
// is a strictly validated systemd unit name.
type CommandSpec struct {
	kind CommandKind
	unit string
}

func HostnameCommand() CommandSpec        { return CommandSpec{kind: CommandHostname} }
func KernelReleaseCommand() CommandSpec   { return CommandSpec{kind: CommandKernelRelease} }
func UptimeCommand() CommandSpec          { return CommandSpec{kind: CommandUptime} }
func LoadCommand() CommandSpec            { return CommandSpec{kind: CommandLoad} }
func MemoryCommand() CommandSpec          { return CommandSpec{kind: CommandMemory} }
func FilesystemsCommand() CommandSpec     { return CommandSpec{kind: CommandFilesystems} }
func NetworkAddressCommand() CommandSpec  { return CommandSpec{kind: CommandNetworkAddress} }
func NetworkCountersCommand() CommandSpec { return CommandSpec{kind: CommandNetworkCounters} }
func ListeningPortsCommand() CommandSpec  { return CommandSpec{kind: CommandListeningPorts} }
func ProcessPressureCommand() CommandSpec { return CommandSpec{kind: CommandProcessPressure} }

func SystemdUnitCommand(unit string) (CommandSpec, error) {
	unit = strings.TrimSpace(unit)
	if !safeUnitPattern.MatchString(unit) || !strings.HasSuffix(unit, ".service") {
		return CommandSpec{}, fmt.Errorf("invalid allowlisted systemd unit %q", unit)
	}
	return CommandSpec{kind: CommandSystemdUnit, unit: unit}, nil
}

// Key is a non-executable stable identity useful for tests and diagnostics.
func (command CommandSpec) Key() string {
	if command.unit != "" {
		return string(command.kind) + ":" + command.unit
	}
	return string(command.kind)
}

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
	default:
		return nil, fmt.Errorf("guest command kind %q is not allowlisted", command.kind)
	}
}

var (
	safeUserPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	safeUnitPattern = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+$`)
)
