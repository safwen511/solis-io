package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/safwen511/solis-io/internal/capture"
	solisconfig "github.com/safwen511/solis-io/internal/config"
	"github.com/safwen511/solis-io/internal/dbstats"
	"github.com/safwen511/solis-io/internal/diagnose"
	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/doctor"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/experiment"
	"github.com/safwen511/solis-io/internal/guest"
	"github.com/safwen511/solis-io/internal/hostmetrics"
	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/incident"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/observability"
	"github.com/safwen511/solis-io/internal/observe"
	"github.com/safwen511/solis-io/internal/output"
	"github.com/safwen511/solis-io/internal/qemuio"
	"github.com/safwen511/solis-io/internal/servicehealth"
	statusview "github.com/safwen511/solis-io/internal/status"
	"github.com/safwen511/solis-io/internal/storage"
	"github.com/safwen511/solis-io/internal/storagevm"
	topview "github.com/safwen511/solis-io/internal/top"
	"github.com/safwen511/solis-io/internal/traceplan"
	"github.com/safwen511/solis-io/internal/version"
	watcher "github.com/safwen511/solis-io/internal/watch"
)

// Run executes the requested Solis command.
func Run(args []string, stdout, stderr io.Writer) error {
	runtimeConfig, commandArgs, err := solisconfig.Resolve(args, os.Getenv(solisconfig.EnvironmentVariable))
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}
	args = commandArgs
	args, err = relocateLeadingGlobalJSON(args)
	if err != nil {
		return err
	}
	args, helpRequested, err := stripHelpFlags(args)
	if err != nil {
		return err
	}
	if helpRequested {
		fmt.Fprintln(stdout, usageForCommand(args))
		return nil
	}
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}

	switch args[0] {
	case "version":
		return runVersion(args, stdout)
	case "doctor":
		return runDoctor(runtimeConfig, args, stdout)
	case "ebpf":
		return runEBPFCommand(runtimeConfig, args, stdout)
	case "inventory":
		return runInventory(runtimeConfig, stdout)
	case "host":
		if err := parseHostStatusArgs(args); err != nil {
			return err
		}
		return runHostStatus(runtimeConfig, stdout)
	case "guest":
		name, err := parseVMJSONStatusArgs(args, "guest")
		if err != nil {
			return err
		}
		return runGuestStatus(runtimeConfig, name, stdout)
	case "service":
		name, err := parseVMJSONStatusArgs(args, "service")
		if err != nil {
			return err
		}
		return runServiceStatus(runtimeConfig, name, stdout)
	case "db":
		name, err := parseVMJSONStatusArgs(args, "db")
		if err != nil {
			return err
		}
		return runDBStatus(runtimeConfig, name, stdout)
	case "observe":
		if len(args) < 2 {
			return errors.New(observeUsage)
		}
		switch args[1] {
		case "snapshot":
			options, err := parseObserveSnapshotArgs(args)
			if err != nil {
				return err
			}
			return runObserveSnapshot(runtimeConfig, options, stdout)
		case "watch":
			options, err := parseObserveWatchArgs(args)
			if err != nil {
				return err
			}
			return runObserveWatch(runtimeConfig, options, stdout, stderr)
		default:
			return errors.New(observeUsage)
		}
	case "status":
		options, err := parseStatusArgs(args)
		if err != nil {
			return err
		}
		return runStatus(runtimeConfig, options, stdout)
	case "top":
		options, err := parseTopArgs(args)
		if err != nil {
			return err
		}
		return runTop(runtimeConfig, options, stdout)
	case "trace":
		victim, suspect, err := parseTracePlanArgs(args)
		if err != nil {
			return err
		}
		return runTracePlan(runtimeConfig, victim, suspect, stdout)
	case "storage":
		return runStorageCommand(runtimeConfig, args, stdout)
	case "vm":
		options, err := parseVMStorageStatsArgs(args)
		if err != nil {
			return err
		}
		return runVMStorageStats(runtimeConfig, options, stdout)
	case "qemu":
		return runQEMUCommand(runtimeConfig, args, stdout)
	case "diagnose":
		return runDiagnoseCommand(runtimeConfig, args, stdout)
	case "capture":
		return runCaptureCommand(runtimeConfig, args, stdout)
	case "watch":
		return runWatchCommand(runtimeConfig, args, stdout)
	case "experiment":
		if len(args) != 3 || args[1] != "summarize" {
			return errors.New("usage: solis experiment summarize <report-dir>")
		}
		return runExperimentSummary(args[2], stdout)
	case "incidents":
		reportDir, victim, suspect, err := parseIncidentExplainArgs(args)
		if err != nil {
			return err
		}
		return runIncidentExplanation(reportDir, victim, suspect, stdout)
	case "inspect":
		if len(args) < 2 || args[1] == "--verbose" {
			return errors.New("usage: solis inspect <vm>")
		}
		verbose := false
		if len(args) > 2 {
			if len(args) != 3 || args[2] != "--verbose" {
				return errors.New("usage: solis inspect <vm> [--verbose]")
			}
			verbose = true
		}
		return runInspect(runtimeConfig, args[1], verbose, stdout)
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func runVersion(args []string, w io.Writer) error {
	info := version.BuildInfo()
	switch {
	case len(args) == 1:
		return version.WriteHuman(w, info)
	case len(args) == 2:
		jsonOutput, matched, err := booleanFlag(args[1], "--json")
		if err != nil || !matched {
			return errors.New("usage: solis version [--json]")
		}
		if jsonOutput {
			return version.WriteJSON(w, info)
		}
		return version.WriteHuman(w, info)
	default:
		return errors.New("usage: solis version [--json]")
	}
}

const incidentExplainUsage = "usage: solis incidents explain <report-dir> --victim <name> --suspect <name>"
const tracePlanUsage = "usage: solis trace plan --victim <name> --suspect <name>"
const storageSnapshotUsage = "usage: solis storage snapshot --victim <name> --suspect <name>"
const storageWatchUsage = "usage: solis storage watch --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]"
const qemuIOWatchUsage = "usage: solis qemu io-watch --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]"
const qemuIOSummaryUsage = "usage: solis qemu io-summary --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]"
const diagnoseNoisyNeighborUsage = "usage: solis diagnose noisy-neighbor [--report-dir <dir>] --victim <vm> (--suspect <vm> | --discover-suspects) [--duration <duration>] [--interval <duration>] [--include-ebpf-latency] [--json] [--output <path> | --output-dir <dir>]"
const captureNoisyNeighborUsage = "usage: solis capture noisy-neighbor [--report-dir <dir>] --victim <vm> (--suspect <vm> | --discover-suspects) [--duration <duration>] [--interval <duration>] [--include-ebpf-latency] --output-dir <dir>"
const watchNoisyNeighborUsage = "usage: solis watch noisy-neighbor --victim <vm> (--suspect <vm> | --discover-suspects) [--window <duration>] [--every <duration>] [--iterations <n>] [--include-ebpf-latency] [--capture-on-alert] [--cooldown <duration>] [--output-dir <dir>] [--verbose]"
const ebpfUsage = "usage: solis ebpf doctor | solis ebpf block-watch [--duration <duration>] | solis ebpf block-events --duration <duration> | solis ebpf block-count --duration <duration> | solis ebpf block-latency [--victim <vm> --suspect <vm>] --duration <duration> | solis ebpf vm-block-latency [options] --json"
const ebpfBlockWatchUsage = "usage: solis ebpf block-watch [--duration <duration>]"
const ebpfBlockEventsUsage = "usage: solis ebpf block-events --duration <duration>"
const ebpfBlockCountUsage = "usage: solis ebpf block-count --duration <duration>"
const ebpfBlockLatencyUsage = "usage: solis ebpf block-latency [--victim <vm> --suspect <vm>] --duration <duration>"
const ebpfVMBlockLatencyUsage = "usage: solis ebpf vm-block-latency [--duration <duration>] [--interval <duration>] [--device <block-device-name>] [--victim <vm>] [--suspect <vm>] [--all-vms] [--output <path>] --json"
const vmStorageStatsUsage = "usage: solis vm storage-stats [--victim <vm>] [--suspect <vm>] [--all-vms] [--duration <duration>] [--interval <duration>] [--output <path>] --json"
const statusUsage = "usage: solis status [--duration <duration>] [--interval <duration>] [--json] [--watch] [--every <duration>] [--iterations <n>] [--clear | --no-clear] [--sort <field>]"
const topUsage = "usage: solis top [--duration <duration>] [--interval <duration>] [--every <duration>] [--iterations <n>] [--include-ebpf-latency] [--clear | --no-clear] [--sort <field>]"
const hostStatusUsage = "usage: solis host status --json"
const guestStatusUsage = "usage: solis guest status --vm <name> --json"
const serviceStatusUsage = "usage: solis service status --vm <name> --json"
const dbStatusUsage = "usage: solis db status --vm <name> --json"
const observeUsage = "usage: solis observe snapshot|watch [options]"
const observeSnapshotUsage = "usage: solis observe snapshot --victim <vm> [--suspect <vm> | --discover-suspects] [--duration <duration>] [--interval <duration>] [--include-guest] [--include-services] [--include-db] [--include-ebpf-latency] --json"
const observeWatchUsage = "usage: solis observe watch --victim <vm> [--suspect <vm> | --discover-suspects] [--duration <duration>] [--interval <duration>] [--every <duration>] [--iterations <n>] [--include-guest] [--include-services] [--include-db] [--include-ebpf-latency] [--output-dir <dir>] --json"

func booleanFlag(token, name string) (value, matched bool, err error) {
	if token == name {
		return true, true, nil
	}
	prefix := name + "="
	if !strings.HasPrefix(token, prefix) {
		return false, false, nil
	}
	parsed, parseErr := strconv.ParseBool(strings.TrimPrefix(token, prefix))
	if parseErr != nil {
		return false, true, fmt.Errorf("invalid boolean value for %s: %q", name, strings.TrimPrefix(token, prefix))
	}
	return parsed, true, nil
}

func setBooleanOption(token, name, usage string, seen, target *bool) (bool, error) {
	value, matched, err := booleanFlag(token, name)
	if err != nil {
		return matched, fmt.Errorf("%s: %w", usage, err)
	}
	if !matched {
		return false, nil
	}
	if *seen {
		return true, fmt.Errorf("%s: %s specified more than once", usage, name)
	}
	*seen = true
	*target = value
	return true, nil
}

func setKnownBooleanOption(token, usage string, seen map[string]bool, targets map[string]*bool) (bool, error) {
	name := token
	if separator := strings.IndexByte(name, '='); separator >= 0 {
		name = name[:separator]
	}
	target, ok := targets[name]
	if !ok {
		return false, nil
	}
	value, matched, err := booleanFlag(token, name)
	if err != nil {
		return true, fmt.Errorf("%s: %w", usage, err)
	}
	if !matched {
		return false, nil
	}
	if seen[name] {
		return true, fmt.Errorf("%s: %s specified more than once", usage, name)
	}
	seen[name] = true
	*target = value
	return true, nil
}

func stripHelpFlags(args []string) ([]string, bool, error) {
	filtered := make([]string, 0, len(args))
	requested := false
	seen := false
	for _, token := range args {
		value, matched, err := booleanFlag(token, "--help")
		if err != nil {
			return nil, false, err
		}
		if !matched {
			filtered = append(filtered, token)
			continue
		}
		if seen {
			return nil, false, errors.New("--help specified more than once")
		}
		seen = true
		requested = value
	}
	return filtered, requested, nil
}

func relocateLeadingGlobalJSON(args []string) ([]string, error) {
	if len(args) == 0 {
		return args, nil
	}
	value, matched, err := booleanFlag(args[0], "--json")
	if err != nil {
		return nil, err
	}
	if !matched {
		return args, nil
	}
	if len(args) > 1 {
		if _, duplicate, duplicateErr := booleanFlag(args[1], "--json"); duplicateErr != nil {
			return nil, duplicateErr
		} else if duplicate {
			return nil, errors.New("--json specified more than once")
		}
	}
	relocated := append([]string(nil), args[1:]...)
	return append(relocated, "--json="+strconv.FormatBool(value)), nil
}

func usageForCommand(args []string) string {
	if len(args) >= 2 {
		switch args[0] + " " + args[1] {
		case "diagnose noisy-neighbor":
			return diagnoseNoisyNeighborUsage
		case "capture noisy-neighbor":
			return captureNoisyNeighborUsage
		case "watch noisy-neighbor":
			return watchNoisyNeighborUsage
		case "ebpf block-watch":
			return ebpfBlockWatchUsage
		case "ebpf block-events":
			return ebpfBlockEventsUsage
		case "ebpf block-count":
			return ebpfBlockCountUsage
		case "ebpf block-latency":
			return ebpfBlockLatencyUsage
		case "ebpf vm-block-latency":
			return ebpfVMBlockLatencyUsage
		case "observe snapshot":
			return observeSnapshotUsage
		case "observe watch":
			return observeWatchUsage
		case "vm storage-stats":
			return vmStorageStatsUsage
		}
	}
	if len(args) >= 1 {
		switch args[0] {
		case "ebpf":
			return ebpfUsage
		case "status":
			return statusUsage
		case "top":
			return topUsage
		case "version":
			return "usage: solis version [--json]"
		}
	}
	var builder strings.Builder
	printUsage(&builder)
	return strings.TrimSpace(builder.String())
}

type ebpfBlockLatencyOptions struct {
	Victim   string
	Suspect  string
	Duration time.Duration
}

type ebpfVMBlockLatencyOptions struct {
	Duration time.Duration
	Interval time.Duration
	Device   string
	Victim   string
	Suspect  string
	AllVMs   bool
	Output   string
	JSON     bool
}

type vmStorageStatsOptions struct {
	Duration time.Duration
	Interval time.Duration
	Victim   string
	Suspect  string
	AllVMs   bool
	Output   string
	JSON     bool
}

type timedTargetOptions struct {
	ReportDirectory    string
	Victim             string
	Suspect            string
	Duration           time.Duration
	Interval           time.Duration
	OutputPath         string
	OutputDirectory    string
	IncludeEBPFLatency bool
	DiscoverSuspects   bool
	JSON               bool
}

type watchNoisyNeighborOptions struct {
	Victim             string
	Suspect            string
	DiscoverSuspects   bool
	Window             time.Duration
	Every              time.Duration
	Iterations         int
	IncludeEBPFLatency bool
	CaptureOnAlert     bool
	OutputDirectory    string
	Cooldown           time.Duration
	Verbose            bool
}

type statusOptions struct {
	Duration   time.Duration
	Interval   time.Duration
	JSON       bool
	Watch      bool
	Every      time.Duration
	Iterations int
	Clear      bool
	Sort       string
}

type topOptions struct {
	Duration           time.Duration
	Interval           time.Duration
	Every              time.Duration
	Iterations         int
	IncludeEBPFLatency bool
	Clear              bool
	Sort               string
}

type observeSnapshotOptions struct {
	Victim             string
	Suspect            string
	DiscoverSuspects   bool
	Duration           time.Duration
	Interval           time.Duration
	JSON               bool
	IncludeGuest       bool
	IncludeServices    bool
	IncludeDB          bool
	IncludeEBPFLatency bool
	EBPFVMAttribution  *ebpf.VMBlockLatencyReport
	EBPFSourceWindow   string
}

type observeWatchOptions struct {
	observeSnapshotOptions
	Every           time.Duration
	Iterations      int
	OutputDirectory string
}

func parseObserveSnapshotArgs(args []string) (observeSnapshotOptions, error) {
	options := observeSnapshotOptions{Duration: 10 * time.Second, Interval: 2 * time.Second}
	if len(args) < 2 || args[0] != "observe" || args[1] != "snapshot" {
		return observeSnapshotOptions{}, errors.New(observeSnapshotUsage)
	}
	seen := make(map[string]bool)
	booleanTargets := map[string]*bool{
		"--json": &options.JSON, "--discover-suspects": &options.DiscoverSuspects,
		"--include-guest": &options.IncludeGuest, "--include-services": &options.IncludeServices,
		"--include-db": &options.IncludeDB, "--include-ebpf-latency": &options.IncludeEBPFLatency,
	}
	for index := 2; index < len(args); index++ {
		flag := args[index]
		if matched, err := setKnownBooleanOption(flag, observeSnapshotUsage, seen, booleanTargets); matched {
			if err != nil {
				return observeSnapshotOptions{}, err
			}
			continue
		}
		if seen[flag] {
			return observeSnapshotOptions{}, fmt.Errorf("%s: %s specified more than once", observeSnapshotUsage, flag)
		}
		seen[flag] = true
		switch flag {
		case "--victim", "--suspect", "--duration", "--interval":
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
				return observeSnapshotOptions{}, fmt.Errorf("%s: %s requires a value", observeSnapshotUsage, flag)
			}
			value := strings.TrimSpace(args[index+1])
			index++
			switch flag {
			case "--victim":
				options.Victim = value
			case "--suspect":
				options.Suspect = value
			case "--duration", "--interval":
				duration, err := time.ParseDuration(value)
				if err != nil || duration <= 0 {
					return observeSnapshotOptions{}, fmt.Errorf("%s: invalid %s %q", observeSnapshotUsage, flag, value)
				}
				if flag == "--duration" {
					options.Duration = duration
				} else {
					options.Interval = duration
				}
			}
		default:
			return observeSnapshotOptions{}, fmt.Errorf("%s: unknown option %s", observeSnapshotUsage, flag)
		}
	}
	if options.Victim == "" {
		return observeSnapshotOptions{}, fmt.Errorf("%s: --victim is required", observeSnapshotUsage)
	}
	if !options.JSON {
		return observeSnapshotOptions{}, fmt.Errorf("%s: --json is required", observeSnapshotUsage)
	}
	if options.Suspect != "" && options.DiscoverSuspects {
		return observeSnapshotOptions{}, fmt.Errorf("%s: --suspect and --discover-suspects cannot be used together", observeSnapshotUsage)
	}
	if options.Interval > options.Duration {
		return observeSnapshotOptions{}, fmt.Errorf("%s: interval %s cannot exceed duration %s", observeSnapshotUsage, options.Interval, options.Duration)
	}
	return options, nil
}

func parseObserveWatchArgs(args []string) (observeWatchOptions, error) {
	options := observeWatchOptions{
		observeSnapshotOptions: observeSnapshotOptions{Duration: 10 * time.Second, Interval: 2 * time.Second},
		Every:                  30 * time.Second,
	}
	if len(args) < 2 || args[0] != "observe" || args[1] != "watch" {
		return observeWatchOptions{}, errors.New(observeWatchUsage)
	}
	seen := make(map[string]bool)
	booleanTargets := map[string]*bool{
		"--json": &options.JSON, "--discover-suspects": &options.DiscoverSuspects,
		"--include-guest": &options.IncludeGuest, "--include-services": &options.IncludeServices,
		"--include-db": &options.IncludeDB, "--include-ebpf-latency": &options.IncludeEBPFLatency,
	}
	for index := 2; index < len(args); index++ {
		flag := args[index]
		if matched, err := setKnownBooleanOption(flag, observeWatchUsage, seen, booleanTargets); matched {
			if err != nil {
				return observeWatchOptions{}, err
			}
			continue
		}
		if seen[flag] {
			return observeWatchOptions{}, fmt.Errorf("%s: %s specified more than once", observeWatchUsage, flag)
		}
		seen[flag] = true
		switch flag {
		case "--victim", "--suspect", "--duration", "--interval", "--every", "--iterations", "--output-dir":
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
				return observeWatchOptions{}, fmt.Errorf("%s: %s requires a value", observeWatchUsage, flag)
			}
			value := strings.TrimSpace(args[index+1])
			index++
			switch flag {
			case "--victim":
				options.Victim = value
			case "--suspect":
				options.Suspect = value
			case "--duration", "--interval", "--every":
				duration, err := time.ParseDuration(value)
				if err != nil || duration <= 0 {
					return observeWatchOptions{}, fmt.Errorf("%s: invalid %s %q", observeWatchUsage, flag, value)
				}
				switch flag {
				case "--duration":
					options.Duration = duration
				case "--interval":
					options.Interval = duration
				case "--every":
					options.Every = duration
				}
			case "--iterations":
				iterations, err := strconv.Atoi(value)
				if err != nil || iterations <= 0 {
					return observeWatchOptions{}, fmt.Errorf("%s: invalid --iterations %q", observeWatchUsage, value)
				}
				options.Iterations = iterations
			case "--output-dir":
				if value == "" {
					return observeWatchOptions{}, fmt.Errorf("%s: --output-dir must not be empty", observeWatchUsage)
				}
				options.OutputDirectory = value
			}
		default:
			return observeWatchOptions{}, fmt.Errorf("%s: unknown option %s", observeWatchUsage, flag)
		}
	}
	if options.Victim == "" {
		return observeWatchOptions{}, fmt.Errorf("%s: --victim is required", observeWatchUsage)
	}
	if !options.JSON {
		return observeWatchOptions{}, fmt.Errorf("%s: --json is required", observeWatchUsage)
	}
	if options.Suspect != "" && options.DiscoverSuspects {
		return observeWatchOptions{}, fmt.Errorf("%s: --suspect and --discover-suspects cannot be used together", observeWatchUsage)
	}
	if options.Interval > options.Duration {
		return observeWatchOptions{}, fmt.Errorf("%s: interval %s cannot exceed duration %s", observeWatchUsage, options.Interval, options.Duration)
	}
	return options, nil
}

func parseHostStatusArgs(args []string) error {
	if len(args) != 3 || args[0] != "host" || args[1] != "status" {
		return errors.New(hostStatusUsage)
	}
	value, matched, err := booleanFlag(args[2], "--json")
	if err != nil || !matched || !value {
		return errors.New(hostStatusUsage)
	}
	return nil
}

func parseVMJSONStatusArgs(args []string, command string) (string, error) {
	usage := guestStatusUsage
	if command == "service" {
		usage = serviceStatusUsage
	} else if command == "db" {
		usage = dbStatusUsage
	}
	if command != "guest" && command != "service" && command != "db" || len(args) != 5 || args[0] != command || args[1] != "status" {
		return "", errors.New(usage)
	}
	var name string
	seenVM, seenJSON := false, false
	for index := 2; index < len(args); index++ {
		if value, matched, err := booleanFlag(args[index], "--json"); matched {
			if err != nil || !value || seenJSON {
				return "", errors.New(usage)
			}
			seenJSON = true
			continue
		}
		switch args[index] {
		case "--vm":
			if seenVM || index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
				return "", errors.New(usage)
			}
			name = strings.TrimSpace(args[index+1])
			seenVM = true
			index++
		default:
			return "", errors.New(usage)
		}
	}
	if !seenVM || !seenJSON || name == "" {
		return "", errors.New(usage)
	}
	return name, nil
}

func parseStatusArgs(args []string) (statusOptions, error) {
	options := statusOptions{
		Duration: 3 * time.Second,
		Interval: time.Second,
		Every:    2 * time.Second,
		Clear:    true,
		Sort:     "name",
	}
	if len(args) == 0 || args[0] != "status" {
		return statusOptions{}, errors.New(statusUsage)
	}
	seen := make(map[string]bool)
	booleanTargets := map[string]*bool{"--json": &options.JSON, "--watch": &options.Watch}
	for index := 1; index < len(args); index++ {
		option := args[index]
		if matched, err := setKnownBooleanOption(option, statusUsage, seen, booleanTargets); matched {
			if err != nil {
				return statusOptions{}, err
			}
			continue
		}
		if value, matched, err := booleanFlag(option, "--clear"); matched {
			if err != nil {
				return statusOptions{}, fmt.Errorf("%s: %w", statusUsage, err)
			}
			if seen["--clear"] {
				return statusOptions{}, fmt.Errorf("%s: --clear specified more than once", statusUsage)
			}
			seen["--clear"] = true
			options.Clear = value
			continue
		}
		if value, matched, err := booleanFlag(option, "--no-clear"); matched {
			if err != nil {
				return statusOptions{}, fmt.Errorf("%s: %w", statusUsage, err)
			}
			if seen["--no-clear"] {
				return statusOptions{}, fmt.Errorf("%s: --no-clear specified more than once", statusUsage)
			}
			seen["--no-clear"] = true
			options.Clear = !value
			continue
		}
		if seen[option] {
			return statusOptions{}, fmt.Errorf("%s: %s specified more than once", statusUsage, option)
		}
		seen[option] = true
		switch option {
		case "--duration", "--interval", "--every", "--iterations", "--sort":
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
				return statusOptions{}, fmt.Errorf("%s: %s requires a value", statusUsage, option)
			}
			value := args[index+1]
			index++
			switch option {
			case "--duration", "--interval", "--every":
				duration, err := time.ParseDuration(value)
				if err != nil || duration <= 0 {
					return statusOptions{}, fmt.Errorf("%s: invalid %s %q", statusUsage, option, value)
				}
				switch option {
				case "--duration":
					options.Duration = duration
				case "--interval":
					options.Interval = duration
				case "--every":
					options.Every = duration
				}
			case "--iterations":
				iterations, err := strconv.Atoi(value)
				if err != nil || iterations <= 0 {
					return statusOptions{}, fmt.Errorf("%s: invalid --iterations %q", statusUsage, value)
				}
				options.Iterations = iterations
			case "--sort":
				if !statusview.ValidSortField(value) {
					return statusOptions{}, fmt.Errorf("%s: invalid --sort field %q; allowed: name, tenant, role, pressure, write, syscw", statusUsage, value)
				}
				options.Sort = strings.ToLower(value)
			}
		default:
			return statusOptions{}, fmt.Errorf("%s: unknown option %s", statusUsage, option)
		}
	}
	if options.Interval > options.Duration {
		return statusOptions{}, fmt.Errorf("%s: interval %s cannot exceed duration %s", statusUsage, options.Interval, options.Duration)
	}
	if options.Watch && options.JSON {
		return statusOptions{}, errors.New("solis status --watch does not support --json yet")
	}
	if seen["--clear"] && seen["--no-clear"] {
		return statusOptions{}, fmt.Errorf("%s: --clear and --no-clear cannot be used together", statusUsage)
	}
	if !options.Watch && (seen["--every"] || seen["--iterations"] || seen["--clear"] || seen["--no-clear"]) {
		return statusOptions{}, fmt.Errorf("%s: --every, --iterations, --clear, and --no-clear require --watch", statusUsage)
	}
	return options, nil
}

func parseTopArgs(args []string) (topOptions, error) {
	options := topOptions{
		Duration: 3 * time.Second,
		Interval: time.Second,
		Every:    5 * time.Second,
		Clear:    true,
		Sort:     "pressure",
	}
	if len(args) == 0 || args[0] != "top" {
		return topOptions{}, errors.New(topUsage)
	}
	seen := make(map[string]bool)
	booleanTargets := map[string]*bool{"--include-ebpf-latency": &options.IncludeEBPFLatency}
	for index := 1; index < len(args); index++ {
		option := args[index]
		if matched, err := setKnownBooleanOption(option, topUsage, seen, booleanTargets); matched {
			if err != nil {
				return topOptions{}, err
			}
			continue
		}
		if value, matched, err := booleanFlag(option, "--clear"); matched {
			if err != nil {
				return topOptions{}, fmt.Errorf("%s: %w", topUsage, err)
			}
			if seen["--clear"] {
				return topOptions{}, fmt.Errorf("%s: --clear specified more than once", topUsage)
			}
			seen["--clear"] = true
			options.Clear = value
			continue
		}
		if value, matched, err := booleanFlag(option, "--no-clear"); matched {
			if err != nil {
				return topOptions{}, fmt.Errorf("%s: %w", topUsage, err)
			}
			if seen["--no-clear"] {
				return topOptions{}, fmt.Errorf("%s: --no-clear specified more than once", topUsage)
			}
			seen["--no-clear"] = true
			options.Clear = !value
			continue
		}
		if seen[option] {
			return topOptions{}, fmt.Errorf("%s: %s specified more than once", topUsage, option)
		}
		seen[option] = true
		switch option {
		case "--duration", "--interval", "--every", "--iterations", "--sort":
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
				return topOptions{}, fmt.Errorf("%s: %s requires a value", topUsage, option)
			}
			value := strings.TrimSpace(args[index+1])
			index++
			switch option {
			case "--duration", "--interval", "--every":
				parsed, err := time.ParseDuration(value)
				if err != nil || parsed <= 0 {
					return topOptions{}, fmt.Errorf("%s: invalid %s %q", topUsage, option, value)
				}
				switch option {
				case "--duration":
					options.Duration = parsed
				case "--interval":
					options.Interval = parsed
				case "--every":
					options.Every = parsed
				}
			case "--iterations":
				iterations, err := strconv.Atoi(value)
				if err != nil || iterations <= 0 {
					return topOptions{}, fmt.Errorf("%s: invalid --iterations %q", topUsage, value)
				}
				options.Iterations = iterations
			case "--sort":
				if !topview.ValidSortField(value) {
					return topOptions{}, fmt.Errorf("%s: invalid --sort field %q; allowed: name, pressure, write, ops, latency", topUsage, value)
				}
				options.Sort = strings.ToLower(value)
			}
		default:
			return topOptions{}, fmt.Errorf("%s: unknown option %s", topUsage, option)
		}
	}
	if options.Interval > options.Duration {
		return topOptions{}, fmt.Errorf("%s: interval %s cannot exceed duration %s", topUsage, options.Interval, options.Duration)
	}
	if seen["--clear"] && seen["--no-clear"] {
		return topOptions{}, fmt.Errorf("%s: --clear and --no-clear cannot be used together", topUsage)
	}
	return options, nil
}

func parseIncidentExplainArgs(args []string) (string, string, string, error) {
	if len(args) < 3 || args[1] != "explain" || strings.HasPrefix(args[2], "--") {
		return "", "", "", errors.New(incidentExplainUsage)
	}

	reportDir := args[2]
	victim, suspect, err := parseVictimSuspectOptions(args, 3, incidentExplainUsage)
	if err != nil {
		return "", "", "", err
	}

	return reportDir, victim, suspect, nil
}

func parseEBPFBlockWatchArgs(args []string) (time.Duration, error) {
	if len(args) < 2 || args[0] != "ebpf" || args[1] != "block-watch" {
		return 0, errors.New(ebpfBlockWatchUsage)
	}
	if len(args) == 2 {
		return 10 * time.Second, nil
	}
	if len(args) != 4 || args[2] != "--duration" {
		return 0, errors.New(ebpfBlockWatchUsage)
	}
	duration, err := time.ParseDuration(args[3])
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s: invalid --duration %q", ebpfBlockWatchUsage, args[3])
	}
	return duration, nil
}

func parseRequiredEBPFDuration(args []string, command, usage string) (time.Duration, error) {
	if len(args) != 4 || args[0] != "ebpf" || args[1] != command || args[2] != "--duration" {
		return 0, errors.New(usage)
	}
	duration, err := time.ParseDuration(args[3])
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s: invalid --duration %q", usage, args[3])
	}
	return duration, nil
}

func parseEBPFBlockLatencyArgs(args []string) (ebpfBlockLatencyOptions, error) {
	if len(args) < 2 || args[0] != "ebpf" || args[1] != "block-latency" {
		return ebpfBlockLatencyOptions{}, errors.New(ebpfBlockLatencyUsage)
	}

	var options ebpfBlockLatencyOptions
	seen := make(map[string]bool)
	for index := 2; index < len(args); index += 2 {
		option := args[index]
		if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
			return ebpfBlockLatencyOptions{}, fmt.Errorf("%s: missing value for %s", ebpfBlockLatencyUsage, option)
		}
		if seen[option] {
			return ebpfBlockLatencyOptions{}, fmt.Errorf("%s: duplicate option %s", ebpfBlockLatencyUsage, option)
		}
		seen[option] = true
		value := args[index+1]
		switch option {
		case "--victim":
			options.Victim = value
		case "--suspect":
			options.Suspect = value
		case "--duration":
			duration, err := time.ParseDuration(value)
			if err != nil || duration <= 0 {
				return ebpfBlockLatencyOptions{}, fmt.Errorf("%s: invalid --duration %q", ebpfBlockLatencyUsage, value)
			}
			options.Duration = duration
		default:
			return ebpfBlockLatencyOptions{}, fmt.Errorf("%s: unknown option %s", ebpfBlockLatencyUsage, option)
		}
	}

	if !seen["--duration"] {
		return ebpfBlockLatencyOptions{}, errors.New(ebpfBlockLatencyUsage)
	}
	if (options.Victim == "") != (options.Suspect == "") {
		return ebpfBlockLatencyOptions{}, fmt.Errorf("%s: --victim and --suspect must be provided together", ebpfBlockLatencyUsage)
	}
	return options, nil
}

func parseEBPFVMBlockLatencyArgs(args []string) (ebpfVMBlockLatencyOptions, error) {
	if len(args) < 2 || args[0] != "ebpf" || args[1] != "vm-block-latency" {
		return ebpfVMBlockLatencyOptions{}, errors.New(ebpfVMBlockLatencyUsage)
	}
	options := ebpfVMBlockLatencyOptions{Duration: 10 * time.Second, Interval: time.Second}
	seen := make(map[string]bool)
	for index := 2; index < len(args); index++ {
		option := args[index]
		if value, matched, err := booleanFlag(option, "--json"); matched {
			if err != nil {
				return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: %w", ebpfVMBlockLatencyUsage, err)
			}
			if seen["--json"] {
				return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: duplicate option --json", ebpfVMBlockLatencyUsage)
			}
			seen["--json"] = true
			options.JSON = value
			continue
		}
		if value, matched, err := booleanFlag(option, "--all-vms"); matched {
			if err != nil {
				return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: %w", ebpfVMBlockLatencyUsage, err)
			}
			if seen["--all-vms"] {
				return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: duplicate option --all-vms", ebpfVMBlockLatencyUsage)
			}
			seen["--all-vms"] = true
			options.AllVMs = value
			continue
		}
		if seen[option] {
			return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: duplicate option %s", ebpfVMBlockLatencyUsage, option)
		}
		seen[option] = true
		switch option {
		case "--duration", "--interval", "--device", "--victim", "--suspect", "--output":
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
				return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: missing value for %s", ebpfVMBlockLatencyUsage, option)
			}
			index++
			value := strings.TrimSpace(args[index])
			if value == "" {
				return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: empty value for %s", ebpfVMBlockLatencyUsage, option)
			}
			switch option {
			case "--duration":
				duration, err := time.ParseDuration(value)
				if err != nil || duration <= 0 {
					return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: invalid --duration %q", ebpfVMBlockLatencyUsage, value)
				}
				options.Duration = duration
			case "--interval":
				interval, err := time.ParseDuration(value)
				if err != nil || interval <= 0 {
					return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: invalid --interval %q", ebpfVMBlockLatencyUsage, value)
				}
				options.Interval = interval
			case "--device":
				if !validBlockDeviceName(value) {
					return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: invalid --device %q; use a block device name such as nvme0n1 or dm-0", ebpfVMBlockLatencyUsage, value)
				}
				options.Device = value
			case "--victim":
				options.Victim = value
			case "--suspect":
				options.Suspect = value
			case "--output":
				options.Output = value
			}
		default:
			return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: unknown option %s", ebpfVMBlockLatencyUsage, option)
		}
	}
	if !options.JSON {
		return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: --json is required", ebpfVMBlockLatencyUsage)
	}
	if options.Interval > options.Duration {
		return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: --interval must not exceed --duration", ebpfVMBlockLatencyUsage)
	}
	if options.AllVMs && (options.Victim != "" || options.Suspect != "") {
		return ebpfVMBlockLatencyOptions{}, fmt.Errorf("%s: --all-vms cannot be combined with --victim or --suspect", ebpfVMBlockLatencyUsage)
	}
	return options, nil
}

func parseVMStorageStatsArgs(args []string) (vmStorageStatsOptions, error) {
	if len(args) < 2 || args[0] != "vm" || args[1] != "storage-stats" {
		return vmStorageStatsOptions{}, errors.New(vmStorageStatsUsage)
	}
	options := vmStorageStatsOptions{Duration: 10 * time.Second, Interval: time.Second}
	seen := make(map[string]bool)
	booleanTargets := map[string]*bool{"--json": &options.JSON, "--all-vms": &options.AllVMs}
	for index := 2; index < len(args); index++ {
		option := args[index]
		if matched, err := setKnownBooleanOption(option, vmStorageStatsUsage, seen, booleanTargets); matched {
			if err != nil {
				return vmStorageStatsOptions{}, err
			}
			continue
		}
		if seen[option] {
			return vmStorageStatsOptions{}, fmt.Errorf("%s: duplicate option %s", vmStorageStatsUsage, option)
		}
		seen[option] = true
		switch option {
		case "--duration", "--interval", "--victim", "--suspect", "--output":
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
				return vmStorageStatsOptions{}, fmt.Errorf("%s: missing value for %s", vmStorageStatsUsage, option)
			}
			index++
			value := strings.TrimSpace(args[index])
			if value == "" {
				return vmStorageStatsOptions{}, fmt.Errorf("%s: empty value for %s", vmStorageStatsUsage, option)
			}
			switch option {
			case "--duration":
				duration, err := time.ParseDuration(value)
				if err != nil || duration <= 0 {
					return vmStorageStatsOptions{}, fmt.Errorf("%s: invalid --duration %q", vmStorageStatsUsage, value)
				}
				options.Duration = duration
			case "--interval":
				interval, err := time.ParseDuration(value)
				if err != nil || interval <= 0 {
					return vmStorageStatsOptions{}, fmt.Errorf("%s: invalid --interval %q", vmStorageStatsUsage, value)
				}
				options.Interval = interval
			case "--victim":
				options.Victim = value
			case "--suspect":
				options.Suspect = value
			case "--output":
				options.Output = value
			}
		default:
			return vmStorageStatsOptions{}, fmt.Errorf("%s: unknown option %s", vmStorageStatsUsage, option)
		}
	}
	if !options.JSON {
		return vmStorageStatsOptions{}, fmt.Errorf("%s: --json is required", vmStorageStatsUsage)
	}
	if options.Interval > options.Duration {
		return vmStorageStatsOptions{}, fmt.Errorf("%s: --interval must not exceed --duration", vmStorageStatsUsage)
	}
	if options.AllVMs && (options.Victim != "" || options.Suspect != "") {
		return vmStorageStatsOptions{}, fmt.Errorf("%s: --all-vms cannot be combined with --victim or --suspect", vmStorageStatsUsage)
	}
	if options.Suspect != "" && options.Victim == "" {
		return vmStorageStatsOptions{}, fmt.Errorf("%s: --suspect requires --victim", vmStorageStatsUsage)
	}
	return options, nil
}

func validBlockDeviceName(value string) bool {
	if value == "" || strings.Contains(value, "/") || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func parseTracePlanArgs(args []string) (string, string, error) {
	if len(args) < 2 || args[1] != "plan" {
		return "", "", errors.New(tracePlanUsage)
	}

	return parseVictimSuspectOptions(args, 2, tracePlanUsage)
}

func parseStorageSnapshotArgs(args []string) (string, string, error) {
	if len(args) < 2 || args[1] != "snapshot" {
		return "", "", errors.New(storageSnapshotUsage)
	}

	return parseVictimSuspectOptions(args, 2, storageSnapshotUsage)
}

func parseStorageWatchArgs(args []string) (string, string, time.Duration, time.Duration, error) {
	if len(args) < 2 || args[1] != "watch" {
		return "", "", 0, 0, errors.New(storageWatchUsage)
	}
	return parseTimedWatchOptions(args, 2, storageWatchUsage, "storage watch")
}

func parseQEMUIOWatchArgs(args []string) (string, string, time.Duration, time.Duration, error) {
	if len(args) < 2 || args[1] != "io-watch" {
		return "", "", 0, 0, errors.New(qemuIOWatchUsage)
	}
	return parseTimedWatchOptions(args, 2, qemuIOWatchUsage, "qemu io-watch")
}

func parseQEMUIOSummaryArgs(args []string) (string, string, time.Duration, time.Duration, error) {
	if len(args) < 2 || args[1] != "io-summary" {
		return "", "", 0, 0, errors.New(qemuIOSummaryUsage)
	}
	return parseTimedWatchOptions(args, 2, qemuIOSummaryUsage, "qemu io-summary")
}

func parseTimedWatchOptions(args []string, start int, usage, commandName string) (string, string, time.Duration, time.Duration, error) {
	options, err := parseTimedTargetOptions(
		args,
		start,
		usage,
		commandName,
		30*time.Second,
		5*time.Second,
		false,
		false,
		false,
		false,
		false,
	)
	if err != nil {
		return "", "", 0, 0, err
	}
	return options.Victim, options.Suspect, options.Duration, options.Interval, nil
}

func parseDiagnoseNoisyNeighborArgs(args []string) (timedTargetOptions, error) {
	if len(args) < 2 || args[1] != "noisy-neighbor" {
		return timedTargetOptions{}, errors.New(diagnoseNoisyNeighborUsage)
	}
	return parseTimedTargetOptions(
		args,
		2,
		diagnoseNoisyNeighborUsage,
		"diagnose noisy-neighbor",
		10*time.Second,
		2*time.Second,
		true,
		true,
		true,
		true,
		true,
	)
}

func parseCaptureNoisyNeighborArgs(args []string) (timedTargetOptions, error) {
	if len(args) < 2 || args[1] != "noisy-neighbor" {
		return timedTargetOptions{}, errors.New(captureNoisyNeighborUsage)
	}
	options, err := parseTimedTargetOptions(
		args,
		2,
		captureNoisyNeighborUsage,
		"capture noisy-neighbor",
		10*time.Second,
		2*time.Second,
		true,
		true,
		true,
		true,
		false,
	)
	if err != nil {
		return timedTargetOptions{}, err
	}
	if options.OutputPath != "" {
		return timedTargetOptions{}, fmt.Errorf("%s: --output is not supported; use --output-dir", captureNoisyNeighborUsage)
	}
	if options.OutputDirectory == "" {
		return timedTargetOptions{}, fmt.Errorf("%s: missing --output-dir", captureNoisyNeighborUsage)
	}
	return options, nil
}

func parseWatchNoisyNeighborArgs(args []string) (watchNoisyNeighborOptions, error) {
	return parseWatchNoisyNeighborArgsWithDefault(args, solisconfig.DevelopmentDefaults().Settings.CaptureOutputRoot)
}

func parseWatchNoisyNeighborArgsWithDefault(args []string, outputDirectory string) (watchNoisyNeighborOptions, error) {
	if len(args) < 2 || args[1] != "noisy-neighbor" {
		return watchNoisyNeighborOptions{}, errors.New(watchNoisyNeighborUsage)
	}
	options := watchNoisyNeighborOptions{
		Window:          10 * time.Second,
		Every:           30 * time.Second,
		OutputDirectory: outputDirectory,
		Cooldown:        2 * time.Minute,
	}
	seen := make(map[string]bool)
	var discoverSet, includeEBPFSet, captureOnAlertSet, verboseSet bool
	for index := 2; index < len(args); {
		option := args[index]
		if matched, err := setBooleanOption(option, "--discover-suspects", watchNoisyNeighborUsage, &discoverSet, &options.DiscoverSuspects); matched {
			if err != nil {
				return watchNoisyNeighborOptions{}, err
			}
			index++
			continue
		}
		if matched, err := setBooleanOption(option, "--include-ebpf-latency", watchNoisyNeighborUsage, &includeEBPFSet, &options.IncludeEBPFLatency); matched {
			if err != nil {
				return watchNoisyNeighborOptions{}, err
			}
			index++
			continue
		}
		if matched, err := setBooleanOption(option, "--capture-on-alert", watchNoisyNeighborUsage, &captureOnAlertSet, &options.CaptureOnAlert); matched {
			if err != nil {
				return watchNoisyNeighborOptions{}, err
			}
			index++
			continue
		}
		if matched, err := setBooleanOption(option, "--verbose", watchNoisyNeighborUsage, &verboseSet, &options.Verbose); matched {
			if err != nil {
				return watchNoisyNeighborOptions{}, err
			}
			index++
			continue
		}
		if seen[option] {
			return watchNoisyNeighborOptions{}, fmt.Errorf("%s: %s specified more than once", watchNoisyNeighborUsage, option)
		}
		seen[option] = true
		if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
			return watchNoisyNeighborOptions{}, fmt.Errorf("%s: %s requires a value", watchNoisyNeighborUsage, option)
		}
		value := args[index+1]
		switch option {
		case "--victim":
			options.Victim = value
		case "--suspect":
			options.Suspect = value
		case "--window":
			parsed, err := time.ParseDuration(value)
			if err != nil || parsed <= 0 {
				return watchNoisyNeighborOptions{}, fmt.Errorf("%s: invalid --window %q", watchNoisyNeighborUsage, value)
			}
			options.Window = parsed
		case "--every":
			parsed, err := time.ParseDuration(value)
			if err != nil || parsed <= 0 {
				return watchNoisyNeighborOptions{}, fmt.Errorf("%s: invalid --every %q", watchNoisyNeighborUsage, value)
			}
			options.Every = parsed
		case "--iterations":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed <= 0 {
				return watchNoisyNeighborOptions{}, fmt.Errorf("%s: invalid --iterations %q", watchNoisyNeighborUsage, value)
			}
			options.Iterations = parsed
		case "--cooldown":
			parsed, err := time.ParseDuration(value)
			if err != nil || parsed <= 0 {
				return watchNoisyNeighborOptions{}, fmt.Errorf("%s: invalid --cooldown %q", watchNoisyNeighborUsage, value)
			}
			options.Cooldown = parsed
		case "--output-dir":
			options.OutputDirectory = value
		default:
			return watchNoisyNeighborOptions{}, fmt.Errorf("%s: unknown option %s", watchNoisyNeighborUsage, option)
		}
		index += 2
	}

	if options.Victim == "" {
		return watchNoisyNeighborOptions{}, fmt.Errorf("%s: missing --victim", watchNoisyNeighborUsage)
	}
	if options.Suspect != "" && options.DiscoverSuspects {
		return watchNoisyNeighborOptions{}, fmt.Errorf("%s: --suspect and --discover-suspects cannot be used together", watchNoisyNeighborUsage)
	}
	if options.Suspect == "" && !options.DiscoverSuspects {
		return watchNoisyNeighborOptions{}, fmt.Errorf("%s: provide either --suspect <vm> or --discover-suspects", watchNoisyNeighborUsage)
	}
	if strings.TrimSpace(options.OutputDirectory) == "" {
		return watchNoisyNeighborOptions{}, fmt.Errorf("%s: --output-dir must not be empty", watchNoisyNeighborUsage)
	}
	return options, nil
}

func parseTimedTargetOptions(
	args []string,
	start int,
	usage string,
	commandName string,
	defaultDuration time.Duration,
	defaultInterval time.Duration,
	allowReportDirectory bool,
	allowOutputOptions bool,
	allowEBPFLatency bool,
	allowSuspectDiscovery bool,
	allowJSON bool,
) (timedTargetOptions, error) {
	options := timedTargetOptions{Duration: defaultDuration, Interval: defaultInterval}
	var durationSet, intervalSet, outputSet, outputDirectorySet, includeEBPFLatencySet, discoverSuspectsSet, jsonSet bool
	for i := start; i < len(args); {
		option := args[i]
		if matched, err := setBooleanOption(option, "--discover-suspects", usage, &discoverSuspectsSet, &options.DiscoverSuspects); matched {
			if err != nil {
				return timedTargetOptions{}, err
			}
			if !allowSuspectDiscovery {
				return timedTargetOptions{}, fmt.Errorf("%s: unknown option %s", usage, option)
			}
			i++
			continue
		}
		if matched, err := setBooleanOption(option, "--include-ebpf-latency", usage, &includeEBPFLatencySet, &options.IncludeEBPFLatency); matched {
			if err != nil {
				return timedTargetOptions{}, err
			}
			if !allowEBPFLatency {
				return timedTargetOptions{}, fmt.Errorf("%s: unknown option %s", usage, option)
			}
			i++
			continue
		}
		if matched, err := setBooleanOption(option, "--json", usage, &jsonSet, &options.JSON); matched {
			if err != nil {
				return timedTargetOptions{}, err
			}
			if !allowJSON {
				return timedTargetOptions{}, fmt.Errorf("%s: unknown option %s", usage, option)
			}
			i++
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return timedTargetOptions{}, fmt.Errorf("%s: %s requires a value", usage, option)
		}
		value := args[i+1]

		switch option {
		case "--report-dir":
			if !allowReportDirectory {
				return timedTargetOptions{}, fmt.Errorf("%s: unknown option %s", usage, option)
			}
			if options.ReportDirectory != "" {
				return timedTargetOptions{}, fmt.Errorf("%s: --report-dir specified more than once", usage)
			}
			options.ReportDirectory = value
		case "--output":
			if !allowOutputOptions {
				return timedTargetOptions{}, fmt.Errorf("%s: unknown option %s", usage, option)
			}
			if outputSet {
				return timedTargetOptions{}, fmt.Errorf("%s: --output specified more than once", usage)
			}
			options.OutputPath = value
			outputSet = true
		case "--output-dir":
			if !allowOutputOptions {
				return timedTargetOptions{}, fmt.Errorf("%s: unknown option %s", usage, option)
			}
			if outputDirectorySet {
				return timedTargetOptions{}, fmt.Errorf("%s: --output-dir specified more than once", usage)
			}
			options.OutputDirectory = value
			outputDirectorySet = true
		case "--victim":
			if options.Victim != "" {
				return timedTargetOptions{}, fmt.Errorf("%s: --victim specified more than once", usage)
			}
			options.Victim = value
		case "--suspect":
			if options.Suspect != "" {
				return timedTargetOptions{}, fmt.Errorf("%s: --suspect specified more than once", usage)
			}
			options.Suspect = value
		case "--duration":
			if durationSet {
				return timedTargetOptions{}, fmt.Errorf("%s: --duration specified more than once", usage)
			}
			parsed, err := time.ParseDuration(value)
			if err != nil || parsed <= 0 {
				return timedTargetOptions{}, fmt.Errorf("%s: invalid --duration %q", usage, value)
			}
			options.Duration = parsed
			durationSet = true
		case "--interval":
			if intervalSet {
				return timedTargetOptions{}, fmt.Errorf("%s: --interval specified more than once", usage)
			}
			parsed, err := time.ParseDuration(value)
			if err != nil || parsed <= 0 {
				return timedTargetOptions{}, fmt.Errorf("%s: invalid --interval %q", usage, value)
			}
			options.Interval = parsed
			intervalSet = true
		default:
			return timedTargetOptions{}, fmt.Errorf("%s: unknown option %s", usage, option)
		}
		i += 2
	}

	if options.Victim == "" {
		return timedTargetOptions{}, fmt.Errorf("%s: missing --victim", usage)
	}
	if options.Suspect != "" && options.DiscoverSuspects {
		return timedTargetOptions{}, fmt.Errorf("%s: --suspect and --discover-suspects cannot be used together", usage)
	}
	if options.Suspect == "" && !options.DiscoverSuspects {
		if allowSuspectDiscovery {
			return timedTargetOptions{}, fmt.Errorf("%s: provide either --suspect <vm> or --discover-suspects", usage)
		}
		return timedTargetOptions{}, fmt.Errorf("%s: missing --suspect", usage)
	}
	if outputSet && outputDirectorySet {
		return timedTargetOptions{}, fmt.Errorf("%s: --output and --output-dir cannot be used together", usage)
	}
	if options.Interval > options.Duration {
		return timedTargetOptions{}, fmt.Errorf("%s interval %s cannot exceed duration %s", commandName, options.Interval, options.Duration)
	}

	return options, nil
}

func parseVictimSuspectOptions(args []string, start int, usage string) (string, string, error) {
	var victim, suspect string
	for i := start; i < len(args); {
		option := args[i]
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return "", "", fmt.Errorf("%s: %s requires a value", usage, option)
		}

		value := args[i+1]
		switch option {
		case "--victim":
			if victim != "" {
				return "", "", fmt.Errorf("%s: --victim specified more than once", usage)
			}
			victim = value
		case "--suspect":
			if suspect != "" {
				return "", "", fmt.Errorf("%s: --suspect specified more than once", usage)
			}
			suspect = value
		default:
			return "", "", fmt.Errorf("%s: unknown option %s", usage, option)
		}
		i += 2
	}

	if victim == "" {
		return "", "", fmt.Errorf("%s: missing --victim", usage)
	}
	if suspect == "" {
		return "", "", fmt.Errorf("%s: missing --suspect", usage)
	}

	return victim, suspect, nil
}

func runTracePlan(runtimeConfig solisconfig.Runtime, victim, suspect string, w io.Writer) error {
	plan, err := loadEnrichedTargetPlan(runtimeConfig, victim, suspect)
	if err != nil {
		return fmt.Errorf("trace plan error: %w", err)
	}

	plan.HostStorage = make(map[string]hoststorage.Mapping)
	for _, vm := range plan.VictimTargets {
		plan.HostStorage[vm.Name] = hoststorage.Resolve(vm.Disk)
	}
	if _, duplicate := plan.HostStorage[plan.SuspectTarget.Name]; !duplicate {
		plan.HostStorage[plan.SuspectTarget.Name] = hoststorage.Resolve(plan.SuspectTarget.Disk)
	}
	if err := traceplan.Write(w, plan); err != nil {
		return fmt.Errorf("trace plan error: %w", err)
	}

	return nil
}

func runStorageSnapshot(runtimeConfig solisconfig.Runtime, victim, suspect string, w io.Writer) error {
	plan, err := loadEnrichedTargetPlan(runtimeConfig, victim, suspect)
	if err != nil {
		return fmt.Errorf("storage snapshot error: %w", err)
	}

	snapshot := storage.Capture(
		plan.VictimSelector,
		plan.SuspectSelector,
		plan.VictimTargets,
		plan.SuspectTarget,
	)
	if err := storage.Write(w, snapshot); err != nil {
		return fmt.Errorf("storage snapshot error: %w", err)
	}

	return nil
}

func runStorageCommand(runtimeConfig solisconfig.Runtime, args []string, w io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: solis storage snapshot|watch [options]")
	}

	switch args[1] {
	case "snapshot":
		victim, suspect, err := parseStorageSnapshotArgs(args)
		if err != nil {
			return err
		}
		return runStorageSnapshot(runtimeConfig, victim, suspect, w)
	case "watch":
		victim, suspect, duration, interval, err := parseStorageWatchArgs(args)
		if err != nil {
			return err
		}
		return runStorageWatch(runtimeConfig, victim, suspect, duration, interval, w)
	default:
		return fmt.Errorf("unknown storage command %q; expected snapshot or watch", args[1])
	}
}

func runStorageWatch(runtimeConfig solisconfig.Runtime, victim, suspect string, duration, interval time.Duration, w io.Writer) error {
	plan, err := loadEnrichedTargetPlan(runtimeConfig, victim, suspect)
	if err != nil {
		return fmt.Errorf("storage watch error: %w", err)
	}

	snapshot := storage.Capture(
		plan.VictimSelector,
		plan.SuspectSelector,
		plan.VictimTargets,
		plan.SuspectTarget,
	)
	if err := storage.Watch(w, snapshot, duration, interval); err != nil {
		return fmt.Errorf("storage watch error: %w", err)
	}

	return nil
}

func runQEMUCommand(runtimeConfig solisconfig.Runtime, args []string, w io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: solis qemu io-watch|io-summary [options]")
	}

	switch args[1] {
	case "io-watch":
		victim, suspect, duration, interval, err := parseQEMUIOWatchArgs(args)
		if err != nil {
			return err
		}
		return runQEMUIOWatch(runtimeConfig, victim, suspect, duration, interval, w)
	case "io-summary":
		victim, suspect, duration, interval, err := parseQEMUIOSummaryArgs(args)
		if err != nil {
			return err
		}
		return runQEMUIOSummary(runtimeConfig, victim, suspect, duration, interval, w)
	default:
		return fmt.Errorf("unknown qemu command %q; expected io-watch or io-summary", args[1])
	}
}

func runQEMUIOWatch(runtimeConfig solisconfig.Runtime, victim, suspect string, duration, interval time.Duration, w io.Writer) error {
	plan, err := loadEnrichedTargetPlan(runtimeConfig, victim, suspect)
	if err != nil {
		return fmt.Errorf("qemu io-watch error: %w", err)
	}

	watchPlan := qemuio.NewPlan(
		plan.VictimSelector,
		plan.SuspectSelector,
		plan.VictimTargets,
		plan.SuspectTarget,
	)
	if err := qemuio.Watch(w, watchPlan, duration, interval); err != nil {
		return fmt.Errorf("qemu io-watch error: %w", err)
	}
	return nil
}

func runQEMUIOSummary(runtimeConfig solisconfig.Runtime, victim, suspect string, duration, interval time.Duration, w io.Writer) error {
	plan, err := loadEnrichedTargetPlan(runtimeConfig, victim, suspect)
	if err != nil {
		return fmt.Errorf("qemu io-summary error: %w", err)
	}

	watchPlan := qemuio.NewPlan(
		plan.VictimSelector,
		plan.SuspectSelector,
		plan.VictimTargets,
		plan.SuspectTarget,
	)
	report, err := qemuio.CollectSummaryWithThresholds(watchPlan, duration, interval, runtimeConfig.Settings.Thresholds)
	if err != nil {
		return fmt.Errorf("qemu io-summary error: %w", err)
	}
	if err := qemuio.WriteSummary(w, report); err != nil {
		return fmt.Errorf("qemu io-summary error: %w", err)
	}
	return nil
}

func runDiagnoseCommand(runtimeConfig solisconfig.Runtime, args []string, w io.Writer) error {
	options, err := parseDiagnoseNoisyNeighborArgs(args)
	if err != nil {
		return err
	}
	return runNoisyNeighborDiagnosis(runtimeConfig, options, w)
}

type noisyNeighborEvidence struct {
	Experiment        experiment.Report
	Incident          incident.Explanation
	TracePlan         traceplan.Plan
	Storage           storage.Snapshot
	QEMU              qemuio.SummaryReport
	EBPFLatency       *ebpf.BlockLatencyEvidence
	EBPFVMAttribution *ebpf.VMBlockLatencyReport
	Discovery         *discovery.Report
	Diagnosis         diagnose.Report
}

func runNoisyNeighborDiagnosis(runtimeConfig solisconfig.Runtime, options timedTargetOptions, w io.Writer) error {
	var report diagnose.Report
	var err error
	if options.DiscoverSuspects {
		var evidence noisyNeighborEvidence
		evidence, err = collectDiscoveredNoisyNeighborEvidence(runtimeConfig, options)
		report = evidence.Diagnosis
	} else {
		var evidence noisyNeighborEvidence
		evidence, err = collectNoisyNeighborEvidence(runtimeConfig, options)
		report = evidence.Diagnosis
	}
	if err != nil {
		return fmt.Errorf("diagnose noisy-neighbor error: %w", err)
	}
	if _, err := diagnose.WriteOutput(
		w,
		report,
		diagnose.OutputOptions{
			Path:      options.OutputPath,
			Directory: options.OutputDirectory,
			JSON:      options.JSON,
		},
		time.Now(),
	); err != nil {
		return fmt.Errorf("diagnose noisy-neighbor error: %w", err)
	}
	return nil
}

func runCaptureCommand(runtimeConfig solisconfig.Runtime, args []string, w io.Writer) error {
	options, err := parseCaptureNoisyNeighborArgs(args)
	if err != nil {
		return err
	}
	var evidence noisyNeighborEvidence
	if options.DiscoverSuspects {
		evidence, err = collectDiscoveredNoisyNeighborEvidence(runtimeConfig, options)
	} else {
		evidence, err = collectNoisyNeighborEvidence(runtimeConfig, options)
	}
	if err != nil {
		return fmt.Errorf("capture noisy-neighbor error: %w", err)
	}

	result, err := writeNoisyNeighborCapture(runtimeConfig, options, evidence, time.Now())
	if err != nil {
		return fmt.Errorf("capture noisy-neighbor error: %w", err)
	}

	if _, err := fmt.Fprintf(w, "Solis capture written to %s\n", result.Directory); err != nil {
		return fmt.Errorf("capture noisy-neighbor error: %w", err)
	}
	if _, err := fmt.Fprintln(w, "Generated files:"); err != nil {
		return fmt.Errorf("capture noisy-neighbor error: %w", err)
	}
	for _, path := range result.Files {
		if _, err := fmt.Fprintf(w, "- %s\n", path); err != nil {
			return fmt.Errorf("capture noisy-neighbor error: %w", err)
		}
	}
	return nil
}

func writeNoisyNeighborCapture(runtimeConfig solisconfig.Runtime, options timedTargetOptions, evidence noisyNeighborEvidence, now time.Time) (capture.Result, error) {
	mode := "pairwise"
	if options.DiscoverSuspects {
		mode = "discover-suspects"
	}
	observeOptions := observeSnapshotOptions{
		Victim: evidence.Diagnosis.Inputs.Victim, Suspect: options.Suspect, DiscoverSuspects: options.DiscoverSuspects,
		Duration: options.Duration, Interval: options.Interval, JSON: true,
		IncludeEBPFLatency: options.IncludeEBPFLatency,
		EBPFVMAttribution:  evidence.EBPFVMAttribution,
		EBPFSourceWindow:   "noisy_neighbor_diagnosis_window",
	}
	if observeOptions.EBPFVMAttribution == nil {
		observeOptions.EBPFVMAttribution = evidence.Diagnosis.EBPFVMAttribution
	}
	observeSnapshot, observeErr := collectObserveSnapshot(context.Background(), runtimeConfig, observeOptions)
	captureEvidence := capture.Evidence{
		Experiment:        evidence.Experiment,
		Incident:          evidence.Incident,
		TracePlan:         evidence.TracePlan,
		Storage:           evidence.Storage,
		QEMU:              evidence.QEMU,
		EBPFLatency:       evidence.EBPFLatency,
		EBPFVMAttribution: evidence.EBPFVMAttribution,
		Discovery:         evidence.Discovery,
		Diagnosis:         evidence.Diagnosis,
	}
	if observeErr != nil {
		captureEvidence.ObserveError = observeErr.Error()
	} else {
		captureEvidence.ObserveSnapshot = &observeSnapshot
	}
	return capture.Write(
		capture.Inputs{
			OutputDirectory:    options.OutputDirectory,
			ReportDirectory:    evidence.Experiment.Directory,
			Victim:             evidence.Diagnosis.Inputs.Victim,
			Suspect:            evidence.Diagnosis.Inputs.Suspect,
			Duration:           options.Duration,
			Interval:           options.Interval,
			IncludeEBPFLatency: options.IncludeEBPFLatency,
			CaptureMode:        mode,
			ConfigSource:       runtimeConfig.Source,
			Thresholds:         runtimeConfig.Settings.Thresholds,
		},
		captureEvidence,
		now,
	)
}

func runWatchCommand(runtimeConfig solisconfig.Runtime, args []string, w io.Writer) error {
	options, err := parseWatchNoisyNeighborArgsWithDefault(args, runtimeConfig.Settings.CaptureOutputRoot)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stats := watcher.FinalSummary{}
	err = runNoisyNeighborWatch(ctx, runtimeConfig, options, w, &stats)
	if summaryErr := watcher.WriteFinal(w, stats); err == nil && summaryErr != nil {
		err = summaryErr
	}
	if err != nil {
		return fmt.Errorf("watch noisy-neighbor error: %w", err)
	}
	return nil
}

func runNoisyNeighborWatch(ctx context.Context, runtimeConfig solisconfig.Runtime, options watchNoisyNeighborOptions, w io.Writer, stats *watcher.FinalSummary) error {
	if err := writeWatchHeader(w, options); err != nil {
		return err
	}
	diagnosisOptions := timedTargetOptions{
		Victim:             options.Victim,
		Suspect:            options.Suspect,
		Duration:           options.Window,
		Interval:           watchSamplingInterval(options.Window),
		IncludeEBPFLatency: options.IncludeEBPFLatency,
		DiscoverSuspects:   options.DiscoverSuspects,
		OutputDirectory:    options.OutputDirectory,
	}
	nextStart := time.Now()
	var lastCapture time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		iterationTime := time.Now().UTC()
		var evidence noisyNeighborEvidence
		var err error
		if options.DiscoverSuspects {
			evidence, err = collectDiscoveredNoisyNeighborEvidence(runtimeConfig, diagnosisOptions)
		} else {
			evidence, err = collectNoisyNeighborEvidence(runtimeConfig, diagnosisOptions)
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		stats.Iterations++
		summary := watcher.NewIterationSummary(iterationTime, evidence.Diagnosis)
		if err := watcher.WriteIteration(w, summary); err != nil {
			return err
		}
		if options.Verbose {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
			if err := diagnose.Write(w, evidence.Diagnosis); err != nil {
				return err
			}
		}

		if watcher.IsAlertReport(evidence.Diagnosis) {
			stats.Alerts++
			if err := watcher.WriteAlert(w, summary); err != nil {
				return err
			}
			captureTime := time.Now().UTC()
			if options.CaptureOnAlert && watcher.CaptureAllowed(captureTime, lastCapture, options.Cooldown) {
				result, err := writeNoisyNeighborCapture(runtimeConfig, diagnosisOptions, evidence, captureTime)
				if err != nil {
					return err
				}
				lastCapture = captureTime
				stats.Captures++
				if err := writeWatchCapturePaths(w, result); err != nil {
					return err
				}
			} else if options.CaptureOnAlert {
				if _, err := fmt.Fprintln(w, "Capture suppressed by cooldown."); err != nil {
					return err
				}
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}

		if options.Iterations > 0 && stats.Iterations >= options.Iterations {
			return nil
		}
		nextStart = nextStart.Add(options.Every)
		wait := time.Until(nextStart)
		if wait <= 0 {
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func writeWatchCapturePaths(w io.Writer, result capture.Result) error {
	if _, err := fmt.Fprintf(w, "Capture directory: %s\n", result.Directory); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Incident report: %s\n", filepath.Join(result.Directory, "incident-report.md")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Evidence JSON: %s\n", filepath.Join(result.Directory, "evidence-summary.json")); err != nil {
		return err
	}
	for _, path := range result.Files {
		if filepath.Base(path) == "ebpf-vm-block-latency.json" {
			_, err := fmt.Fprintf(w, "eBPF VM attribution JSON: %s\n", path)
			return err
		}
	}
	return nil
}

func writeWatchHeader(w io.Writer, options watchNoisyNeighborOptions) error {
	mode := "pairwise"
	if options.DiscoverSuspects {
		mode = "discover-suspects"
	}
	_, err := fmt.Fprintf(
		w,
		"Solis Noisy Neighbor Watch\n"+
			"Victim: %s\n"+
			"Suspect mode: %s\n"+
			"Window: %s\n"+
			"Every: %s\n"+
			"Cooldown: %s\n\n",
		options.Victim,
		mode,
		options.Window,
		options.Every,
		options.Cooldown,
	)
	return err
}

func watchSamplingInterval(window time.Duration) time.Duration {
	const defaultInterval = 2 * time.Second
	if window < defaultInterval {
		return window
	}
	return defaultInterval
}

func collectNoisyNeighborEvidence(runtimeConfig solisconfig.Runtime, options timedTargetOptions) (noisyNeighborEvidence, error) {
	experimentReport, experimentAvailable, err := loadOptionalExperimentReport(options.ReportDirectory)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}
	var explanation incident.Explanation
	if experimentAvailable {
		explanation, err = incident.NewExplanation(experimentReport, options.Victim, options.Suspect)
		if err != nil {
			return noisyNeighborEvidence{}, err
		}
	}

	plan, err := loadEnrichedTargetPlan(runtimeConfig, options.Victim, options.Suspect)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}
	storageSnapshot := storage.Capture(
		plan.VictimSelector,
		plan.SuspectSelector,
		plan.VictimTargets,
		plan.SuspectTarget,
	)
	plan.HostStorage = make(map[string]hoststorage.Mapping, len(storageSnapshot.Targets))
	for _, target := range storageSnapshot.Targets {
		plan.HostStorage[target.VM.Name] = target.Storage
	}

	qemuPlan := qemuio.NewPlan(
		plan.VictimSelector,
		plan.SuspectSelector,
		plan.VictimTargets,
		plan.SuspectTarget,
	)
	var latencyContext *ebpf.BlockLatencyVMContext
	if options.IncludeEBPFLatency {
		if len(plan.VictimTargets) == 1 {
			context := ebpf.NewBlockLatencyVMContext(plan.VictimTargets[0], plan.SuspectTarget)
			latencyContext = &context
		}
	}
	latencyResult := startBlockLatencyCollection(options.IncludeEBPFLatency, options.Duration)
	vmLatencyTargets := append([]inventory.VM(nil), plan.VictimTargets...)
	if _, duplicate := inventory.FindByName(vmLatencyTargets, plan.SuspectTarget.Name); !duplicate {
		vmLatencyTargets = append(vmLatencyTargets, plan.SuspectTarget)
	}
	vmLatencyResult := startVMBlockLatencyCollection(options.IncludeEBPFLatency, options.Duration, options.Interval, vmLatencyTargets)
	qemuReport, err := qemuio.CollectSummaryWithThresholds(qemuPlan, options.Duration, options.Interval, runtimeConfig.Settings.Thresholds)
	latencyEvidence := finishBlockLatencyCollection(latencyResult, latencyContext)
	vmLatencyEvidence := finishVMBlockLatencyCollection(vmLatencyResult, options.Duration, options.Interval)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}
	diagnosisReport, err := newDiagnosisReport(
		diagnose.Inputs{
			ReportDirectory: experimentReport.Directory,
			Victim:          options.Victim,
			Suspect:         options.Suspect,
			Duration:        options.Duration,
			Interval:        options.Interval,
			ConfigSource:    runtimeConfig.Source,
			Thresholds:      runtimeConfig.Settings.Thresholds,
		},
		experimentReport,
		experimentAvailable,
		storageSnapshot,
		qemuReport,
	)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}
	diagnosisReport.EBPFLatency = latencyEvidence
	diagnosisReport.EBPFVMAttribution = vmLatencyEvidence
	diagnosisReport = diagnose.ApplyEBPFVMAttribution(diagnosisReport)

	return noisyNeighborEvidence{
		Experiment:        experimentReport,
		Incident:          explanation,
		TracePlan:         plan,
		Storage:           storageSnapshot,
		QEMU:              qemuReport,
		EBPFLatency:       latencyEvidence,
		EBPFVMAttribution: vmLatencyEvidence,
		Diagnosis:         diagnosisReport,
	}, nil
}

func collectDiscoveredNoisyNeighborEvidence(runtimeConfig solisconfig.Runtime, options timedTargetOptions) (noisyNeighborEvidence, error) {
	experimentReport, experimentAvailable, err := loadOptionalExperimentReport(options.ReportDirectory)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}
	vms, err := inventory.LoadFromConfig(runtimeConfig.Settings.InventoryCSV)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}
	vms = inventory.EnrichWithOptions(vms, privacySafeEnrichOptions(runtimeConfig))
	targets, err := discovery.Resolve(vms, options.Victim)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}

	latencyResult := startBlockLatencyCollection(options.IncludeEBPFLatency, options.Duration)
	vmLatencyTargets := []inventory.VM{targets.Victim}
	for _, candidate := range targets.CandidateTargets {
		vmLatencyTargets = append(vmLatencyTargets, candidate.VM)
	}
	vmLatencyResult := startVMBlockLatencyCollection(options.IncludeEBPFLatency, options.Duration, options.Interval, vmLatencyTargets)
	samplingPlan := discovery.SamplingPlan(targets)
	sampled, sampleErr := qemuio.CollectSummaryWithThresholds(samplingPlan, options.Duration, options.Interval, runtimeConfig.Settings.Thresholds)
	discoveryReport := discovery.Analyze(targets, sampled)

	var selectedSuspect string
	var latencyContext *ebpf.BlockLatencyVMContext
	var qemuReport qemuio.SummaryReport
	var storageSnapshot storage.Snapshot
	if discoveryReport.Selected != nil {
		selected := discoveryReport.Selected.VM
		selectedSuspect = selected.Name
		pairPlan := qemuio.NewPlan(targets.Victim.Name, selected.Name, []inventory.VM{targets.Victim}, selected)
		qemuReport = qemuio.SummaryForPlan(sampled, pairPlan)
		storageSnapshot = storage.Capture(targets.Victim.Name, selected.Name, []inventory.VM{targets.Victim}, selected)
		if options.IncludeEBPFLatency {
			context := ebpf.NewBlockLatencyVMContext(targets.Victim, selected)
			latencyContext = &context
		}
	} else {
		selectedSuspect = "-"
		qemuReport = sampled
		storageSnapshot = storage.Snapshot{
			VictimSelector:  targets.Victim.Name,
			SuspectSelector: "-",
			Targets: []storage.VMTarget{{
				TargetType: "victim",
				VM:         targets.Victim,
				Storage:    targets.VictimStorage,
			}},
		}
	}
	latencyEvidence := finishBlockLatencyCollection(latencyResult, latencyContext)
	vmLatencyEvidence := finishVMBlockLatencyCollection(vmLatencyResult, options.Duration, options.Interval)
	if sampleErr != nil {
		return noisyNeighborEvidence{}, sampleErr
	}
	if latencyEvidence != nil && discoveryReport.Selected == nil {
		latencyEvidence.Notice = "eBPF VM-aware latency requires a selected suspect; skipping VM-aware eBPF latency."
	}

	report, err := newDiagnosisReport(
		diagnose.Inputs{
			ReportDirectory: experimentReport.Directory,
			Victim:          targets.Victim.Name,
			Suspect:         selectedSuspect,
			Duration:        options.Duration,
			Interval:        options.Interval,
			ConfigSource:    runtimeConfig.Source,
			Thresholds:      runtimeConfig.Settings.Thresholds,
		},
		experimentReport,
		experimentAvailable,
		storageSnapshot,
		qemuReport,
	)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}
	report.Discovery = &discoveryReport
	report.EBPFLatency = latencyEvidence
	report.EBPFVMAttribution = vmLatencyEvidence
	report = diagnose.ApplyEBPFVMAttribution(report)
	if discoveryReport.Selected == nil {
		if experimentAvailable {
			report.Verdict = diagnose.NoDominantCandidateVerdict
		} else {
			report.Verdict = diagnose.NoDominantLiveCandidateVerdict
		}
	}

	var explanation incident.Explanation
	if experimentAvailable {
		explanation, err = incident.NewExplanation(experimentReport, targets.Victim.Name, selectedSuspect)
		if err != nil {
			return noisyNeighborEvidence{}, err
		}
	}
	tracePlan := traceplan.Plan{
		VictimSelector: targets.Victim.Name,
		VictimTargets:  []inventory.VM{targets.Victim},
		HostStorage: map[string]hoststorage.Mapping{
			targets.Victim.Name: targets.VictimStorage,
		},
	}
	if discoveryReport.Selected != nil {
		selected := *discoveryReport.Selected
		tracePlan.SuspectSelector = selected.VM.Name
		tracePlan.SuspectTarget = selected.VM
		tracePlan.HostStorage[selected.VM.Name] = selected.Storage
	}

	return noisyNeighborEvidence{
		Experiment:        experimentReport,
		Incident:          explanation,
		TracePlan:         tracePlan,
		Storage:           storageSnapshot,
		QEMU:              qemuReport,
		EBPFLatency:       latencyEvidence,
		EBPFVMAttribution: vmLatencyEvidence,
		Discovery:         &discoveryReport,
		Diagnosis:         report,
	}, nil
}

func loadOptionalExperimentReport(path string) (experiment.Report, bool, error) {
	if strings.TrimSpace(path) == "" {
		return experiment.Report{}, false, nil
	}
	report, err := experiment.Load(path)
	if err != nil {
		return experiment.Report{}, false, err
	}
	return report, true, nil
}

func newDiagnosisReport(
	inputs diagnose.Inputs,
	experimentReport experiment.Report,
	experimentAvailable bool,
	storageSnapshot storage.Snapshot,
	qemuReport qemuio.SummaryReport,
) (diagnose.Report, error) {
	if !experimentAvailable {
		return diagnose.NewLiveReport(inputs, storageSnapshot, qemuReport), nil
	}
	return diagnose.NewReport(inputs, experimentReport, storageSnapshot, qemuReport)
}

func startBlockLatencyCollection(enabled bool, duration time.Duration) <-chan blockLatencyCollectionResult {
	if !enabled {
		return nil
	}
	results := make(chan blockLatencyCollectionResult, 1)
	go func() {
		result, err := ebpf.MeasureBlockLatency(duration)
		results <- blockLatencyCollectionResult{result: result, err: err}
	}()
	return results
}

func finishBlockLatencyCollection(results <-chan blockLatencyCollectionResult, context *ebpf.BlockLatencyVMContext) *ebpf.BlockLatencyEvidence {
	if results == nil {
		return nil
	}
	collected := <-results
	evidence := &ebpf.BlockLatencyEvidence{Result: collected.result, Context: context}
	if collected.err != nil {
		evidence.UnavailableReason = collected.err.Error()
	}
	return evidence
}

type blockLatencyCollectionResult struct {
	result ebpf.BlockLatencyResult
	err    error
}

type vmBlockLatencyCollectionResult struct {
	report ebpf.VMBlockLatencyReport
	err    error
}

func startVMBlockLatencyCollection(enabled bool, duration, interval time.Duration, targets []inventory.VM) <-chan vmBlockLatencyCollectionResult {
	if !enabled {
		return nil
	}
	results := make(chan vmBlockLatencyCollectionResult, 1)
	mappings, err := ebpf.BuildVMCgroupMappings(targets)
	if err != nil {
		results <- vmBlockLatencyCollectionResult{err: fmt.Errorf("map validated libvirt VM cgroups: %w", err)}
		return results
	}
	go func() {
		report := ebpf.CollectVMBlockLatencyReport(context.Background(), ebpf.VMBlockLatencyCollectOptions{
			Duration: duration,
			Interval: interval,
		}, mappings)
		results <- vmBlockLatencyCollectionResult{report: report}
	}()
	return results
}

func finishVMBlockLatencyCollection(results <-chan vmBlockLatencyCollectionResult, duration, interval time.Duration) *ebpf.VMBlockLatencyReport {
	if results == nil {
		return nil
	}
	collected := <-results
	if collected.err == nil {
		return &collected.report
	}
	report := ebpf.VMBlockLatencyReport{
		SchemaVersion:      "1",
		ObservedAtUTC:      time.Now().UTC().Format(time.RFC3339Nano),
		Duration:           duration.String(),
		Interval:           interval.String(),
		Mode:               "experimental",
		CollectionMode:     "typed_btf_vm_attributed_latency",
		AttributionMethod:  "blkcg_cgroup_id_to_libvirt_vm",
		AttributionQuality: "unavailable",
		Availability: ebpf.VMBlockLatencyAvailability{
			Available: false,
			Status:    "mapping_error",
			Error:     collected.err.Error(),
		},
		VMAttributionPreflight: ebpf.VMBlockAttributionPreflight{
			Status:        "unavailable",
			MissingFields: []string{},
			Caveats:       []string{"VM cgroup mapping failed before eBPF attachment"},
		},
		VMs: []ebpf.VMBlockLatencyVM{},
		UnavailableSections: []ebpf.VMBlockLatencyUnavailableSection{{
			Name: "cgroup_mapping", Status: "mapping_error", Error: collected.err.Error(),
		}},
		Caveats: []string{"no VM-attributed latency was collected because validated libvirt cgroup mapping failed"},
		Privacy: observability.PrivacyFlags{},
	}
	return &report
}

func loadEnrichedTargetPlan(runtimeConfig solisconfig.Runtime, victim, suspect string) (traceplan.Plan, error) {
	vms, err := inventory.LoadFromConfig(runtimeConfig.Settings.InventoryCSV)
	if err != nil {
		return traceplan.Plan{}, err
	}

	plan, err := traceplan.Resolve(vms, victim, suspect)
	if err != nil {
		return traceplan.Plan{}, err
	}

	targets := append([]inventory.VM(nil), plan.VictimTargets...)
	if _, duplicate := inventory.FindByName(targets, plan.SuspectTarget.Name); !duplicate {
		targets = append(targets, plan.SuspectTarget)
	}
	targets = inventory.EnrichWithOptions(targets, privacySafeEnrichOptions(runtimeConfig))

	plan, err = traceplan.Resolve(targets, victim, suspect)
	if err != nil {
		return traceplan.Plan{}, err
	}

	return plan, nil
}

func runIncidentExplanation(reportDir, victim, suspect string, w io.Writer) error {
	report, err := experiment.Load(reportDir)
	if err != nil {
		return fmt.Errorf("incidents explain error: %w", err)
	}

	explanation, err := incident.NewExplanation(report, victim, suspect)
	if err != nil {
		return fmt.Errorf("incidents explain error: %w", err)
	}
	if err := incident.WriteExplanation(w, explanation); err != nil {
		return fmt.Errorf("incidents explain error: %w", err)
	}

	return nil
}

func runExperimentSummary(reportDir string, w io.Writer) error {
	report, err := experiment.Load(reportDir)
	if err != nil {
		return fmt.Errorf("experiment summarize error: %w", err)
	}

	if err := experiment.WriteSummary(w, report); err != nil {
		return fmt.Errorf("experiment summarize error: %w", err)
	}

	return nil
}

func runInventory(runtimeConfig solisconfig.Runtime, w io.Writer) error {
	vms, err := inventory.LoadFromConfig(runtimeConfig.Settings.InventoryCSV)
	if err != nil {
		return fmt.Errorf("inventory error: %w", err)
	}

	return output.InventoryTable(w, inventory.EnrichWithOptions(vms, inventory.EnrichOptions{LibvirtURI: runtimeConfig.Settings.LibvirtURI}))
}

func runStatus(runtimeConfig solisconfig.Runtime, options statusOptions, w io.Writer) error {
	if options.Watch {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		var summary statusview.WatchSummary
		err := runStatusWatch(ctx, runtimeConfig, options, w, &summary)
		if summaryErr := statusview.WriteWatchSummary(w, summary); err == nil && summaryErr != nil {
			err = summaryErr
		}
		if err != nil {
			return fmt.Errorf("status watch error: %w", err)
		}
		return nil
	}

	report, err := collectStatus(runtimeConfig, options)
	if err != nil {
		return fmt.Errorf("status error: %w", err)
	}
	if err := statusview.SortReport(&report, options.Sort); err != nil {
		return fmt.Errorf("status error: %w", err)
	}
	if options.JSON {
		err = statusview.WriteJSON(w, report)
	} else {
		err = statusview.WriteHuman(w, report)
	}
	if err != nil {
		return fmt.Errorf("status error: %w", err)
	}
	return nil
}

func collectStatus(runtimeConfig solisconfig.Runtime, options statusOptions) (statusview.Report, error) {
	vms, err := inventory.LoadFromConfig(runtimeConfig.Settings.InventoryCSV)
	if err != nil {
		return statusview.Report{}, err
	}
	report, err := statusview.CollectWithThresholds(
		inventory.EnrichWithOptions(vms, privacySafeEnrichOptions(runtimeConfig)),
		options.Duration,
		options.Interval,
		runtimeConfig.Settings.Thresholds,
	)
	if err != nil {
		return statusview.Report{}, err
	}
	return report, nil
}

func runStatusWatch(ctx context.Context, runtimeConfig solisconfig.Runtime, options statusOptions, w io.Writer, summary *statusview.WatchSummary) error {
	nextStart := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		timestamp := time.Now().UTC()
		report, err := collectStatus(runtimeConfig, options)
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if err := statusview.SortReport(&report, options.Sort); err != nil {
			return err
		}
		summary.IterationsRun++
		counts := statusview.CountPressures(report)
		summary.HighPressureObservations += counts.High
		if options.Clear {
			if _, err := fmt.Fprint(w, "\x1b[2J\x1b[H"); err != nil {
				return err
			}
		}
		if err := statusview.WriteWatchFrame(w, report, statusview.WatchFrame{
			Timestamp: timestamp,
			Every:     options.Every,
			Iteration: summary.IterationsRun,
		}); err != nil {
			return err
		}

		if options.Iterations > 0 && summary.IterationsRun >= options.Iterations {
			return nil
		}
		nextStart = nextStart.Add(options.Every)
		wait := time.Until(nextStart)
		if wait <= 0 {
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

type liveTopSource struct {
	runtimeConfig solisconfig.Runtime
}

type topStatusCollectionResult struct {
	report statusview.Report
	err    error
}

type topHostCollectionResult struct {
	report hostmetrics.HostStatus
	err    error
}

func (source liveTopSource) Collect(ctx context.Context, request topview.CollectRequest) (topview.Snapshot, error) {
	select {
	case <-ctx.Done():
		return topview.Snapshot{}, ctx.Err()
	default:
	}
	vms, err := inventory.LoadFromConfig(source.runtimeConfig.Settings.InventoryCSV)
	if err != nil {
		return topview.Snapshot{}, fmt.Errorf("load VM inventory: %w", err)
	}
	vms = inventory.EnrichWithOptions(vms, privacySafeEnrichOptions(source.runtimeConfig))
	snapshot := topview.Snapshot{
		Status:               statusview.Report{SchemaVersion: statusview.SchemaVersion, Duration: request.Duration.String(), Interval: request.Interval.String(), VMs: []statusview.VMStatus{}},
		StatusState:          "collection_error",
		EBPFLatencyRequested: request.IncludeEBPFLatency,
	}

	var mappings []ebpf.VMBlockCgroupMapping
	latencyPrepared := false
	if request.IncludeEBPFLatency {
		targets, targetErr := selectVMBlockLatencyTargets(vms, ebpfVMBlockLatencyOptions{AllVMs: true})
		if targetErr != nil {
			snapshot.EBPFUnavailableState = "target_selection_error"
		} else {
			var mappingErr error
			mappings, mappingErr = ebpf.BuildVMCgroupMappings(targets)
			if mappingErr != nil {
				snapshot.EBPFUnavailableState = "mapping_error"
			} else {
				latencyPrepared = true
			}
		}
	}

	snapshot.ObservedAtUTC = time.Now().UTC()
	statusResults := make(chan topStatusCollectionResult, 1)
	go func() {
		report, collectErr := statusview.CollectWithThresholds(
			vms,
			request.Duration,
			request.Interval,
			source.runtimeConfig.Settings.Thresholds,
		)
		statusResults <- topStatusCollectionResult{report: report, err: collectErr}
	}()
	var hostResults chan topHostCollectionResult
	hostOptions, hostOptionsErr := hostStatusOptions(source.runtimeConfig.Settings)
	if hostOptionsErr != nil {
		snapshot.HostUnavailableState = "configuration_error"
	} else {
		hostOptions.Interval = request.Duration
		hostOptions.CollectNetwork = false
		hostResults = make(chan topHostCollectionResult, 1)
		go func() {
			report, collectErr := hostmetrics.Collect(hostOptions)
			hostResults <- topHostCollectionResult{report: report, err: collectErr}
		}()
	}

	var latencyResults chan ebpf.VMBlockLatencyReport
	if latencyPrepared {
		latencyResults = make(chan ebpf.VMBlockLatencyReport, 1)
		go func() {
			latencyResults <- ebpf.CollectVMBlockLatencyReportForPlatform(ctx, ebpf.VMBlockLatencyCollectOptions{
				Duration: request.Duration,
				Interval: request.Interval,
			}, mappings, runtime.GOOS)
		}()
	}

	statusDone := false
	hostDone := hostResults == nil
	latencyDone := latencyResults == nil
	for !statusDone || !hostDone || !latencyDone {
		select {
		case <-ctx.Done():
			return topview.Snapshot{}, ctx.Err()
		case statusResult := <-statusResults:
			statusDone = true
			statusResults = nil
			if statusResult.err == nil {
				snapshot.Status = statusResult.report
				snapshot.StatusAvailable = true
				snapshot.StatusState = "available"
			}
		case hostResult := <-hostResults:
			hostDone = true
			hostResults = nil
			if hostResult.err == nil {
				snapshot.Host = &hostResult.report
			} else {
				snapshot.HostUnavailableState = "collection_error"
			}
		case report := <-latencyResults:
			latencyDone = true
			latencyResults = nil
			snapshot.EBPFLatency = &report
		}
	}
	return snapshot, nil
}

func runTop(runtimeConfig solisconfig.Runtime, options topOptions, w io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := topview.Run(ctx, w, liveTopSource{runtimeConfig: runtimeConfig}, topview.Options{
		Duration:           options.Duration,
		Interval:           options.Interval,
		Every:              options.Every,
		Iterations:         options.Iterations,
		Clear:              options.Clear,
		Sort:               options.Sort,
		IncludeEBPFLatency: options.IncludeEBPFLatency,
	})
	if err != nil {
		return fmt.Errorf("top error: %w", err)
	}
	return nil
}

func runDoctor(runtimeConfig solisconfig.Runtime, args []string, w io.Writer) error {
	lab := false
	if len(args) == 2 && args[1] == "--lab" {
		lab = true
	} else if len(args) != 1 {
		return errors.New("usage: solis doctor [--lab]")
	}
	if err := doctor.Write(w, doctor.RunWithOptions(doctor.Options{
		Root:              runtimeConfig.BaseDir,
		InventoryCSV:      runtimeConfig.Settings.InventoryCSV,
		CaptureOutputRoot: runtimeConfig.Settings.CaptureOutputRoot,
		DefaultReportDir:  runtimeConfig.Settings.DefaultReportDir,
		LibvirtURI:        runtimeConfig.Settings.LibvirtURI,
		ConfigSource:      runtimeConfig.Source,
		SchemaVersion:     runtimeConfig.Settings.SchemaVersion,
		Observability:     runtimeConfig.Settings.Observability,
		Lab:               lab,
	})); err != nil {
		return fmt.Errorf("doctor error: %w", err)
	}
	return nil
}

func runEBPFCommand(runtimeConfig solisconfig.Runtime, args []string, w io.Writer) error {
	if len(args) < 2 {
		return errors.New(ebpfUsage)
	}
	switch args[1] {
	case "doctor":
		if len(args) != 2 {
			return errors.New("usage: solis ebpf doctor")
		}
		if err := ebpf.WriteDoctor(w, ebpf.Inspect()); err != nil {
			return fmt.Errorf("ebpf doctor error: %w", err)
		}
		return nil
	case "block-watch":
		duration, err := parseEBPFBlockWatchArgs(args)
		if err != nil {
			return err
		}
		if err := ebpf.WriteBlockWatch(w, duration, ebpf.Inspect()); err != nil {
			return fmt.Errorf("ebpf block-watch error: %w", err)
		}
		return nil
	case "block-events":
		duration, err := parseRequiredEBPFDuration(args, "block-events", ebpfBlockEventsUsage)
		if err != nil {
			return err
		}
		formats, err := ebpf.LoadBlockFormats()
		if err != nil {
			return err
		}
		if err := ebpf.WriteBlockEvents(w, duration, formats); err != nil {
			return fmt.Errorf("ebpf block-events error: %w", err)
		}
		return nil
	case "block-count":
		duration, err := parseRequiredEBPFDuration(args, "block-count", ebpfBlockCountUsage)
		if err != nil {
			return err
		}
		result, err := ebpf.CountBlockEvents(duration)
		if err != nil {
			return fmt.Errorf("ebpf block-count error: %w", err)
		}
		if err := ebpf.WriteBlockCount(w, result); err != nil {
			return fmt.Errorf("ebpf block-count error: %w", err)
		}
		return nil
	case "block-latency":
		options, err := parseEBPFBlockLatencyArgs(args)
		if err != nil {
			return err
		}
		var vmContext *ebpf.BlockLatencyVMContext
		if options.Victim != "" {
			plan, err := loadEnrichedTargetPlan(runtimeConfig, options.Victim, options.Suspect)
			if err != nil {
				return fmt.Errorf("ebpf block-latency error: %w", err)
			}
			if plan.VictimIsTenant || len(plan.VictimTargets) != 1 {
				return fmt.Errorf("ebpf block-latency error: victim must resolve to one VM: %s", options.Victim)
			}
			context := ebpf.NewBlockLatencyVMContext(plan.VictimTargets[0], plan.SuspectTarget)
			vmContext = &context
		}
		result, err := ebpf.MeasureBlockLatency(options.Duration)
		if err != nil {
			return fmt.Errorf("ebpf block-latency error: %w", err)
		}
		if vmContext != nil {
			err = ebpf.WriteVMBlockLatency(w, result, *vmContext)
		} else {
			err = ebpf.WriteBlockLatency(w, result)
		}
		if err != nil {
			return fmt.Errorf("ebpf block-latency error: %w", err)
		}
		return nil
	case "vm-block-latency":
		options, err := parseEBPFVMBlockLatencyArgs(args)
		if err != nil {
			return err
		}
		return runEBPFVMBlockLatency(runtimeConfig, options, w)
	default:
		return errors.New(ebpfUsage)
	}
}

func runEBPFVMBlockLatency(runtimeConfig solisconfig.Runtime, options ebpfVMBlockLatencyOptions, w io.Writer) error {
	vms, err := inventory.LoadFromConfig(runtimeConfig.Settings.InventoryCSV)
	if err != nil {
		return fmt.Errorf("ebpf vm-block-latency error: %w", err)
	}
	vms = inventory.EnrichWithOptions(vms, privacySafeEnrichOptions(runtimeConfig))
	targets, err := selectVMBlockLatencyTargets(vms, options)
	if err != nil {
		return fmt.Errorf("ebpf vm-block-latency error: %w", err)
	}
	mappings, err := ebpf.BuildVMCgroupMappings(targets)
	if err != nil {
		return fmt.Errorf("ebpf vm-block-latency error: map libvirt cgroups: %w", err)
	}
	report := ebpf.CollectVMBlockLatencyReportForPlatform(context.Background(), ebpf.VMBlockLatencyCollectOptions{
		Duration: options.Duration, Interval: options.Interval, DeviceFilter: options.Device,
	}, mappings, runtime.GOOS)
	if options.Output != "" {
		if err := writeVMBlockLatencyOutput(options.Output, report); err != nil {
			return fmt.Errorf("ebpf vm-block-latency error: %w", err)
		}
	}
	if err := ebpf.WriteVMBlockLatencyJSON(w, report); err != nil {
		return fmt.Errorf("ebpf vm-block-latency error: %w", err)
	}
	return nil
}

func runVMStorageStats(runtimeConfig solisconfig.Runtime, options vmStorageStatsOptions, w io.Writer) error {
	vms, err := inventory.LoadFromConfig(runtimeConfig.Settings.InventoryCSV)
	if err != nil {
		return fmt.Errorf("vm storage-stats error: %w", err)
	}
	vms = inventory.EnrichWithOptions(vms, privacySafeEnrichOptions(runtimeConfig))
	targets, err := selectVMStorageStatsTargets(vms, options)
	if err != nil {
		return fmt.Errorf("vm storage-stats error: %w", err)
	}
	mappings, err := ebpf.BuildVMCgroupMappings(targets)
	if err != nil {
		return fmt.Errorf("vm storage-stats error: map libvirt cgroups: %w", err)
	}
	report, err := storagevm.NewCollector().Collect(context.Background(), storagevm.CollectRequest{
		VMs: targets, Mappings: mappings, Duration: options.Duration, Interval: options.Interval,
		ConfigSource: runtimeConfig.Source, LibvirtURI: runtimeConfig.Settings.LibvirtURI,
	})
	if err != nil {
		return fmt.Errorf("vm storage-stats error: %w", err)
	}
	if options.Output != "" {
		if err := writeVMStorageStatsOutput(options.Output, report); err != nil {
			return fmt.Errorf("vm storage-stats error: %w", err)
		}
	}
	if err := storagevm.WriteJSON(w, report); err != nil {
		return fmt.Errorf("vm storage-stats error: %w", err)
	}
	return nil
}

func selectVMStorageStatsTargets(vms []inventory.VM, options vmStorageStatsOptions) ([]inventory.VM, error) {
	requested := []string{}
	if options.Victim != "" {
		requested = append(requested, options.Victim)
	}
	if options.Suspect != "" && options.Suspect != options.Victim {
		requested = append(requested, options.Suspect)
	}
	if len(requested) == 0 {
		targets := make([]inventory.VM, 0, len(vms))
		for _, vm := range vms {
			if strings.EqualFold(strings.TrimSpace(vm.State), "running") {
				targets = append(targets, vm)
			}
		}
		if len(targets) == 0 {
			return nil, errors.New("no running VMs found")
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })
		return targets, nil
	}
	targets := make([]inventory.VM, 0, len(requested))
	for _, name := range requested {
		vm, ok := inventory.FindByName(vms, name)
		if !ok {
			return nil, fmt.Errorf("VM not found: %s", name)
		}
		targets = append(targets, *vm)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })
	return targets, nil
}

func writeVMStorageStatsOutput(path string, report storagevm.VMStorageStatsReport) error {
	return storagevm.WriteJSONFile(path, report)
}

func writeVMBlockLatencyOutput(path string, report ebpf.VMBlockLatencyReport) error {
	return output.WritePrivateAtomicFile(path, func(writer io.Writer) error {
		return ebpf.WriteVMBlockLatencyJSON(writer, report)
	})
}

func selectVMBlockLatencyTargets(vms []inventory.VM, options ebpfVMBlockLatencyOptions) ([]inventory.VM, error) {
	requested := []string{}
	if options.Victim != "" {
		requested = append(requested, options.Victim)
	}
	if options.Suspect != "" && options.Suspect != options.Victim {
		requested = append(requested, options.Suspect)
	}
	if len(requested) == 0 {
		targets := make([]inventory.VM, 0, len(vms))
		for _, vm := range vms {
			if strings.EqualFold(strings.TrimSpace(vm.State), "running") && strings.TrimSpace(vm.QEMUPID) != "" {
				targets = append(targets, vm)
			}
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })
		return targets, nil
	}
	targets := make([]inventory.VM, 0, len(requested))
	for _, name := range requested {
		vm, ok := inventory.FindByName(vms, name)
		if !ok {
			return nil, fmt.Errorf("VM not found: %s", name)
		}
		targets = append(targets, *vm)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })
	return targets, nil
}

func runInspect(runtimeConfig solisconfig.Runtime, name string, verbose bool, w io.Writer) error {
	vms, err := inventory.LoadFromConfig(runtimeConfig.Settings.InventoryCSV)
	if err != nil {
		return fmt.Errorf("inspect error: %w", err)
	}

	vms = inventory.EnrichWithOptions(vms, inventory.EnrichOptions{LibvirtURI: runtimeConfig.Settings.LibvirtURI})
	vm, ok := inventory.FindByName(vms, name)
	if !ok {
		return fmt.Errorf("VM not found: %s", name)
	}

	return output.VMDetail(w, *vm, verbose)
}

func runHostStatus(runtimeConfig solisconfig.Runtime, w io.Writer) error {
	options, err := hostStatusOptions(runtimeConfig.Settings)
	if err != nil {
		return fmt.Errorf("host status error: %w", err)
	}
	status, err := hostmetrics.Collect(options)
	if err != nil {
		return fmt.Errorf("host status error: %w", err)
	}
	if err := hostmetrics.WriteJSON(w, status); err != nil {
		return fmt.Errorf("host status error: %w", err)
	}
	return nil
}

func runGuestStatus(runtimeConfig solisconfig.Runtime, name string, w io.Writer) error {
	vm, guestConfig, serviceRefs, err := loadGuestTarget(runtimeConfig, name)
	if err != nil {
		return fmt.Errorf("guest status error: %w", err)
	}
	connectTimeout, err := time.ParseDuration(guestConfig.ConnectTimeout)
	if err != nil || connectTimeout <= 0 {
		return fmt.Errorf("guest status error: invalid configured guest connect timeout %q", guestConfig.ConnectTimeout)
	}
	runner, err := guest.NewSSHRunner(guest.SSHOptions{ConnectTimeout: connectTimeout, KnownHosts: guestConfig.KnownHosts})
	if err != nil {
		return fmt.Errorf("guest status error: %w", err)
	}
	return runGuestStatusWithRunner(context.Background(), *vm, guestConfig, serviceRefs, runner, w)
}

func runGuestStatusWithRunner(ctx context.Context, vm inventory.VM, guestConfig solisconfig.GuestObservabilityConfig, serviceRefs []string, runner guest.Runner, w io.Writer) error {
	target, err := guest.TargetForVM(vm, guestConfig.User)
	if err != nil {
		return fmt.Errorf("guest status error: %w", err)
	}
	status, err := guest.Collect(ctx, runner, target, vm, guest.CollectOptions{
		CommandTimeout: 10 * time.Second, ServiceRefs: serviceRefs, Now: time.Now,
	})
	if err != nil {
		return fmt.Errorf("guest status error: %w", err)
	}
	if err := observability.WriteGuestStatus(w, status); err != nil {
		return fmt.Errorf("guest status error: %w", err)
	}
	return nil
}

func runServiceStatus(runtimeConfig solisconfig.Runtime, name string, w io.Writer) error {
	vm, guestConfig, _, err := loadGuestTarget(runtimeConfig, name)
	if err != nil {
		return fmt.Errorf("service status error: %w", err)
	}
	services := configuredServicesForVM(runtimeConfig.Settings.EffectiveObservability().Services, name)
	if len(services) == 0 {
		return fmt.Errorf("service status error: no services configured for VM: %s", name)
	}
	connectTimeout, err := time.ParseDuration(guestConfig.ConnectTimeout)
	if err != nil || connectTimeout <= 0 {
		return fmt.Errorf("service status error: invalid configured guest connect timeout %q", guestConfig.ConnectTimeout)
	}
	runner, err := guest.NewSSHRunner(guest.SSHOptions{ConnectTimeout: connectTimeout, KnownHosts: guestConfig.KnownHosts})
	if err != nil {
		return fmt.Errorf("service status error: %w", err)
	}
	return runServiceStatusWithRunner(context.Background(), *vm, guestConfig, services, runner, w)
}

func runServiceStatusWithRunner(ctx context.Context, vm inventory.VM, guestConfig solisconfig.GuestObservabilityConfig, services []solisconfig.ServiceObservabilityConfig, runner guest.Runner, w io.Writer) error {
	target, err := guest.TargetForVM(vm, guestConfig.User)
	if err != nil {
		return fmt.Errorf("service status error: %w", err)
	}
	connectTimeout, err := time.ParseDuration(guestConfig.ConnectTimeout)
	if err != nil || connectTimeout <= 0 {
		return fmt.Errorf("service status error: invalid configured guest connect timeout %q", guestConfig.ConnectTimeout)
	}
	report, err := servicehealth.Collect(ctx, runner, target, vm, services, servicehealth.Options{
		CommandTimeout: 10 * time.Second, HealthTimeout: connectTimeout, Now: time.Now,
	})
	if err != nil {
		return fmt.Errorf("service status error: %w", err)
	}
	if err := servicehealth.WriteJSON(w, report); err != nil {
		return fmt.Errorf("service status error: %w", err)
	}
	return nil
}

func runDBStatus(runtimeConfig solisconfig.Runtime, name string, w io.Writer) error {
	vm, guestConfig, database, err := loadDatabaseTarget(runtimeConfig, name)
	if err != nil {
		return fmt.Errorf("db status error: %w", err)
	}
	connectTimeout, err := time.ParseDuration(guestConfig.ConnectTimeout)
	if err != nil || connectTimeout <= 0 {
		return fmt.Errorf("db status error: database collection requires a positive observability.guest.connect_timeout")
	}
	if strings.TrimSpace(guestConfig.Transport) != "ssh" || strings.TrimSpace(guestConfig.User) == "" || strings.TrimSpace(guestConfig.KnownHosts) == "" {
		return errors.New("db status error: database collection requires configured observability.guest SSH user and known_hosts")
	}
	runner, err := guest.NewSSHRunner(guest.SSHOptions{ConnectTimeout: connectTimeout, KnownHosts: guestConfig.KnownHosts})
	if err != nil {
		return fmt.Errorf("db status error: %w", err)
	}
	return runDBStatusWithRunner(context.Background(), *vm, guestConfig, database, runner, w)
}

func runDBStatusWithRunner(ctx context.Context, vm inventory.VM, guestConfig solisconfig.GuestObservabilityConfig, database solisconfig.DatabaseObservabilityConfig, runner guest.Runner, w io.Writer) error {
	target, err := guest.TargetForVM(vm, guestConfig.User)
	if err != nil {
		return fmt.Errorf("db status error: %w", err)
	}
	status, err := dbstats.Collect(ctx, runner, target, vm, database, dbstats.Options{CommandTimeout: 10 * time.Second, Now: time.Now})
	if err != nil {
		return fmt.Errorf("db status error: %w", err)
	}
	if err := dbstats.WriteJSON(w, status); err != nil {
		return fmt.Errorf("db status error: %w", err)
	}
	return nil
}

func runObserveSnapshot(runtimeConfig solisconfig.Runtime, options observeSnapshotOptions, w io.Writer) error {
	snapshot, err := collectObserveSnapshot(context.Background(), runtimeConfig, options)
	if err != nil {
		return err
	}
	if err := observe.WriteJSON(w, snapshot); err != nil {
		return fmt.Errorf("observe snapshot error: %w", err)
	}
	return nil
}

func collectObserveSnapshot(ctx context.Context, runtimeConfig solisconfig.Runtime, options observeSnapshotOptions) (observe.ObserveSnapshot, error) {
	vms, err := inventory.LoadFromConfig(runtimeConfig.Settings.InventoryCSV)
	if err != nil {
		return observe.ObserveSnapshot{}, fmt.Errorf("observe snapshot error: %w", err)
	}
	names := make([]string, len(vms))
	for index := range vms {
		names[index] = vms[index].Name
	}
	if err := solisconfig.ValidateWithInventory(runtimeConfig.Settings, names); err != nil {
		return observe.ObserveSnapshot{}, fmt.Errorf("observe snapshot error: %w", err)
	}
	if _, ok := inventory.FindByName(vms, options.Victim); !ok {
		return observe.ObserveSnapshot{}, fmt.Errorf("observe snapshot error: victim VM not found: %s", options.Victim)
	}
	if options.Suspect != "" {
		if _, ok := inventory.FindByName(vms, options.Suspect); !ok {
			return observe.ObserveSnapshot{}, fmt.Errorf("observe snapshot error: suspect VM not found: %s", options.Suspect)
		}
	}

	// Observe snapshots deliberately skip QEMU command-line discovery. Inventory
	// runtime identity is limited to libvirt state, PID, disk, and lease metadata.
	vms = inventory.EnrichWithOptions(vms, privacySafeEnrichOptions(runtimeConfig))
	observabilityConfig := runtimeConfig.Settings.EffectiveObservability()
	serviceConfigured := make(map[string]bool)
	for _, service := range observabilityConfig.Services {
		serviceConfigured[service.VM] = true
	}
	databaseConfigured := make(map[string]bool)
	for _, database := range observabilityConfig.Databases {
		databaseConfigured[database.VM] = true
	}
	includeGuest := options.IncludeGuest || observabilityConfig.Guest.Enabled
	includeServices := options.IncludeServices || len(observabilityConfig.Services) > 0
	includeDB := options.IncludeDB || len(observabilityConfig.Databases) > 0

	runner, runnerErr := observeGuestRunner(observabilityConfig.Guest)
	dependencies := observe.Dependencies{
		Now: time.Now,
		Host: func(_ context.Context, windowID string) (hostmetrics.HostStatus, error) {
			hostOptions, err := hostStatusOptions(runtimeConfig.Settings)
			if err != nil {
				return hostmetrics.HostStatus{}, err
			}
			hostOptions.Interval = options.Interval
			hostOptions.WindowID = windowID
			return hostmetrics.Collect(hostOptions)
		},
		QEMU: func(_ context.Context, plan qemuio.Plan, duration, interval time.Duration) (qemuio.SummaryReport, error) {
			return qemuio.CollectSummaryWithThresholds(plan, duration, interval, runtimeConfig.Settings.Thresholds)
		},
		Storage: hoststorage.Resolve,
		Discovery: func(enriched []inventory.VM, victim string, sampled qemuio.SummaryReport) (discovery.Report, error) {
			targets, err := discovery.Resolve(enriched, victim)
			if err != nil {
				return discovery.Report{}, err
			}
			return discovery.Analyze(targets, sampled), nil
		},
	}
	dependencies.Guest = func(ctx context.Context, vm inventory.VM, windowID string) (observability.GuestStatus, error) {
		if runnerErr != nil {
			return observability.GuestStatus{}, runnerErr
		}
		target, err := guest.TargetForVM(vm, observabilityConfig.Guest.User)
		if err != nil {
			return observability.GuestStatus{}, err
		}
		refs := configuredServiceRefs(observabilityConfig.Services, vm.Name)
		return guest.Collect(ctx, runner, target, vm, guest.CollectOptions{
			CommandTimeout: 10 * time.Second, WindowID: windowID, ServiceRefs: refs, Now: time.Now,
		})
	}
	dependencies.Service = func(ctx context.Context, vm inventory.VM, windowID string) (servicehealth.Report, error) {
		if runnerErr != nil {
			return servicehealth.Report{}, runnerErr
		}
		target, err := guest.TargetForVM(vm, observabilityConfig.Guest.User)
		if err != nil {
			return servicehealth.Report{}, err
		}
		connectTimeout, err := configuredGuestTimeout(observabilityConfig.Guest)
		if err != nil {
			return servicehealth.Report{}, err
		}
		return servicehealth.Collect(ctx, runner, target, vm, configuredServicesForVM(observabilityConfig.Services, vm.Name), servicehealth.Options{
			CommandTimeout: 10 * time.Second, HealthTimeout: connectTimeout, WindowID: windowID, Now: time.Now,
		})
	}
	dependencies.Database = func(ctx context.Context, vm inventory.VM, windowID string) (observability.DBStatus, error) {
		if runnerErr != nil {
			return observability.DBStatus{}, runnerErr
		}
		database, err := configuredDatabaseForVM(observabilityConfig.Databases, vm.Name)
		if err != nil {
			return observability.DBStatus{}, err
		}
		target, err := guest.TargetForVM(vm, observabilityConfig.Guest.User)
		if err != nil {
			return observability.DBStatus{}, err
		}
		return dbstats.Collect(ctx, runner, target, vm, database, dbstats.Options{
			CommandTimeout: 10 * time.Second, WindowID: windowID, Now: time.Now,
		})
	}

	snapshot, err := observe.Collect(ctx, observe.Request{
		Victim: options.Victim, Suspect: options.Suspect, DiscoverSuspects: options.DiscoverSuspects,
		Duration: options.Duration, Interval: options.Interval, ConfigSource: runtimeConfig.Source,
		IncludeGuest: includeGuest, IncludeServices: includeServices, IncludeDB: includeDB,
		IncludeEBPFLatency: options.IncludeEBPFLatency, GuestEnabled: observabilityConfig.Guest.Enabled,
		ServiceConfigured: serviceConfigured, DatabaseConfigured: databaseConfigured,
		EBPFVMAttribution: options.EBPFVMAttribution, EBPFSourceWindow: options.EBPFSourceWindow,
	}, vms, dependencies)
	if err != nil {
		return observe.ObserveSnapshot{}, fmt.Errorf("observe snapshot error: %w", err)
	}
	return snapshot, nil
}

func runObserveWatch(runtimeConfig solisconfig.Runtime, options observeWatchOptions, stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	output := stdout
	summary := observe.WatchSummary{}
	var outputFile *os.File
	if options.OutputDirectory != "" {
		path, file, err := openObserveWatchOutput(options.OutputDirectory, options.Victim, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("observe watch error: %w", err)
		}
		outputFile = file
		output = io.MultiWriter(stdout, outputFile)
		summary.OutputPath = path
	}

	err := observe.Watch(ctx, output, observe.WatchOptions{Every: options.Every, Iterations: options.Iterations}, func(iterationContext context.Context) (observe.ObserveSnapshot, error) {
		return collectObserveSnapshot(iterationContext, runtimeConfig, options.observeSnapshotOptions)
	}, &summary)
	if outputFile != nil {
		if closeErr := outputFile.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		outputFile = nil
	}
	if summaryErr := observe.WriteWatchSummary(stderr, summary); err == nil && summaryErr != nil {
		err = summaryErr
	}
	if err != nil {
		return fmt.Errorf("observe watch error: %w", err)
	}
	return nil
}

func openObserveWatchOutput(directory, victim string, now time.Time) (string, *os.File, error) {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", nil, fmt.Errorf("create observe watch output directory %q: %w", directory, err)
	}
	name := fmt.Sprintf("observe-watch-%s-%s.jsonl", diagnose.FormatUTCTimestamp(now), diagnose.SanitizeFilenamePart(victim))
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", nil, fmt.Errorf("create observe watch output %q: %w", path, err)
	}
	return path, file, nil
}

func observeGuestRunner(configuration solisconfig.GuestObservabilityConfig) (guest.Runner, error) {
	if strings.TrimSpace(configuration.Transport) != "ssh" {
		return nil, errors.New("observability guest SSH transport is not configured")
	}
	if strings.TrimSpace(configuration.User) == "" || strings.TrimSpace(configuration.KnownHosts) == "" {
		return nil, errors.New("observability guest SSH user and known_hosts are required")
	}
	timeout, err := configuredGuestTimeout(configuration)
	if err != nil {
		return nil, err
	}
	return guest.NewSSHRunner(guest.SSHOptions{ConnectTimeout: timeout, KnownHosts: configuration.KnownHosts})
}

func privacySafeEnrichOptions(runtimeConfig solisconfig.Runtime) inventory.EnrichOptions {
	return inventory.EnrichOptions{LibvirtURI: runtimeConfig.Settings.LibvirtURI, SkipQEMUProcessArguments: true}
}

func configuredGuestTimeout(configuration solisconfig.GuestObservabilityConfig) (time.Duration, error) {
	timeout, err := time.ParseDuration(strings.TrimSpace(configuration.ConnectTimeout))
	if err != nil || timeout <= 0 {
		return 0, fmt.Errorf("invalid configured guest connect timeout %q", configuration.ConnectTimeout)
	}
	return timeout, nil
}

func configuredServiceRefs(services []solisconfig.ServiceObservabilityConfig, name string) []string {
	configured := configuredServicesForVM(services, name)
	refs := make([]string, 0, len(configured))
	for _, service := range configured {
		identity := strings.TrimSpace(service.ID)
		if identity == "" {
			identity = service.VM
		}
		refs = append(refs, identity)
	}
	sort.Strings(refs)
	return refs
}

func configuredDatabaseForVM(databases []solisconfig.DatabaseObservabilityConfig, name string) (solisconfig.DatabaseObservabilityConfig, error) {
	configured := make([]solisconfig.DatabaseObservabilityConfig, 0, 1)
	for _, database := range databases {
		if database.VM == name {
			configured = append(configured, database)
		}
	}
	if len(configured) == 0 {
		return solisconfig.DatabaseObservabilityConfig{}, fmt.Errorf("no database configured for VM: %s", name)
	}
	if len(configured) > 1 {
		return solisconfig.DatabaseObservabilityConfig{}, fmt.Errorf("multiple databases configured for VM %s; observe snapshot currently requires exactly one", name)
	}
	if configured[0].Kind != "postgresql" {
		return solisconfig.DatabaseObservabilityConfig{}, fmt.Errorf("unsupported database kind %q; supported kind is postgresql", configured[0].Kind)
	}
	return configured[0], nil
}

func loadDatabaseTarget(runtimeConfig solisconfig.Runtime, name string) (*inventory.VM, solisconfig.GuestObservabilityConfig, solisconfig.DatabaseObservabilityConfig, error) {
	vms, err := inventory.LoadFromConfig(runtimeConfig.Settings.InventoryCSV)
	if err != nil {
		return nil, solisconfig.GuestObservabilityConfig{}, solisconfig.DatabaseObservabilityConfig{}, err
	}
	names := make([]string, len(vms))
	for index := range vms {
		names[index] = vms[index].Name
	}
	if err := solisconfig.ValidateWithInventory(runtimeConfig.Settings, names); err != nil {
		return nil, solisconfig.GuestObservabilityConfig{}, solisconfig.DatabaseObservabilityConfig{}, err
	}
	vm, ok := inventory.FindByName(vms, name)
	if !ok {
		return nil, solisconfig.GuestObservabilityConfig{}, solisconfig.DatabaseObservabilityConfig{}, fmt.Errorf("VM not found: %s", name)
	}
	observabilityConfig := runtimeConfig.Settings.EffectiveObservability()
	configured := make([]solisconfig.DatabaseObservabilityConfig, 0, 1)
	for _, database := range observabilityConfig.Databases {
		if database.VM == name {
			configured = append(configured, database)
		}
	}
	if len(configured) == 0 {
		return nil, solisconfig.GuestObservabilityConfig{}, solisconfig.DatabaseObservabilityConfig{}, fmt.Errorf("no database configured for VM: %s", name)
	}
	if len(configured) > 1 {
		return nil, solisconfig.GuestObservabilityConfig{}, solisconfig.DatabaseObservabilityConfig{}, fmt.Errorf("multiple databases configured for VM %s; db status currently requires exactly one", name)
	}
	if configured[0].Kind != "postgresql" {
		return nil, solisconfig.GuestObservabilityConfig{}, solisconfig.DatabaseObservabilityConfig{}, fmt.Errorf("unsupported database kind %q; supported kind is postgresql", configured[0].Kind)
	}
	return vm, observabilityConfig.Guest, configured[0], nil
}

func loadGuestTarget(runtimeConfig solisconfig.Runtime, name string) (*inventory.VM, solisconfig.GuestObservabilityConfig, []string, error) {
	observabilityConfig := runtimeConfig.Settings.EffectiveObservability()
	if !observabilityConfig.Guest.Enabled {
		return nil, solisconfig.GuestObservabilityConfig{}, nil, errors.New("guest collection is disabled in configuration")
	}
	vms, err := inventory.LoadFromConfig(runtimeConfig.Settings.InventoryCSV)
	if err != nil {
		return nil, solisconfig.GuestObservabilityConfig{}, nil, err
	}
	names := make([]string, len(vms))
	for index := range vms {
		names[index] = vms[index].Name
	}
	if err := solisconfig.ValidateWithInventory(runtimeConfig.Settings, names); err != nil {
		return nil, solisconfig.GuestObservabilityConfig{}, nil, err
	}
	vm, ok := inventory.FindByName(vms, name)
	if !ok {
		return nil, solisconfig.GuestObservabilityConfig{}, nil, fmt.Errorf("VM not found: %s", name)
	}
	services := configuredServicesForVM(observabilityConfig.Services, name)
	refs := make([]string, 0, len(services))
	for _, service := range services {
		identity := strings.TrimSpace(service.ID)
		if identity == "" {
			identity = service.VM
		}
		refs = append(refs, identity)
	}
	sort.Strings(refs)
	return vm, observabilityConfig.Guest, refs, nil
}

func configuredServicesForVM(services []solisconfig.ServiceObservabilityConfig, name string) []solisconfig.ServiceObservabilityConfig {
	selected := make([]solisconfig.ServiceObservabilityConfig, 0)
	for _, service := range services {
		if service.VM == name {
			selected = append(selected, service)
		}
	}
	sort.Slice(selected, func(i, j int) bool {
		left, right := strings.TrimSpace(selected[i].ID), strings.TrimSpace(selected[j].ID)
		if left == "" {
			left = selected[i].VM
		}
		if right == "" {
			right = selected[j].VM
		}
		return left < right
	})
	return selected
}

func hostStatusOptions(settings solisconfig.Settings) (hostmetrics.Options, error) {
	options := hostmetrics.DefaultOptions()
	if settings.Observability == nil {
		return options, nil
	}
	host := settings.Observability.Host
	options.CollectPSI = host.CollectPSI
	options.CollectNetwork = host.CollectNetwork
	if strings.TrimSpace(host.Interval) == "" {
		return options, nil
	}
	interval, err := time.ParseDuration(host.Interval)
	if err != nil || interval <= 0 {
		return hostmetrics.Options{}, fmt.Errorf("invalid configured host interval %q", host.Interval)
	}
	options.Interval = interval
	return options, nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Solis I/O

Usage:
  solis [--config <path>] <command> [options]

Commands:
  solis version [--json]
  solis doctor [--lab]
  solis ebpf doctor
  solis ebpf block-watch [--duration <duration>]
  solis ebpf block-events --duration <duration>
  solis ebpf block-count --duration <duration>
  solis ebpf block-latency [--victim <vm> --suspect <vm>] --duration <duration>
  solis ebpf vm-block-latency [--duration <duration>] [--interval <duration>] [--device <name>] [--victim <vm>] [--suspect <vm>] [--all-vms] [--output <path>] --json
  solis inventory
  solis host status --json
  solis guest status --vm <name> --json
  solis service status --vm <name> --json
  solis db status --vm <name> --json
  solis observe snapshot --victim <vm> [--suspect <vm> | --discover-suspects] [--duration <duration>] [--interval <duration>] [--include-guest] [--include-services] [--include-db] [--include-ebpf-latency] --json
  solis observe watch --victim <vm> [--suspect <vm> | --discover-suspects] [--duration <duration>] [--interval <duration>] [--every <duration>] [--iterations <n>] [--include-guest] [--include-services] [--include-db] [--include-ebpf-latency] [--output-dir <dir>] --json
  solis status [--duration <duration>] [--interval <duration>] [--json] [--watch] [--every <duration>] [--iterations <n>] [--clear | --no-clear] [--sort <field>]
  solis top [--duration <duration>] [--interval <duration>] [--every <duration>] [--iterations <n>] [--include-ebpf-latency] [--clear | --no-clear] [--sort <field>]
  solis inspect <vm> [--verbose]
  solis experiment summarize <report-dir>
  solis incidents explain <report-dir> --victim <name> --suspect <name>
  solis trace plan --victim <name> --suspect <name>
  solis storage snapshot --victim <name> --suspect <name>
  solis storage watch --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]
  solis vm storage-stats [--victim <vm>] [--suspect <vm>] [--all-vms] [--duration <duration>] [--interval <duration>] [--output <path>] --json
  solis qemu io-watch --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]
  solis qemu io-summary --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]
  solis diagnose noisy-neighbor [--report-dir <dir>] --victim <vm> (--suspect <vm> | --discover-suspects) [--duration <duration>] [--interval <duration>] [--include-ebpf-latency] [--json] [--output <path> | --output-dir <dir>]
  solis capture noisy-neighbor [--report-dir <dir>] --victim <vm> (--suspect <vm> | --discover-suspects) [--duration <duration>] [--interval <duration>] [--include-ebpf-latency] --output-dir <dir>
  solis watch noisy-neighbor --victim <vm> (--suspect <vm> | --discover-suspects) [--window <duration>] [--every <duration>] [--iterations <n>] [--include-ebpf-latency] [--capture-on-alert] [--cooldown <duration>] [--output-dir <dir>] [--verbose]

Configuration precedence:
  --config <path> > SOLIS_CONFIG > built-in development defaults

Solis I/O is a Linux-only provider-side KVM storage latency attribution tool.`)
}
