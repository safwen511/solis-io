package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/experiment"
	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/incident"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/output"
	"github.com/safwen511/solis-io/internal/storage"
	"github.com/safwen511/solis-io/internal/traceplan"
)

const defaultConfigPath = "lab/config/vms.csv"

// Run executes the requested Solis command.
func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}

	switch args[0] {
	case "doctor":
		fmt.Fprintln(stdout, "solis doctor: compatibility checks will be implemented here")
		return nil
	case "inventory":
		return runInventory(stdout)
	case "top":
		fmt.Fprintln(stdout, "solis top: live VM I/O view will be implemented here")
		return nil
	case "trace":
		victim, suspect, err := parseTracePlanArgs(args)
		if err != nil {
			return err
		}
		return runTracePlan(victim, suspect, stdout)
	case "storage":
		return runStorageCommand(args, stdout)
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
		return runInspect(args[1], verbose, stdout)
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

const incidentExplainUsage = "usage: solis incidents explain <report-dir> --victim <name> --suspect <name>"
const tracePlanUsage = "usage: solis trace plan --victim <name> --suspect <name>"
const storageSnapshotUsage = "usage: solis storage snapshot --victim <name> --suspect <name>"
const storageWatchUsage = "usage: solis storage watch --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]"

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

	duration := 30 * time.Second
	interval := 5 * time.Second
	var victim, suspect string
	var durationSet, intervalSet bool
	for i := 2; i < len(args); {
		option := args[i]
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return "", "", 0, 0, fmt.Errorf("%s: %s requires a value", storageWatchUsage, option)
		}
		value := args[i+1]

		switch option {
		case "--victim":
			if victim != "" {
				return "", "", 0, 0, fmt.Errorf("%s: --victim specified more than once", storageWatchUsage)
			}
			victim = value
		case "--suspect":
			if suspect != "" {
				return "", "", 0, 0, fmt.Errorf("%s: --suspect specified more than once", storageWatchUsage)
			}
			suspect = value
		case "--duration":
			if durationSet {
				return "", "", 0, 0, fmt.Errorf("%s: --duration specified more than once", storageWatchUsage)
			}
			parsed, err := time.ParseDuration(value)
			if err != nil || parsed <= 0 {
				return "", "", 0, 0, fmt.Errorf("%s: invalid --duration %q", storageWatchUsage, value)
			}
			duration = parsed
			durationSet = true
		case "--interval":
			if intervalSet {
				return "", "", 0, 0, fmt.Errorf("%s: --interval specified more than once", storageWatchUsage)
			}
			parsed, err := time.ParseDuration(value)
			if err != nil || parsed <= 0 {
				return "", "", 0, 0, fmt.Errorf("%s: invalid --interval %q", storageWatchUsage, value)
			}
			interval = parsed
			intervalSet = true
		default:
			return "", "", 0, 0, fmt.Errorf("%s: unknown option %s", storageWatchUsage, option)
		}
		i += 2
	}

	if victim == "" {
		return "", "", 0, 0, fmt.Errorf("%s: missing --victim", storageWatchUsage)
	}
	if suspect == "" {
		return "", "", 0, 0, fmt.Errorf("%s: missing --suspect", storageWatchUsage)
	}
	if interval > duration {
		return "", "", 0, 0, fmt.Errorf("storage watch interval %s cannot exceed duration %s", interval, duration)
	}

	return victim, suspect, duration, interval, nil
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

func runTracePlan(victim, suspect string, w io.Writer) error {
	plan, err := loadEnrichedTargetPlan(victim, suspect)
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

func runStorageSnapshot(victim, suspect string, w io.Writer) error {
	plan, err := loadEnrichedTargetPlan(victim, suspect)
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

func runStorageCommand(args []string, w io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: solis storage snapshot|watch [options]")
	}

	switch args[1] {
	case "snapshot":
		victim, suspect, err := parseStorageSnapshotArgs(args)
		if err != nil {
			return err
		}
		return runStorageSnapshot(victim, suspect, w)
	case "watch":
		victim, suspect, duration, interval, err := parseStorageWatchArgs(args)
		if err != nil {
			return err
		}
		return runStorageWatch(victim, suspect, duration, interval, w)
	default:
		return fmt.Errorf("unknown storage command %q; expected snapshot or watch", args[1])
	}
}

func runStorageWatch(victim, suspect string, duration, interval time.Duration, w io.Writer) error {
	plan, err := loadEnrichedTargetPlan(victim, suspect)
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

func loadEnrichedTargetPlan(victim, suspect string) (traceplan.Plan, error) {
	vms, err := inventory.LoadFromConfig(defaultConfigPath)
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
	targets = inventory.Enrich(targets)

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

func runInventory(w io.Writer) error {
	vms, err := inventory.LoadFromConfig(defaultConfigPath)
	if err != nil {
		return fmt.Errorf("inventory error: %w", err)
	}

	return output.InventoryTable(w, inventory.Enrich(vms))
}

func runInspect(name string, verbose bool, w io.Writer) error {
	vms, err := inventory.LoadFromConfig(defaultConfigPath)
	if err != nil {
		return fmt.Errorf("inspect error: %w", err)
	}

	vms = inventory.Enrich(vms)
	vm, ok := inventory.FindByName(vms, name)
	if !ok {
		return fmt.Errorf("VM not found: %s", name)
	}

	return output.VMDetail(w, *vm, verbose)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Solis I/O

Usage:
  solis doctor
  solis inventory
  solis top
  solis inspect <vm> [--verbose]
  solis experiment summarize <report-dir>
  solis incidents explain <report-dir> --victim <name> --suspect <name>
  solis trace plan --victim <name> --suspect <name>
  solis storage snapshot --victim <name> --suspect <name>
  solis storage watch --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]

Solis I/O is a Linux-only provider-side KVM storage latency attribution tool.`)
}
