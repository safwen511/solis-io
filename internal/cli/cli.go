package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/safwen511/solis-io/internal/experiment"
	"github.com/safwen511/solis-io/internal/incident"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/output"
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

func parseIncidentExplainArgs(args []string) (string, string, string, error) {
	if len(args) < 3 || args[1] != "explain" || strings.HasPrefix(args[2], "--") {
		return "", "", "", errors.New(incidentExplainUsage)
	}

	reportDir := args[2]
	var victim, suspect string
	for i := 3; i < len(args); {
		option := args[i]
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return "", "", "", fmt.Errorf("%s: %s requires a value", incidentExplainUsage, option)
		}

		value := args[i+1]
		switch option {
		case "--victim":
			if victim != "" {
				return "", "", "", fmt.Errorf("%s: --victim specified more than once", incidentExplainUsage)
			}
			victim = value
		case "--suspect":
			if suspect != "" {
				return "", "", "", fmt.Errorf("%s: --suspect specified more than once", incidentExplainUsage)
			}
			suspect = value
		default:
			return "", "", "", fmt.Errorf("%s: unknown option %s", incidentExplainUsage, option)
		}
		i += 2
	}

	if victim == "" {
		return "", "", "", fmt.Errorf("%s: missing --victim", incidentExplainUsage)
	}
	if suspect == "" {
		return "", "", "", fmt.Errorf("%s: missing --suspect", incidentExplainUsage)
	}

	return reportDir, victim, suspect, nil
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

Solis I/O is a Linux-only provider-side KVM storage latency attribution tool.`)
}
