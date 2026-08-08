package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/capture"
	"github.com/safwen511/solis-io/internal/diagnose"
	"github.com/safwen511/solis-io/internal/doctor"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/experiment"
	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/incident"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/output"
	"github.com/safwen511/solis-io/internal/qemuio"
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
		return runDoctor(stdout)
	case "ebpf":
		return runEBPFCommand(args, stdout)
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
	case "qemu":
		return runQEMUCommand(args, stdout)
	case "diagnose":
		return runDiagnoseCommand(args, stdout)
	case "capture":
		return runCaptureCommand(args, stdout)
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
const qemuIOWatchUsage = "usage: solis qemu io-watch --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]"
const qemuIOSummaryUsage = "usage: solis qemu io-summary --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]"
const diagnoseNoisyNeighborUsage = "usage: solis diagnose noisy-neighbor --report-dir <dir> --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>] [--output <path> | --output-dir <dir>]"
const captureNoisyNeighborUsage = "usage: solis capture noisy-neighbor --report-dir <dir> --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>] --output-dir <dir>"
const ebpfUsage = "usage: solis ebpf doctor | solis ebpf block-watch [--duration <duration>] | solis ebpf block-events --duration <duration> | solis ebpf block-count --duration <duration> | solis ebpf block-latency --duration <duration>"
const ebpfBlockWatchUsage = "usage: solis ebpf block-watch [--duration <duration>]"
const ebpfBlockEventsUsage = "usage: solis ebpf block-events --duration <duration>"
const ebpfBlockCountUsage = "usage: solis ebpf block-count --duration <duration>"
const ebpfBlockLatencyUsage = "usage: solis ebpf block-latency --duration <duration>"

type timedTargetOptions struct {
	ReportDirectory string
	Victim          string
	Suspect         string
	Duration        time.Duration
	Interval        time.Duration
	OutputPath      string
	OutputDirectory string
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

func parseTimedTargetOptions(
	args []string,
	start int,
	usage string,
	commandName string,
	defaultDuration time.Duration,
	defaultInterval time.Duration,
	allowReportDirectory bool,
	allowOutputOptions bool,
) (timedTargetOptions, error) {
	options := timedTargetOptions{Duration: defaultDuration, Interval: defaultInterval}
	var durationSet, intervalSet, outputSet, outputDirectorySet bool
	for i := start; i < len(args); {
		option := args[i]
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

	if allowReportDirectory && options.ReportDirectory == "" {
		return timedTargetOptions{}, fmt.Errorf("%s: missing --report-dir", usage)
	}
	if options.Victim == "" {
		return timedTargetOptions{}, fmt.Errorf("%s: missing --victim", usage)
	}
	if options.Suspect == "" {
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

func runQEMUCommand(args []string, w io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: solis qemu io-watch|io-summary [options]")
	}

	switch args[1] {
	case "io-watch":
		victim, suspect, duration, interval, err := parseQEMUIOWatchArgs(args)
		if err != nil {
			return err
		}
		return runQEMUIOWatch(victim, suspect, duration, interval, w)
	case "io-summary":
		victim, suspect, duration, interval, err := parseQEMUIOSummaryArgs(args)
		if err != nil {
			return err
		}
		return runQEMUIOSummary(victim, suspect, duration, interval, w)
	default:
		return fmt.Errorf("unknown qemu command %q; expected io-watch or io-summary", args[1])
	}
}

func runQEMUIOWatch(victim, suspect string, duration, interval time.Duration, w io.Writer) error {
	plan, err := loadEnrichedTargetPlan(victim, suspect)
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

func runQEMUIOSummary(victim, suspect string, duration, interval time.Duration, w io.Writer) error {
	plan, err := loadEnrichedTargetPlan(victim, suspect)
	if err != nil {
		return fmt.Errorf("qemu io-summary error: %w", err)
	}

	watchPlan := qemuio.NewPlan(
		plan.VictimSelector,
		plan.SuspectSelector,
		plan.VictimTargets,
		plan.SuspectTarget,
	)
	report, err := qemuio.CollectSummary(watchPlan, duration, interval)
	if err != nil {
		return fmt.Errorf("qemu io-summary error: %w", err)
	}
	if err := qemuio.WriteSummary(w, report); err != nil {
		return fmt.Errorf("qemu io-summary error: %w", err)
	}
	return nil
}

func runDiagnoseCommand(args []string, w io.Writer) error {
	options, err := parseDiagnoseNoisyNeighborArgs(args)
	if err != nil {
		return err
	}
	return runNoisyNeighborDiagnosis(options, w)
}

type noisyNeighborEvidence struct {
	Experiment experiment.Report
	Incident   incident.Explanation
	TracePlan  traceplan.Plan
	Storage    storage.Snapshot
	QEMU       qemuio.SummaryReport
	Diagnosis  diagnose.Report
}

func runNoisyNeighborDiagnosis(options timedTargetOptions, w io.Writer) error {
	evidence, err := collectNoisyNeighborEvidence(options)
	if err != nil {
		return fmt.Errorf("diagnose noisy-neighbor error: %w", err)
	}
	if _, err := diagnose.WriteOutput(
		w,
		evidence.Diagnosis,
		diagnose.OutputOptions{
			Path:      options.OutputPath,
			Directory: options.OutputDirectory,
		},
		time.Now(),
	); err != nil {
		return fmt.Errorf("diagnose noisy-neighbor error: %w", err)
	}
	return nil
}

func runCaptureCommand(args []string, w io.Writer) error {
	options, err := parseCaptureNoisyNeighborArgs(args)
	if err != nil {
		return err
	}
	evidence, err := collectNoisyNeighborEvidence(options)
	if err != nil {
		return fmt.Errorf("capture noisy-neighbor error: %w", err)
	}

	result, err := capture.Write(
		capture.Inputs{
			OutputDirectory: options.OutputDirectory,
			ReportDirectory: evidence.Experiment.Directory,
			Victim:          options.Victim,
			Suspect:         options.Suspect,
			Duration:        options.Duration,
			Interval:        options.Interval,
		},
		capture.Evidence{
			Experiment: evidence.Experiment,
			Incident:   evidence.Incident,
			TracePlan:  evidence.TracePlan,
			Storage:    evidence.Storage,
			QEMU:       evidence.QEMU,
			Diagnosis:  evidence.Diagnosis,
		},
		time.Now(),
	)
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

func collectNoisyNeighborEvidence(options timedTargetOptions) (noisyNeighborEvidence, error) {
	experimentReport, err := experiment.Load(options.ReportDirectory)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}
	explanation, err := incident.NewExplanation(experimentReport, options.Victim, options.Suspect)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}

	plan, err := loadEnrichedTargetPlan(options.Victim, options.Suspect)
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
	qemuReport, err := qemuio.CollectSummary(qemuPlan, options.Duration, options.Interval)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}
	diagnosisReport, err := diagnose.NewReport(
		diagnose.Inputs{
			ReportDirectory: experimentReport.Directory,
			Victim:          options.Victim,
			Suspect:         options.Suspect,
			Duration:        options.Duration,
			Interval:        options.Interval,
		},
		experimentReport,
		storageSnapshot,
		qemuReport,
	)
	if err != nil {
		return noisyNeighborEvidence{}, err
	}

	return noisyNeighborEvidence{
		Experiment: experimentReport,
		Incident:   explanation,
		TracePlan:  plan,
		Storage:    storageSnapshot,
		QEMU:       qemuReport,
		Diagnosis:  diagnosisReport,
	}, nil
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

func runDoctor(w io.Writer) error {
	if err := doctor.Write(w, doctor.Run(".")); err != nil {
		return fmt.Errorf("doctor error: %w", err)
	}
	return nil
}

func runEBPFCommand(args []string, w io.Writer) error {
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
		duration, err := parseRequiredEBPFDuration(args, "block-latency", ebpfBlockLatencyUsage)
		if err != nil {
			return err
		}
		result, err := ebpf.MeasureBlockLatency(duration)
		if err != nil {
			return fmt.Errorf("ebpf block-latency error: %w", err)
		}
		if err := ebpf.WriteBlockLatency(w, result); err != nil {
			return fmt.Errorf("ebpf block-latency error: %w", err)
		}
		return nil
	default:
		return errors.New(ebpfUsage)
	}
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
  solis ebpf doctor
  solis ebpf block-watch [--duration <duration>]
  solis ebpf block-events --duration <duration>
  solis ebpf block-count --duration <duration>
  solis ebpf block-latency --duration <duration>
  solis inventory
  solis top
  solis inspect <vm> [--verbose]
  solis experiment summarize <report-dir>
  solis incidents explain <report-dir> --victim <name> --suspect <name>
  solis trace plan --victim <name> --suspect <name>
  solis storage snapshot --victim <name> --suspect <name>
  solis storage watch --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]
  solis qemu io-watch --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]
  solis qemu io-summary --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>]
  solis diagnose noisy-neighbor --report-dir <dir> --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>] [--output <path> | --output-dir <dir>]
  solis capture noisy-neighbor --report-dir <dir> --victim <name> --suspect <name> [--duration <duration>] [--interval <duration>] --output-dir <dir>

Solis I/O is a Linux-only provider-side KVM storage latency attribution tool.`)
}
