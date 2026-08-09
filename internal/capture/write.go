package capture

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/diagnose"
	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/experiment"
	"github.com/safwen511/solis-io/internal/incident"
	"github.com/safwen511/solis-io/internal/observe"
	"github.com/safwen511/solis-io/internal/qemuio"
	"github.com/safwen511/solis-io/internal/storage"
	"github.com/safwen511/solis-io/internal/traceplan"
)

type artifact struct {
	name   string
	render func(io.Writer) error
}

// Write creates a timestamped capture directory containing all evidence files.
func Write(inputs Inputs, evidence Evidence, now time.Time) (Result, error) {
	if inputs.OutputDirectory == "" {
		return Result{}, fmt.Errorf("output directory must not be empty")
	}

	timestamp := diagnose.FormatUTCTimestamp(now)
	directory := filepath.Join(inputs.OutputDirectory, captureDirectoryName(now, inputs.Victim, inputs.Suspect))
	if err := os.MkdirAll(inputs.OutputDirectory, 0o755); err != nil {
		return Result{}, fmt.Errorf("create capture output directory %q: %w", inputs.OutputDirectory, err)
	}

	var artifacts []artifact
	if evidence.Diagnosis.ExperimentAvailable {
		artifacts = append(
			artifacts,
			artifact{"experiment-summary.txt", func(w io.Writer) error { return experiment.WriteSummary(w, evidence.Experiment) }},
			artifact{"incident-explanation.txt", func(w io.Writer) error { return incident.WriteExplanation(w, evidence.Incident) }},
		)
	} else {
		artifacts = append(
			artifacts,
			artifact{"experiment-summary.txt", writeLiveOnlyExperimentPlaceholder},
			artifact{"incident-explanation.txt", writeLiveOnlyIncidentPlaceholder},
		)
	}
	if evidence.Discovery != nil && evidence.Discovery.Selected == nil {
		artifacts = append(artifacts, artifact{
			"victim-topology.txt",
			func(w io.Writer) error { return discovery.WriteVictimTopology(w, *evidence.Discovery) },
		})
	} else {
		artifacts = append(artifacts, artifact{
			"trace-plan.txt",
			func(w io.Writer) error { return traceplan.Write(w, evidence.TracePlan) },
		})
	}
	artifacts = append(
		artifacts,
		artifact{"storage-snapshot.txt", func(w io.Writer) error { return storage.Write(w, evidence.Storage) }},
		artifact{"qemu-io-summary.txt", func(w io.Writer) error { return qemuio.WriteSummary(w, evidence.QEMU) }},
	)
	if evidence.Discovery != nil {
		artifacts = append(artifacts, artifact{
			"suspect-discovery.txt",
			func(w io.Writer) error { return discovery.Write(w, *evidence.Discovery) },
		})
	}
	if inputs.IncludeEBPFLatency {
		latencyEvidence := ebpf.BlockLatencyEvidence{UnavailableReason: "collector did not return eBPF block latency evidence"}
		if evidence.EBPFLatency != nil {
			latencyEvidence = *evidence.EBPFLatency
		}
		artifacts = append(artifacts, artifact{
			"ebpf-block-latency.txt",
			func(w io.Writer) error { return ebpf.WriteBlockLatencyEvidenceFile(w, latencyEvidence) },
		})
	}
	artifacts = append(artifacts, artifact{"observe-snapshot.json", func(w io.Writer) error {
		return writeObserveSnapshot(w, inputs, evidence, now)
	}})
	var generatedFiles []string
	artifacts = append(
		artifacts,
		artifact{"diagnosis.txt", func(w io.Writer) error { return diagnose.Write(w, evidence.Diagnosis) }},
		artifact{"evidence-summary.json", func(w io.Writer) error {
			return WriteEvidenceSummary(w, inputs, evidence, timestamp)
		}},
		artifact{"incident-report.md", func(w io.Writer) error {
			return WriteIncidentReport(w, inputs, evidence, timestamp, generatedFiles)
		}},
		artifact{"metadata.txt", func(w io.Writer) error { return WriteMetadata(w, inputs, timestamp) }},
	)
	generatedFiles = make([]string, 0, len(artifacts)+1)
	for _, artifact := range artifacts {
		generatedFiles = append(generatedFiles, artifact.name)
	}
	generatedFiles = append(generatedFiles, manifestFilename)

	return writeBundle(directory, filepath.Base(directory), now, artifacts)
}

func captureDirectoryName(now time.Time, victim, suspect string) string {
	return fmt.Sprintf(
		"capture-%s-%s-%s",
		diagnose.FormatUTCTimestamp(now),
		diagnose.SanitizeFilenamePart(victim),
		diagnose.SanitizeFilenamePart(suspect),
	)
}

// WriteMetadata emits deterministic metadata for one capture.
func WriteMetadata(dst io.Writer, inputs Inputs, timestamp string) error {
	mode := captureMode(inputs)
	discoveryFile := "-"
	if mode == "discover-suspects" {
		discoveryFile = "suspect-discovery.txt"
	}
	ebpfRequested := yesNo(inputs.IncludeEBPFLatency)
	ebpfWritten := yesNo(inputs.IncludeEBPFLatency)
	evidenceMode := captureEvidenceMode(inputs)
	thresholds := qemuio.EffectiveThresholds(inputs.Thresholds)
	if _, err := fmt.Fprintf(
		dst,
		"Solis Capture Metadata\n"+
			"Capture timestamp UTC: %s\n"+
			"Report directory: %s\n"+
			"Evidence mode: %s\n"+
			"Victim: %s\n"+
			"Suspect: %s\n"+
			"Duration: %s\n"+
			"Interval: %s\n"+
			"Config source: %s\n"+
			"Write threshold MiB/s: %.2f\n"+
			"Write syscall threshold/s: %.2f\n"+
			"Dominance ratio: %.2f\n"+
			"Solis command: %s\n"+
			"Capture mode: %s\n"+
			"Selected suspect: %s\n"+
			"eBPF latency requested: %s\n"+
			"eBPF latency file written: %s\n"+
			"Discovery file: %s\n"+
			"Incident report: incident-report.md\n"+
			"Evidence JSON: evidence-summary.json\n"+
			"Observe snapshot: observe-snapshot.json\n"+
			"Manifest: manifest.json\n",
		timestamp,
		valueOrDash(inputs.ReportDirectory),
		evidenceMode,
		inputs.Victim,
		inputs.Suspect,
		inputs.Duration,
		inputs.Interval,
		valueOrDash(inputs.ConfigSource),
		thresholds.WriteMiBPerSecond,
		thresholds.WriteSyscallsPerSecond,
		thresholds.DominanceRatio,
		commandName,
		mode,
		valueOrDash(inputs.Suspect),
		ebpfRequested,
		ebpfWritten,
		discoveryFile,
	); err != nil {
		return err
	}
	if inputs.IncludeEBPFLatency {
		_, err := fmt.Fprintln(dst, "eBPF block latency: ebpf-block-latency.txt (experimental; host/storage-path level)")
		return err
	}
	return nil
}

func writeObserveSnapshot(dst io.Writer, inputs Inputs, evidence Evidence, now time.Time) error {
	snapshot := evidence.ObserveSnapshot
	reason := strings.TrimSpace(evidence.ObserveError)
	if snapshot == nil {
		unavailable := observe.NewUnavailableSnapshot(
			inputs.Victim, inputs.Suspect, captureMode(inputs), inputs.Duration, inputs.Interval,
			inputs.ConfigSource, reason, now,
		)
		snapshot = &unavailable
	}
	data, err := observe.MarshalJSON(*snapshot)
	if err != nil {
		unavailable := observe.NewUnavailableSnapshot(
			inputs.Victim, inputs.Suspect, captureMode(inputs), inputs.Duration, inputs.Interval,
			inputs.ConfigSource, "observe snapshot rendering rejected: "+err.Error(), now,
		)
		data, err = observe.MarshalJSON(unavailable)
		if err != nil {
			return err
		}
	}
	_, err = dst.Write(append(data, '\n'))
	return err
}

func writeLiveOnlyExperimentPlaceholder(dst io.Writer) error {
	_, err := fmt.Fprintln(
		dst,
		"Experiment evidence\n"+
			"No report directory supplied.\n"+
			"Application-level slowdown evidence unavailable in this live-only run.",
	)
	return err
}

func writeLiveOnlyIncidentPlaceholder(dst io.Writer) error {
	_, err := fmt.Fprintln(
		dst,
		"Incident explanation\n"+
			"No report directory supplied.\n"+
			"Application-level slowdown evidence unavailable in this live-only run.\n"+
			"See diagnosis.txt and incident-report.md for provider-side live evidence.",
	)
	return err
}

func captureMode(inputs Inputs) string {
	if inputs.CaptureMode == "discover-suspects" {
		return "discover-suspects"
	}
	return "pairwise"
}

func captureEvidenceMode(inputs Inputs) string {
	if strings.TrimSpace(inputs.ReportDirectory) == "" {
		return "live-only"
	}
	return "report-backed"
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func writeArtifact(path string, render func(io.Writer) error) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create capture artifact %q: %w", path, err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure capture artifact %q: %w", path, err)
	}
	if err := render(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("render capture artifact %q: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync capture artifact %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close capture artifact %q: %w", path, err)
	}
	return nil
}

func writeBundle(finalDirectory, captureID string, createdAt time.Time, artifacts []artifact) (result Result, err error) {
	seenNames := make(map[string]struct{}, len(artifacts))
	for _, item := range artifacts {
		if err := validateArtifactName(item.name); err != nil {
			return Result{}, err
		}
		if item.render == nil {
			return Result{}, fmt.Errorf("capture artifact %q has no renderer", item.name)
		}
		if _, exists := seenNames[item.name]; exists {
			return Result{}, fmt.Errorf("duplicate capture artifact name %q", item.name)
		}
		seenNames[item.name] = struct{}{}
	}
	if _, statErr := os.Lstat(finalDirectory); statErr == nil {
		return Result{}, fmt.Errorf("capture directory already exists: %q", finalDirectory)
	} else if !os.IsNotExist(statErr) {
		return Result{}, fmt.Errorf("check capture directory %q: %w", finalDirectory, statErr)
	}

	parent := filepath.Dir(finalDirectory)
	temporaryDirectory, err := os.MkdirTemp(parent, "."+filepath.Base(finalDirectory)+".tmp-")
	if err != nil {
		return Result{}, fmt.Errorf("create temporary capture directory in %q: %w", parent, err)
	}
	if err := os.Chmod(temporaryDirectory, 0o700); err != nil {
		_ = os.RemoveAll(temporaryDirectory)
		return Result{}, fmt.Errorf("secure temporary capture directory %q: %w", temporaryDirectory, err)
	}
	finalized := false
	defer func() {
		if !finalized {
			_ = os.RemoveAll(temporaryDirectory)
		}
	}()

	artifactNames := make([]string, 0, len(artifacts))
	for _, item := range artifacts {
		path := filepath.Join(temporaryDirectory, item.name)
		if err := writeArtifact(path, item.render); err != nil {
			return Result{}, err
		}
		artifactNames = append(artifactNames, item.name)
	}

	manifest, err := buildManifest(temporaryDirectory, captureID, createdAt, artifactNames)
	if err != nil {
		return Result{}, err
	}
	if err := writeArtifact(filepath.Join(temporaryDirectory, manifestFilename), func(dst io.Writer) error {
		return WriteManifest(dst, manifest)
	}); err != nil {
		return Result{}, err
	}
	if err := syncDirectory(temporaryDirectory); err != nil {
		return Result{}, fmt.Errorf("sync temporary capture directory %q: %w", temporaryDirectory, err)
	}
	if _, statErr := os.Lstat(finalDirectory); statErr == nil {
		return Result{}, fmt.Errorf("capture directory already exists: %q", finalDirectory)
	} else if !os.IsNotExist(statErr) {
		return Result{}, fmt.Errorf("check capture directory %q before finalization: %w", finalDirectory, statErr)
	}
	if err := os.Rename(temporaryDirectory, finalDirectory); err != nil {
		return Result{}, fmt.Errorf("finalize capture directory %q: %w", finalDirectory, err)
	}
	finalized = true

	result = Result{Directory: finalDirectory, Files: make([]string, 0, len(artifactNames)+1)}
	for _, name := range artifactNames {
		result.Files = append(result.Files, filepath.Join(finalDirectory, name))
	}
	result.Files = append(result.Files, filepath.Join(finalDirectory, manifestFilename))
	return result, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
