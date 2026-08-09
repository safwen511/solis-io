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
	if err := os.Mkdir(directory, 0o755); err != nil {
		return Result{}, fmt.Errorf("create capture directory %q: %w", directory, err)
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
	var generatedFiles []string
	artifacts = append(
		artifacts,
		artifact{"diagnosis.txt", func(w io.Writer) error { return diagnose.Write(w, evidence.Diagnosis) }},
		artifact{"incident-report.md", func(w io.Writer) error {
			return WriteIncidentReport(w, inputs, evidence, timestamp, generatedFiles)
		}},
		artifact{"metadata.txt", func(w io.Writer) error { return WriteMetadata(w, inputs, timestamp) }},
	)
	generatedFiles = make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		generatedFiles = append(generatedFiles, artifact.name)
	}

	result := Result{Directory: directory}
	for _, artifact := range artifacts {
		path := filepath.Join(directory, artifact.name)
		if err := writeArtifact(path, artifact.render); err != nil {
			return result, err
		}
		result.Files = append(result.Files, path)
	}
	return result, nil
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
			"Solis command: %s\n"+
			"Capture mode: %s\n"+
			"Selected suspect: %s\n"+
			"eBPF latency requested: %s\n"+
			"eBPF latency file written: %s\n"+
			"Discovery file: %s\n"+
			"Incident report: incident-report.md\n",
		timestamp,
		valueOrDash(inputs.ReportDirectory),
		evidenceMode,
		inputs.Victim,
		inputs.Suspect,
		inputs.Duration,
		inputs.Interval,
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
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create capture artifact %q: %w", path, err)
	}
	if err := render(file); err != nil {
		file.Close()
		return fmt.Errorf("render capture artifact %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close capture artifact %q: %w", path, err)
	}
	return nil
}
