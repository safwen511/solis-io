package capture

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/safwen511/solis-io/internal/diagnose"
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

	artifacts := []artifact{
		{"experiment-summary.txt", func(w io.Writer) error { return experiment.WriteSummary(w, evidence.Experiment) }},
		{"incident-explanation.txt", func(w io.Writer) error { return incident.WriteExplanation(w, evidence.Incident) }},
		{"trace-plan.txt", func(w io.Writer) error { return traceplan.Write(w, evidence.TracePlan) }},
		{"storage-snapshot.txt", func(w io.Writer) error { return storage.Write(w, evidence.Storage) }},
		{"qemu-io-summary.txt", func(w io.Writer) error { return qemuio.WriteSummary(w, evidence.QEMU) }},
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
	artifacts = append(
		artifacts,
		artifact{"diagnosis.txt", func(w io.Writer) error { return diagnose.Write(w, evidence.Diagnosis) }},
		artifact{"metadata.txt", func(w io.Writer) error { return WriteMetadata(w, inputs, timestamp) }},
	)

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
	if _, err := fmt.Fprintf(
		dst,
		"Solis Capture Metadata\n"+
			"Capture timestamp UTC: %s\n"+
			"Report directory: %s\n"+
			"Victim: %s\n"+
			"Suspect: %s\n"+
			"Duration: %s\n"+
			"Interval: %s\n"+
			"Solis command: %s\n",
		timestamp,
		inputs.ReportDirectory,
		inputs.Victim,
		inputs.Suspect,
		inputs.Duration,
		inputs.Interval,
		commandName,
	); err != nil {
		return err
	}
	if inputs.IncludeEBPFLatency {
		_, err := fmt.Fprintln(dst, "eBPF block latency: ebpf-block-latency.txt (experimental; host/storage-path level)")
		return err
	}
	return nil
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
