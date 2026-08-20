package ebpf

import (
	"fmt"
	"io"
	"strings"
)

// BlockLatencyEvidence contains an optional host-wide latency result for a
// higher-level diagnosis or capture. UnavailableReason is populated when the
// optional collector could not run.
type BlockLatencyEvidence struct {
	Result            BlockLatencyResult
	Context           *BlockLatencyVMContext
	UnavailableReason string
	Notice            string
}

// WriteBlockLatencyEvidence writes an embeddable experimental evidence section
// without the standalone command title.
func WriteBlockLatencyEvidence(dst io.Writer, evidence BlockLatencyEvidence) error {
	if notice := oneLineReason(evidence.Notice); notice != "" {
		if _, err := fmt.Fprintln(dst, notice); err != nil {
			return err
		}
	}
	if reason := oneLineReason(evidence.UnavailableReason); reason != "" {
		if _, err := fmt.Fprintf(dst, "eBPF block latency evidence unavailable: %s\n", reason); err != nil {
			return err
		}
	} else if err := writeBlockLatencyResult(dst, evidence.Result); err != nil {
		return err
	}

	_, err := fmt.Fprintln(
		dst,
		"eBPF latency is host/storage-path level, not precise per-VM attribution.\nQEMU io-summary is used for VM writer attribution.",
	)
	return err
}

// WriteBlockLatencyEvidenceFile writes the standalone-style artifact used by
// incident captures.
func WriteBlockLatencyEvidenceFile(dst io.Writer, evidence BlockLatencyEvidence) error {
	if oneLineReason(evidence.UnavailableReason) != "" || oneLineReason(evidence.Notice) != "" {
		if _, err := fmt.Fprintln(dst, "Solis eBPF Block Latency (experimental)"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(dst); err != nil {
			return err
		}
		return WriteBlockLatencyEvidence(dst, evidence)
	}
	if evidence.Context != nil {
		return WriteVMBlockLatency(dst, evidence.Result, *evidence.Context)
	}
	return WriteBlockLatency(dst, evidence.Result)
}

// oneLineReason derives stable operator-facing text for one line reason.
func oneLineReason(reason string) string {
	return strings.Join(strings.Fields(reason), " ")
}
