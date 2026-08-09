package diagnose

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/discovery"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
)

func TestVerdict(t *testing.T) {
	tests := []struct {
		name     string
		evidence Evidence
		want     string
	}{
		{
			name: "all noisy-neighbor signals",
			evidence: Evidence{
				SlowdownObserved:               true,
				StorageTopologyAvailable:       true,
				SharedPhysicalDisk:             true,
				QEMUDataAvailable:              true,
				MeaningfulSuspectWritePressure: true,
				SuspectDominant:                true,
			},
			want: ProbableVerdict,
		},
		{
			name: "syscall fallback supports noisy-neighbor verdict",
			evidence: Evidence{
				SlowdownObserved:               true,
				StorageTopologyAvailable:       true,
				SharedPhysicalDisk:             true,
				QEMUDataAvailable:              true,
				MeaningfulSuspectSyscwPressure: true,
				SuspectSyscwDominant:           true,
			},
			want: ProbableVerdict,
		},
		{
			name: "slowdown with low write pressure",
			evidence: Evidence{
				SlowdownObserved:               true,
				StorageTopologyAvailable:       true,
				SharedPhysicalDisk:             true,
				QEMUDataAvailable:              true,
				MeaningfulSuspectWritePressure: false,
			},
			want: LowPressureVerdict,
		},
		{
			name: "slowdown on different physical disks",
			evidence: Evidence{
				SlowdownObserved:               true,
				StorageTopologyAvailable:       true,
				SharedPhysicalDisk:             false,
				QEMUDataAvailable:              true,
				MeaningfulSuspectWritePressure: true,
				SuspectDominant:                true,
			},
			want: TopologyMismatchVerdict,
		},
		{
			name: "no experiment slowdown",
			evidence: Evidence{
				StorageTopologyAvailable:       true,
				SharedPhysicalDisk:             true,
				QEMUDataAvailable:              true,
				MeaningfulSuspectWritePressure: true,
				SuspectDominant:                true,
			},
			want: InsufficientVerdict,
		},
		{
			name: "live QEMU data unavailable",
			evidence: Evidence{
				SlowdownObserved:         true,
				StorageTopologyAvailable: true,
				SharedPhysicalDisk:       true,
				QEMUDataAvailable:        false,
			},
			want: InsufficientVerdict,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Verdict(test.evidence); got != test.want {
				t.Fatalf("Verdict() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestWriteIncludesQEMUSyscallFallbackEvidence(t *testing.T) {
	report := Report{
		QEMU: qemuio.SummaryReport{
			VictimDataAvailable:            true,
			SuspectDataAvailable:           true,
			VictimAverageSyscwPerSecond:    500,
			SuspectAverageSyscwPerSecond:   122364.35,
			SyscwRatio:                     "244.73x",
			WriteSyscallPressure:           "HIGH",
			DominantWriteSyscallSource:     "b-stress",
			Conclusion:                     "QEMU write syscall pressure observed, but byte counters did not advance meaningfully.",
			MeaningfulSuspectSyscwPressure: true,
			SuspectSyscwDominant:           true,
		},
	}
	var output bytes.Buffer
	if err := Write(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Victim average syscw/s:",
		"Suspect average syscw/s:",
		"122364.35",
		"Dominant write syscall source:",
		"b-stress",
		"QEMU write syscall pressure observed, but byte counters did not advance meaningfully.",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestWriteWithoutEBPFLatencyPreservesExistingOutput(t *testing.T) {
	var output bytes.Buffer
	if err := Write(&output, Report{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "eBPF block latency evidence") {
		t.Fatalf("output unexpectedly contains optional eBPF section:\n%s", output.String())
	}
	if strings.Contains(output.String(), "Suspect discovery") {
		t.Fatalf("pairwise output unexpectedly contains suspect discovery:\n%s", output.String())
	}
}

func TestWriteIncludesSuspectDiscoveryTable(t *testing.T) {
	discoveryReport := discovery.Report{
		Victim:        inventory.VM{Name: "a-web"},
		VictimStorage: hoststorage.Mapping{PhysicalDisk: "/dev/nvme0n1"},
		Candidates: []discovery.Candidate{{
			VM:         inventory.VM{Name: "b-stress", Tenant: "tenant-b", Role: "stress"},
			SharedDisk: true,
			Summary: qemuio.VMSummary{
				Available:                true,
				AverageWriteMiBPerSecond: 3.2,
				MaxWriteMiBPerSecond:     10.81,
				AverageSyscwPerSecond:    139413,
				MaxSyscwPerSecond:        141000,
			},
			Score:  "HIGH",
			Reason: "dominant syscall pressure",
		}},
		SelectionReason: "dominant syscall pressure",
	}
	discoveryReport.Selected = &discoveryReport.Candidates[0]
	var output bytes.Buffer
	if err := Write(&output, Report{Discovery: &discoveryReport}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Suspect discovery",
		"Victim physical disk:",
		"/dev/nvme0n1",
		"AVG_WRITE_MIB/S",
		"AVG_SYSCW/S",
		"b-stress",
		"dominant syscall pressure",
		"Selected suspect:",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestWriteDiscoveryWithoutSelectionIncludesVerdictAndEBPFNotice(t *testing.T) {
	discoveryReport := discovery.Report{
		Victim:          inventory.VM{Name: "a-web"},
		VictimStorage:   hoststorage.Mapping{PhysicalDisk: "/dev/nvme0n1"},
		SelectionReason: "no dominant writer observed",
	}
	latency := ebpf.BlockLatencyEvidence{
		Result: ebpf.BlockLatencyResult{Duration: time.Second},
		Notice: "eBPF VM-aware latency requires a selected suspect; skipping VM-aware eBPF latency.",
	}
	var output bytes.Buffer
	if err := Write(&output, Report{
		Discovery:   &discoveryReport,
		EBPFLatency: &latency,
		Verdict:     NoDominantCandidateVerdict,
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Selected suspect:",
		"Reason:",
		"no dominant writer observed",
		"eBPF VM-aware latency requires a selected suspect; skipping VM-aware eBPF latency.",
		NoDominantCandidateVerdict,
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "QEMU I/O conclusion:") {
		t.Fatalf("no-selection output contains misleading pairwise QEMU conclusion:\n%s", output.String())
	}
}

func TestWriteIncludesEBPFBlockLatencyEvidence(t *testing.T) {
	latency := ebpf.BlockLatencyEvidence{Result: ebpf.BlockLatencyResult{
		Duration:          10 * time.Second,
		CompletedRequests: 4,
		TotalLatencyNS:    400_000,
		MaxLatencyNS:      250_000,
	}}
	latency.Result.Histogram[2] = 3
	latency.Result.Histogram[3] = 1
	var output bytes.Buffer
	if err := Write(&output, Report{EBPFLatency: &latency}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"eBPF block latency evidence",
		"Total completed requests:  4",
		"Average latency:           100.00 us",
		"Max latency:               250.00 us",
		"50-99 us",
		"eBPF latency is host/storage-path level, not precise per-VM attribution.",
		"QEMU io-summary is used for VM writer attribution.",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestWriteIncludesEBPFUnavailableWarning(t *testing.T) {
	latency := ebpf.BlockLatencyEvidence{UnavailableReason: "permission denied loading eBPF\ntry running with sudo"}
	var output bytes.Buffer
	if err := Write(&output, Report{EBPFLatency: &latency}); err != nil {
		t.Fatal(err)
	}
	want := "eBPF block latency evidence unavailable: permission denied loading eBPF try running with sudo"
	if !strings.Contains(output.String(), want) {
		t.Fatalf("output missing %q:\n%s", want, output.String())
	}
}
