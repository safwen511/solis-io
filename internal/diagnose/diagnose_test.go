package diagnose

import (
	"bytes"
	"strings"
	"testing"

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
