package diagnose

import "testing"

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
