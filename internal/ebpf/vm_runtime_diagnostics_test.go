package ebpf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestPermissionDeniedGuidanceDependsOnEffectiveUID verifies permission denied guidance depends on
// effective uid.
func TestPermissionDeniedGuidanceDependsOnEffectiveUID(t *testing.T) {
	nonRoot := permissionDeniedMessage(1000, syscall.EPERM)
	if !strings.Contains(nonRoot, "try running with sudo") {
		t.Fatalf("non-root guidance = %q", nonRoot)
	}
	root := permissionDeniedMessage(0, syscall.EPERM)
	if strings.Contains(root, "try running with sudo") || !strings.Contains(root, "despite euid=0") || !strings.Contains(root, "CAP_BPF") {
		t.Fatalf("root guidance = %q", root)
	}
}

// TestVMBlockPermissionDiagnosticsAreStageSpecific verifies vm block permission diagnostics are
// stage specific.
func TestVMBlockPermissionDiagnosticsAreStageSpecific(t *testing.T) {
	tests := []struct {
		name      string
		resources *fakeVMBlockCountResources
		loaderErr error
		stage     string
	}{
		{name: "object load", loaderErr: syscall.EPERM, stage: "object_load"},
		{name: "issue attach", resources: &fakeVMBlockCountResources{issueErr: syscall.EPERM}, stage: "issue_attach"},
		{name: "complete attach", resources: &fakeVMBlockCountResources{completeErr: syscall.EPERM}, stage: "complete_attach"},
		{name: "map read", resources: &fakeVMBlockCountResources{counterErr: syscall.EPERM}, stage: "map_read"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, loader := fakeCiliumVMBlockSource(test.resources)
			loader.err = test.loaderErr
			report := collectCountOnlyDiagnosticTestReport(source, 0)
			if report.Availability.Available || report.Availability.Status != "permission_denied" {
				t.Fatalf("availability = %#v", report.Availability)
			}
			if report.Diagnostics.Stage != test.stage || report.Diagnostics.EUID != 0 {
				t.Fatalf("diagnostics = %#v", report.Diagnostics)
			}
			if strings.Contains(report.Availability.Error, "try running with sudo") || !strings.Contains(report.Diagnostics.RawError, "operation not permitted") {
				t.Fatalf("report = %#v", report)
			}
			if report.KernelCounters != (VMBlockKernelCounters{}) || report.HostSummary.TotalOps != 0 || privacyCollected(report) {
				t.Fatalf("failed collection fabricated evidence or violated privacy: %#v", report)
			}
		})
	}
}

// TestVMBlockRuntimeDiagnosticsReadBoundedSafeHostState verifies vm block runtime diagnostics read
// bounded safe host state.
func TestVMBlockRuntimeDiagnosticsReadBoundedSafeHostState(t *testing.T) {
	root := t.TempDir()
	statusPath := filepath.Join(root, "status")
	lockdownPath := filepath.Join(root, "lockdown")
	perfPath := filepath.Join(root, "perf")
	unprivilegedPath := filepath.Join(root, "unprivileged")
	for path, value := range map[string]string{
		statusPath:       "Name:\tsolis-test\nCapEff:\t000000c001200000\n",
		lockdownPath:     "none [integrity] confidentiality\n",
		perfPath:         "3\n",
		unprivilegedPath: "2\n",
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	diagnostics := collectVMBlockRuntimeDiagnostics(vmBlockDiagnosticConfig{
		SelfStatusPath: statusPath, LockdownPath: lockdownPath,
		PerfEventParanoidPath: perfPath, UnprivilegedBPFDisabledPath: unprivilegedPath,
		GetEUID: func() int { return 0 }, GetMemlock: func() (string, error) { return "soft=8388608 hard=8388608", nil },
	}, "object_load", errors.New(strings.Repeat("x", maxVMBlockVerifierLogBytes+500)))
	if diagnostics.LockdownMode != "integrity" || diagnostics.PerfEventParanoid != "3" || diagnostics.UnprivilegedBPFDisabled != "2" {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if !diagnostics.CapabilitySummary.Available || diagnostics.CapabilitySummary.CapEff != "000000c001200000" {
		t.Fatalf("capabilities = %#v", diagnostics.CapabilitySummary)
	}
	if len(diagnostics.RawError) > maxVMBlockVerifierLogBytes || !strings.HasSuffix(diagnostics.RawError, "... (truncated)") {
		t.Fatalf("raw error was not bounded: length=%d", len(diagnostics.RawError))
	}
}

// TestGeneratedObjectPresentButAttachDeniedRemainsUnavailable verifies generated object present but
// attach denied remains unavailable.
func TestGeneratedObjectPresentButAttachDeniedRemainsUnavailable(t *testing.T) {
	resources := &fakeVMBlockCountResources{issueErr: syscall.EPERM}
	source, loader := fakeCiliumVMBlockSource(resources)
	report := collectCountOnlyDiagnosticTestReport(source, 0)
	if !loader.loaded || report.Availability.Available || report.Diagnostics.Stage != "issue_attach" {
		t.Fatalf("loader/report = loaded:%v report:%#v", loader.loaded, report)
	}
	if report.HostSummary.TotalOps != 0 || report.KernelCounters != (VMBlockKernelCounters{}) || privacyCollected(report) {
		t.Fatalf("attach denial fabricated results: %#v", report)
	}
}

// collectCountOnlyDiagnosticTestReport collects count only diagnostic test report from the
// configured evidence sources.
func collectCountOnlyDiagnosticTestReport(source VMBlockKernelSource, euid int) VMBlockLatencyReport {
	return CollectVMBlockLatencyReportWithKernelSource(context.Background(), VMBlockLatencyCollectOptions{
		Duration: time.Nanosecond, Interval: time.Nanosecond,
		effectiveUID: func() int { return euid },
		diagnosticProbe: func(stage string, gotEUID int, err error) VMBlockRuntimeDiagnostics {
			return VMBlockRuntimeDiagnostics{
				Stage: stage, EUID: gotEUID, RawError: boundedError(err), LockdownMode: "none",
				MemlockLimit: "soft=8388608 hard=8388608", PerfEventParanoid: "2", UnprivilegedBPFDisabled: "2",
				CapabilitySummary: VMBlockCapabilitySummary{Available: true, CapEff: "000000c001200000"},
			}
		},
	}, nil, source)
}
