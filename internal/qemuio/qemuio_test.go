package qemuio

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/inventory"
)

// TestParseProcIO verifies parse proc io.
func TestParseProcIO(t *testing.T) {
	input := `rchar: 101
wchar: 202
syscr: 303
syscw: 404
read_bytes: 505
write_bytes: 606
cancelled_write_bytes: 707
`

	got, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	want := Counters{
		RChar:               101,
		WChar:               202,
		Syscr:               303,
		Syscw:               404,
		ReadBytes:           505,
		WriteBytes:          606,
		CancelledWriteBytes: 707,
	}
	if got != want {
		t.Fatalf("Parse() = %#v, want %#v", got, want)
	}
}

// TestParseProcIOReportsMissingField verifies parse proc io reports missing field.
func TestParseProcIOReportsMissingField(t *testing.T) {
	_, err := Parse(strings.NewReader("rchar: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "missing proc io fields") {
		t.Fatalf("Parse() error = %v, want missing-fields error", err)
	}
}

// TestCalculateDelta verifies calculate delta.
func TestCalculateDelta(t *testing.T) {
	previous := Counters{
		Syscr:      10,
		Syscw:      5,
		ReadBytes:  1 * bytesPerMiB,
		WriteBytes: 2 * bytesPerMiB,
	}
	current := Counters{
		Syscr:      50,
		Syscw:      25,
		ReadBytes:  5 * bytesPerMiB,
		WriteBytes: 4 * bytesPerMiB,
	}

	rates, err := CalculateDelta(previous, current, 2*time.Second)
	if err != nil {
		t.Fatalf("CalculateDelta() error = %v", err)
	}
	if rates.ReadBytesPerSecond != 2*bytesPerMiB || rates.WriteBytesPerSecond != bytesPerMiB {
		t.Fatalf("byte rates = %#v, want 2 MiB/s read and 1 MiB/s write", rates)
	}
	if rates.ReadMiBPerSecond != 2 || rates.WriteMiBPerSecond != 1 {
		t.Fatalf("MiB rates = %#v, want 2 read and 1 write", rates)
	}
	if rates.SyscrPerSecond != 20 || rates.SyscwPerSecond != 10 {
		t.Fatalf("syscall rates = %#v, want 20 syscr/s and 10 syscw/s", rates)
	}
}

// TestCalculateDeltaRejectsCounterReset verifies calculate delta rejects counter reset.
func TestCalculateDeltaRejectsCounterReset(t *testing.T) {
	_, err := CalculateDelta(Counters{ReadBytes: 2}, Counters{ReadBytes: 1}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "read_bytes counter decreased") {
		t.Fatalf("CalculateDelta() error = %v, want counter-decreased error", err)
	}
}

// TestNewPlanSortsAndCombinesTargets verifies new plan sorts and combines targets.
func TestNewPlanSortsAndCombinesTargets(t *testing.T) {
	victims := []inventory.VM{{Name: "a-web"}, {Name: "a-db"}}
	plan := NewPlan("tenant-a", "a-web", victims, victims[0])
	if len(plan.Targets) != 2 {
		t.Fatalf("len(Targets) = %d, want 2", len(plan.Targets))
	}
	if plan.Targets[0].VM.Name != "a-db" || plan.Targets[0].TargetType != "victim" {
		t.Fatalf("Targets[0] = %#v, want sorted victim a-db", plan.Targets[0])
	}
	if plan.Targets[1].VM.Name != "a-web" || plan.Targets[1].TargetType != "victim,suspect" {
		t.Fatalf("Targets[1] = %#v, want combined a-web target", plan.Targets[1])
	}
}

// TestPermissionDeniedReadError verifies permission denied read error.
func TestPermissionDeniedReadError(t *testing.T) {
	path := "/proc/123/io"
	err := formatProcessIOReadError(path, &os.PathError{Op: "open", Path: path, Err: os.ErrPermission})
	want := "permission denied reading /proc/123/io; try running with sudo"
	if err.Error() != want {
		t.Fatalf("formatProcessIOReadError() = %q, want %q", err, want)
	}
}

// TestWriteWatchRowRendersPermissionDenied verifies write watch row renders permission denied.
func TestWriteWatchRowRendersPermissionDenied(t *testing.T) {
	var output bytes.Buffer
	target := Target{TargetType: "victim", VM: inventory.VM{Name: "a-db", QEMUPID: "123"}}
	err := formatProcessIOReadError("/proc/123/io", os.ErrPermission)
	if writeErr := writeWatchRow(&output, 2*time.Second, target, Rates{}, err); writeErr != nil {
		t.Fatalf("writeWatchRow() error = %v", writeErr)
	}
	want := "permission denied reading /proc/123/io; try running with sudo"
	if !strings.Contains(output.String(), want) {
		t.Fatalf("writeWatchRow() output = %q, want %q", output.String(), want)
	}
}
