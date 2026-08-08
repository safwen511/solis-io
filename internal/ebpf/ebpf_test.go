package ebpf

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInspectFindsBTFMountsAndBlockTracepoints(t *testing.T) {
	root := t.TempDir()
	traceRoot := filepath.Join(root, "trace")
	debugRoot := filepath.Join(root, "debug")
	btfPath := filepath.Join(root, "vmlinux")
	mountInfoPath := filepath.Join(root, "mountinfo")
	for _, event := range []string{"block_rq_issue", "block_rq_complete"} {
		if err := os.MkdirAll(filepath.Join(traceRoot, "events", "block", event), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(traceRoot, "events", "block", event, "id"), []byte("42\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(debugRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(btfPath, []byte("btf"), 0o644); err != nil {
		t.Fatal(err)
	}
	mountInfo := fmt.Sprintf(
		"31 20 0:30 / %s rw - tracefs tracefs rw\n32 20 0:31 / %s rw - debugfs debugfs rw\n",
		traceRoot,
		debugRoot,
	)
	if err := os.WriteFile(mountInfoPath, []byte(mountInfo), 0o644); err != nil {
		t.Fatal(err)
	}

	report := inspect(probeConfig{
		BTFPath:       btfPath,
		MountInfoPath: mountInfoPath,
		TraceRoot:     traceRoot,
		DebugRoot:     debugRoot,
	})
	if !Ready(report) {
		t.Fatalf("Ready() = false, checks = %#v", report.Checks)
	}
	if report.TraceRoot != traceRoot {
		t.Fatalf("TraceRoot = %q, want %q", report.TraceRoot, traceRoot)
	}
}

func TestReadyRejectsFailureButAllowsWarning(t *testing.T) {
	if !Ready(Report{Checks: []Check{{Status: OK}, {Status: WARN}}}) {
		t.Fatal("Ready() = false for OK/WARN checks")
	}
	if Ready(Report{Checks: []Check{{Status: FAIL}}}) {
		t.Fatal("Ready() = true for failed check")
	}
}

func TestParseMountInfoUnescapesMountpoint(t *testing.T) {
	mounts := parseMountInfo("31 20 0:30 / /tmp/trace\\040space rw - tracefs tracefs rw\n")
	if len(mounts) != 1 || mounts[0].point != "/tmp/trace space" || mounts[0].filesystem != "tracefs" {
		t.Fatalf("parseMountInfo() = %#v", mounts)
	}
}

func TestWriteBlockWatchMakesReadinessOnlyModeClear(t *testing.T) {
	report := Report{Checks: []Check{{Status: OK, Name: "Kernel BTF", Detail: defaultBTFPath}}}
	var output bytes.Buffer
	if err := WriteBlockWatch(&output, 10*time.Second, report); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Requested duration: 10s", "Attachment:         none", "No watch was started", "no program was attached"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}
