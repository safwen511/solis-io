package ebpf

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"
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

func TestParseTracepointFormat(t *testing.T) {
	input := `name: block_rq_issue
ID: 112
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:dev_t dev;	offset:8;	size:4;	signed:0;
	field:sector_t sector;	offset:16;	size:8;	signed:0;
	field:unsigned int nr_sector;	offset:24;	size:4;	signed:0;
	field:char rwbs[8];	offset:32;	size:8;	signed:1;
	field:__data_loc char[] cmd;	offset:40;	size:4;	signed:1;
`
	format, err := ParseTracepointFormat(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if format.Name != "block_rq_issue" || format.ID != 112 || len(format.Fields) != 6 {
		t.Fatalf("format = %#v", format)
	}
	checks := []struct {
		index int
		name  string
		type_ string
	}{
		{1, "dev", "dev_t"},
		{4, "rwbs", "char[8]"},
		{5, "cmd", "__data_loc char[]"},
	}
	for _, check := range checks {
		field := format.Fields[check.index]
		if field.Name != check.name || field.Type != check.type_ {
			t.Errorf("field[%d] = %#v, want name=%q type=%q", check.index, field, check.name, check.type_)
		}
	}
}

func TestWriteBlockEventsHighlightsUsefulFields(t *testing.T) {
	formats := []TracepointFormat{{
		Name: "block_rq_issue",
		ID:   112,
		Fields: []TracepointField{
			{Name: "common_type", Type: "unsigned short", Offset: 0, Size: 2},
			{Name: "dev", Type: "dev_t", Offset: 8, Size: 4},
		},
	}}
	var output bytes.Buffer
	if err := WriteBlockEvents(&output, 10*time.Second, formats); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Tracepoint: block:block_rq_issue", "Event ID:   112", "yes", "dev", "Attachment:         none"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestWriteBlockCountFormatsRates(t *testing.T) {
	var output bytes.Buffer
	result := BlockCountResult{Duration: 2 * time.Second, IssueCount: 25, CompleteCount: 20}
	if err := WriteBlockCount(&output, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"block:block_rq_issue", "25", "12.50", "block:block_rq_complete", "20", "10.00"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestCounterProgramDoesNotReadTracepointContext(t *testing.T) {
	instructions := counterProgram(7, 1)
	for _, instruction := range instructions {
		if instruction.Code == 0x61 && instruction.Regs&0x0f == 1 {
			t.Fatalf("counter program reads tracepoint context: %#v", instructions)
		}
	}
	if len(instructions) != 11 {
		t.Fatalf("counter program has %d instructions, want 11", len(instructions))
	}
	if instructions[4].Imm != 1 {
		t.Fatalf("counter key = %d, want 1", instructions[4].Imm)
	}
}

func TestBPFABILayout(t *testing.T) {
	tests := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"instruction size", unsafe.Sizeof(bpfInstruction{}), 8},
		{"map create attribute size", unsafe.Sizeof(bpfMapCreateAttr{}), 72},
		{"map extra offset", unsafe.Offsetof(bpfMapCreateAttr{}.MapExtra), 64},
		{"program load attribute size", unsafe.Sizeof(bpfProgramLoadAttr{}), 72},
		{"program instructions offset", unsafe.Offsetof(bpfProgramLoadAttr{}.Instructions), 8},
		{"program name offset", unsafe.Offsetof(bpfProgramLoadAttr{}.ProgramName), 48},
		{"expected attach type offset", unsafe.Offsetof(bpfProgramLoadAttr{}.ExpectedAttachType), 68},
		{"raw tracepoint attribute size", unsafe.Sizeof(bpfRawTracepointAttr{}), 16},
		{"map element attribute size", unsafe.Sizeof(bpfMapElementAttr{}), 32},
	}
	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("%s = %d, want %d", test.name, test.got, test.want)
		}
	}
}
