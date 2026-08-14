package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/capture"
	solisconfig "github.com/safwen511/solis-io/internal/config"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/guest"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/observability"
	"github.com/safwen511/solis-io/internal/observe"
	"github.com/safwen511/solis-io/internal/storagevm"
	topview "github.com/safwen511/solis-io/internal/top"
	"github.com/safwen511/solis-io/internal/version"
)

type fakeGuestRunner struct{ outputs map[string]string }

func (runner fakeGuestRunner) Run(_ context.Context, _ guest.Target, command guest.CommandSpec) (guest.Result, error) {
	return guest.Result{Output: runner.outputs[command.Key()]}, nil
}

func TestRunVersionHumanAndJSON(t *testing.T) {
	var human bytes.Buffer
	if err := Run([]string{"version"}, &human, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"version: dev", "git_commit: unknown", "build_time: unknown", "go_version:", "platform:"} {
		if !strings.Contains(human.String(), want) {
			t.Errorf("human version output missing %q:\n%s", want, human.String())
		}
	}

	var jsonOutput bytes.Buffer
	if err := Run([]string{"version", "--json"}, &jsonOutput, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var decoded version.Info
	if err := json.Unmarshal(jsonOutput.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid version JSON: %v\n%s", err, jsonOutput.String())
	}
	if decoded != version.BuildInfo() {
		t.Fatalf("version JSON = %#v, want %#v", decoded, version.BuildInfo())
	}
	if err := Run([]string{"version", "--yaml"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage: solis version") {
		t.Fatalf("invalid version flag error = %v", err)
	}
}

func TestCommandCenterBuildsOnlyFixedParseableWorkflowArguments(t *testing.T) {
	tests := []struct {
		request topview.LaunchRequest
		check   func([]string) error
	}{
		{request: topview.LaunchRequest{Workflow: topview.WorkflowInvestigate, VM: "a-web"}, check: func(args []string) error {
			_, err := parseDiagnoseNoisyNeighborArgs(args)
			return err
		}},
		{request: topview.LaunchRequest{Workflow: topview.WorkflowBundle, VM: "a-web"}, check: func(args []string) error {
			_, err := parseCaptureNoisyNeighborArgs(args)
			return err
		}},
		{request: topview.LaunchRequest{Workflow: topview.WorkflowWatch, VM: "a-web"}, check: func(args []string) error {
			options, err := parseWatchNoisyNeighborArgs(args)
			if err == nil && options.Iterations != 3 {
				return errors.New("embedded watch is not bounded to three iterations")
			}
			return err
		}},
		{request: topview.LaunchRequest{Workflow: topview.WorkflowObserve, VM: "a-web"}, check: func(args []string) error {
			_, err := parseObserveSnapshotArgs(args)
			return err
		}},
		{request: topview.LaunchRequest{Workflow: topview.WorkflowDoctor}, check: func(args []string) error {
			if strings.Join(args, " ") != "doctor" {
				return errors.New("unexpected doctor arguments")
			}
			return nil
		}},
		{request: topview.LaunchRequest{Workflow: topview.WorkflowEBPFDoctor}, check: func(args []string) error {
			if strings.Join(args, " ") != "ebpf doctor" {
				return errors.New("unexpected eBPF doctor arguments")
			}
			return nil
		}},
		{request: topview.LaunchRequest{Workflow: topview.WorkflowInventory}},
		{request: topview.LaunchRequest{Workflow: topview.WorkflowStatus}, check: func(args []string) error {
			_, err := parseStatusArgs(args)
			return err
		}},
		{request: topview.LaunchRequest{Workflow: topview.WorkflowVersion}},
	}
	for _, test := range tests {
		args, err := topLaunchArgs(test.request, "/var/lib/solis/captures")
		if err != nil {
			t.Errorf("topLaunchArgs(%q) error = %v", test.request.Workflow, err)
			continue
		}
		if len(args) == 0 {
			t.Errorf("topLaunchArgs(%q) returned no arguments", test.request.Workflow)
			continue
		}
		if test.check != nil {
			if err := test.check(args); err != nil {
				t.Errorf("topLaunchArgs(%q) = %v: %v", test.request.Workflow, args, err)
			}
		}
	}

	if _, err := topLaunchArgs(topview.LaunchRequest{Workflow: topview.WorkflowInvestigate}, "/tmp/captures"); err == nil {
		t.Fatal("VM workflow accepted an empty selection")
	}
	if _, err := topLaunchArgs(topview.LaunchRequest{Workflow: topview.WorkflowBundle, VM: "a-web"}, ""); err == nil {
		t.Fatal("bundle workflow accepted an empty capture root")
	}
	if _, err := topLaunchArgs(topview.LaunchRequest{Workflow: "arbitrary"}, "/tmp/captures"); err == nil {
		t.Fatal("arbitrary workflow was accepted")
	}
}

func TestBoundedWorkflowWriterPreservesPrefixAndMarksTruncation(t *testing.T) {
	writer := newBoundedWorkflowWriter(5)
	value := []byte("abcdefgh")
	written, err := writer.Write(value)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(value) {
		t.Fatalf("Write returned %d, want %d", written, len(value))
	}
	if got := writer.String(); !strings.HasPrefix(got, "abcde") || !strings.Contains(got, "output truncated") {
		t.Fatalf("bounded output = %q", got)
	}
}

func TestRunInventoryOutsideRepositoryWithExplicitConfig(t *testing.T) {
	configDirectory := t.TempDir()
	inventoryPath := filepath.Join(configDirectory, "vms.csv")
	if err := os.WriteFile(inventoryPath, []byte(
		"name,tenant,network,ip,memory_mb,vcpus,disk_gb,role\n"+
			"portable-web,tenant-a,tenant-a-net,192.0.2.10,1024,1,10,web\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDirectory, "solis.json")
	if err := os.WriteFile(configPath, []byte(`{
  "schema_version": "1",
  "inventory_csv": "vms.csv",
  "capture_output_root": "captures",
  "default_report_dir": "reports",
  "libvirt_uri": "qemu:///system",
  "thresholds": {"write_mib_per_sec": 10, "write_syscalls_per_sec": 10000, "dominance_ratio": 2}
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	binDirectory := t.TempDir()
	writeExecutable(t, binDirectory, "virsh", `#!/bin/sh
case "$*" in
  *domstate*) printf 'running\n' ;;
  *domifaddr*) printf 'vnet0 52:54:00:00:00:01 ipv4 192.0.2.10/24\n' ;;
  *domblklist*) printf 'file disk vda /tmp/portable-web.qcow2\n' ;;
esac
`)
	writeExecutable(t, binDirectory, "ps", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))

	originalDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	outsideDirectory := t.TempDir()
	if err := os.Chdir(outsideDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDirectory) })

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"inventory", "--config", configPath}, &stdout, &stderr); err != nil {
		t.Fatalf("Run() error = %v; stderr = %s", err, stderr.String())
	}
	for _, want := range []string{"portable-web", "running", "192.0.2.10", "/tmp/portable-web.qcow2"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("inventory output missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestParseHostStatusJSON(t *testing.T) {
	if err := parseHostStatusArgs([]string{"host", "status", "--json"}); err != nil {
		t.Fatalf("parseHostStatusArgs() error = %v", err)
	}
	for _, args := range [][]string{
		{"host"},
		{"host", "status"},
		{"host", "status", "--human"},
		{"host", "status", "--json", "extra"},
	} {
		if err := parseHostStatusArgs(args); err == nil || !strings.Contains(err.Error(), hostStatusUsage) {
			t.Fatalf("parseHostStatusArgs(%v) error = %v", args, err)
		}
	}
}

func TestParseObserveSnapshot(t *testing.T) {
	options, err := parseObserveSnapshotArgs([]string{
		"observe", "snapshot", "--victim", "a-web", "--discover-suspects",
		"--duration", "4s", "--interval", "1s", "--include-guest",
		"--include-services", "--include-db", "--include-ebpf-latency", "--json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Victim != "a-web" || !options.DiscoverSuspects || !options.JSON ||
		options.Duration != 4*time.Second || options.Interval != time.Second ||
		!options.IncludeGuest || !options.IncludeServices || !options.IncludeDB || !options.IncludeEBPFLatency {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseObserveSnapshotDefaults(t *testing.T) {
	options, err := parseObserveSnapshotArgs([]string{"observe", "snapshot", "--victim", "a-web", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Duration != 10*time.Second || options.Interval != 2*time.Second || options.Suspect != "" || options.DiscoverSuspects {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseEBPFVMBlockLatency(t *testing.T) {
	options, err := parseEBPFVMBlockLatencyArgs([]string{
		"ebpf", "vm-block-latency", "--victim", "a-web", "--suspect", "b-stress",
		"--duration", "5s", "--interval", "1s", "--device", "nvme0n1", "--output", "/tmp/report.json", "--json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Victim != "a-web" || options.Suspect != "b-stress" || options.Duration != 5*time.Second || options.Interval != time.Second || options.Device != "nvme0n1" || options.Output != "/tmp/report.json" || !options.JSON {
		t.Fatalf("options = %#v", options)
	}
	defaults, err := parseEBPFVMBlockLatencyArgs([]string{"ebpf", "vm-block-latency", "--all-vms", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Duration != 10*time.Second || defaults.Interval != time.Second || !defaults.AllVMs {
		t.Fatalf("defaults = %#v", defaults)
	}
}

func TestParseEBPFVMBlockLatencyExplicitBooleanValues(t *testing.T) {
	options, err := parseEBPFVMBlockLatencyArgs([]string{"ebpf", "vm-block-latency", "--all-vms=true", "--json=true"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.JSON || !options.AllVMs {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseEBPFVMBlockLatencyValidation(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"ebpf", "vm-block-latency"}, "--json is required"},
		{[]string{"ebpf", "vm-block-latency", "--json", "--interval", "11s"}, "must not exceed"},
		{[]string{"ebpf", "vm-block-latency", "--json", "--device", "/dev/nvme0n1"}, "invalid --device"},
		{[]string{"ebpf", "vm-block-latency", "--json", "--all-vms", "--victim", "a-web"}, "cannot be combined"},
		{[]string{"ebpf", "vm-block-latency", "--json", "--json"}, "duplicate option"},
	}
	for _, test := range tests {
		if _, err := parseEBPFVMBlockLatencyArgs(test.args); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("parse(%v) error = %v, want %q", test.args, err, test.want)
		}
	}
}

func TestParseObserveSnapshotValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "victim required", args: []string{"observe", "snapshot", "--json"}, want: "--victim is required"},
		{name: "json required", args: []string{"observe", "snapshot", "--victim", "a-web"}, want: "--json is required"},
		{name: "suspect modes conflict", args: []string{"observe", "snapshot", "--victim", "a-web", "--suspect", "b-stress", "--discover-suspects", "--json"}, want: "cannot be used together"},
		{name: "invalid window", args: []string{"observe", "snapshot", "--victim", "a-web", "--duration", "1s", "--interval", "2s", "--json"}, want: "cannot exceed duration"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseObserveSnapshotArgs(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRunObserveSnapshotRejectsUnknownTargetsBeforeCollection(t *testing.T) {
	runtime := solisconfig.DevelopmentDefaults()
	runtime.Settings.InventoryCSV = filepath.Join(t.TempDir(), "vms.csv")
	if err := os.WriteFile(runtime.Settings.InventoryCSV, []byte(
		"name,tenant,network,ip,memory_mb,vcpus,disk_gb,role\n"+
			"a-web,tenant-a,tenant-a-net,192.0.2.10,1024,1,10,web\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		options observeSnapshotOptions
		want    string
	}{
		{options: observeSnapshotOptions{Victim: "missing", Duration: time.Second, Interval: time.Second, JSON: true}, want: "victim VM not found: missing"},
		{options: observeSnapshotOptions{Victim: "a-web", Suspect: "missing", Duration: time.Second, Interval: time.Second, JSON: true}, want: "suspect VM not found: missing"},
	} {
		var output bytes.Buffer
		err := runObserveSnapshot(runtime, test.options, &output)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("error = %v, want %q", err, test.want)
		}
	}
}

func TestObserveWorkflowSummaryIsCompactAndIncludesAttribution(t *testing.T) {
	snapshot := observe.ObserveSnapshot{
		ObservedAtUTC: "2026-08-14T01:30:00Z", Duration: "10s", Interval: "2s",
		Victim: observe.Target{Name: "a-web"}, SelectedSuspect: "b-stress", SuspectMode: "discover-suspects",
		EvidenceQuality: observe.EvidenceQuality{Overall: observe.EvidenceMeasured},
		StorageTopology: observe.StorageTopology{Available: true, SharedPhysicalDisk: true, PhysicalDisk: "/dev/nvme0n1"},
		QEMUEvidence: observe.QEMUEvidence{
			Available: true, DominantWriter: "b-stress", VictimAverageWriteMiBS: 0.1, SuspectAverageWriteMiBS: 6.25,
		},
		EBPFVMAttribution: &observe.EBPFVMAttribution{
			Available: true, Quality: "available", HostTotalOps: 8100,
			AttributedPercent: 99.2, UnattributedPercent: 0.8,
			VictimTotalOps: 20, VictimP95MS: 0.25, SuspectTotalOps: 8000, SuspectP95MS: 20, MatchedVMCount: 3,
		},
		Privacy: observability.PrivacyFlags{},
	}
	var output bytes.Buffer
	if err := writeObserveWorkflowSummary(&output, snapshot); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{
		"OBSERVATION SUMMARY", "Selected VM: a-web", "Selected suspect: b-stress",
		"Evidence quality: measured", "dominant_writer=b-stress", "quality=available",
		"attributed=99.20%", "selected=20", "suspect=8000", "Privacy boundary: safe=true",
		"Detailed JSON: available in memory",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Observe summary missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, `"host_status"`) || strings.Count(text, "\n") > 14 {
		t.Fatalf("Observe summary dumped detailed JSON instead of a compact report:\n%s", text)
	}
}

func TestSaveTopWorkflowDetailUsesPrivateAtomicOutput(t *testing.T) {
	root := t.TempDir()
	detail := topview.WorkflowDetail{
		SuggestedName: "observe-20260814T013000Z-a-web.json",
		Contents:      []byte("{\n  \"schema_version\": \"1\"\n}\n"),
	}
	path, err := saveTopWorkflowDetail(root, detail)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(root, detail.SuggestedName) {
		t.Fatalf("saved path = %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("saved mode = %o, want 600", info.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, detail.Contents) {
		t.Fatalf("saved detail = %q", contents)
	}
	if _, err := saveTopWorkflowDetail(root, topview.WorkflowDetail{SuggestedName: "../escape.json", Contents: []byte("{}")}); err == nil {
		t.Fatal("path traversal detail name was accepted")
	}
	if _, err := saveTopWorkflowDetail(filepath.Join(root, "missing"), detail); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("missing parent error = %v", err)
	}
}

func TestDiagnosisTargetEnrichmentDoesNotReadProcessArguments(t *testing.T) {
	directory := t.TempDir()
	inventoryPath := filepath.Join(directory, "vms.csv")
	if err := os.WriteFile(inventoryPath, []byte(
		"name,tenant,network,ip,memory_mb,vcpus,disk_gb,role\n"+
			"a-web,tenant-a,tenant-a-net,192.0.2.10,1024,1,10,web\n"+
			"b-stress,tenant-b,tenant-b-net,192.0.2.20,1024,1,10,stress\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(directory, "ps-called")
	writeExecutable(t, directory, "virsh", `#!/bin/sh
case "$*" in
  *domstate*) printf 'running\n' ;;
  *domifaddr*a-web*) printf 'vnet0 x ipv4 192.0.2.10/24\n' ;;
  *domifaddr*b-stress*) printf 'vnet0 x ipv4 192.0.2.20/24\n' ;;
  *domblklist*a-web*) printf 'file disk vda /images/a-web.qcow2\n' ;;
  *domblklist*b-stress*) printf 'file disk vda /images/b-stress.qcow2\n' ;;
esac
`)
	writeExecutable(t, directory, "ps", "#!/bin/sh\ntouch \"$SOLIS_PS_MARKER\"\nexit 0\n")
	t.Setenv("SOLIS_PS_MARKER", marker)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	runtime := solisconfig.DevelopmentDefaults()
	runtime.Settings.InventoryCSV = inventoryPath
	plan, err := loadEnrichedTargetPlan(runtime, "a-web", "b-stress")
	if err != nil {
		t.Fatal(err)
	}
	if plan.VictimTargets[0].Disk != "/images/a-web.qcow2" || plan.SuspectTarget.Disk != "/images/b-stress.qcow2" {
		t.Fatalf("plan = %#v", plan)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("process argument fallback was invoked: %v", err)
	}
}

func TestParseObserveWatch(t *testing.T) {
	options, err := parseObserveWatchArgs([]string{
		"observe", "watch", "--victim", "a-web", "--discover-suspects",
		"--duration", "1s", "--interval", "1s", "--every", "2s", "--iterations", "2",
		"--include-guest", "--include-services", "--include-db", "--include-ebpf-latency",
		"--output-dir", "reports", "--json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Victim != "a-web" || !options.DiscoverSuspects || !options.JSON ||
		options.Duration != time.Second || options.Interval != time.Second || options.Every != 2*time.Second || options.Iterations != 2 ||
		options.OutputDirectory != "reports" || !options.IncludeGuest || !options.IncludeServices || !options.IncludeDB || !options.IncludeEBPFLatency {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseObserveWatchDefaults(t *testing.T) {
	options, err := parseObserveWatchArgs([]string{"observe", "watch", "--victim", "a-web", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Duration != 10*time.Second || options.Interval != 2*time.Second || options.Every != 30*time.Second || options.Iterations != 0 {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseObserveWatchValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "victim required", args: []string{"observe", "watch", "--json"}, want: "--victim is required"},
		{name: "json required", args: []string{"observe", "watch", "--victim", "a-web"}, want: "--json is required"},
		{name: "suspect conflict", args: []string{"observe", "watch", "--victim", "a-web", "--suspect", "b-stress", "--discover-suspects", "--json"}, want: "cannot be used together"},
		{name: "invalid iterations", args: []string{"observe", "watch", "--victim", "a-web", "--iterations", "0", "--json"}, want: "invalid --iterations"},
		{name: "invalid every", args: []string{"observe", "watch", "--victim", "a-web", "--every", "0s", "--json"}, want: "invalid --every"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseObserveWatchArgs(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestOpenObserveWatchOutputCreatesSanitizedJSONLFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "nested", "observe")
	path, file, err := openObserveWatchOutput(directory, "tenant/a web", time.Date(2026, 8, 9, 10, 11, 12, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "observe-watch-20260809T101112Z-tenant_a_web.jsonl" {
		t.Fatalf("path = %q", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestParseGuestAndServiceStatusJSON(t *testing.T) {
	for _, command := range []string{"guest", "service", "db"} {
		for _, args := range [][]string{{command, "status", "--vm", "a-web", "--json"}, {command, "status", "--json", "--vm", "a-web"}} {
			name, err := parseVMJSONStatusArgs(args, command)
			if err != nil || name != "a-web" {
				t.Fatalf("parse %v = %q, %v", args, name, err)
			}
		}
		if _, err := parseVMJSONStatusArgs([]string{command, "status", "--json"}, command); err == nil {
			t.Fatalf("%s accepted missing VM", command)
		}
	}
}

func TestLoadDatabaseTargetRejectsUnknownAndMissingConfig(t *testing.T) {
	database := solisconfig.DatabaseObservabilityConfig{VM: "a-db", Kind: "postgresql", Database: "postgres"}
	runtime := testDBRuntime(t, []solisconfig.DatabaseObservabilityConfig{database})
	if _, _, _, err := loadDatabaseTarget(runtime, "missing"); err == nil || !strings.Contains(err.Error(), "VM not found: missing") {
		t.Fatalf("unknown VM error = %v", err)
	}
	runtime = testDBRuntime(t, nil)
	if _, _, _, err := loadDatabaseTarget(runtime, "a-db"); err == nil || !strings.Contains(err.Error(), "no database configured for VM: a-db") {
		t.Fatalf("missing DB config error = %v", err)
	}
}

func TestLoadDatabaseTargetRejectsUnsupportedKind(t *testing.T) {
	runtime := testDBRuntime(t, []solisconfig.DatabaseObservabilityConfig{{VM: "a-db", Kind: "mysql", Database: "postgres"}})
	if _, _, _, err := loadDatabaseTarget(runtime, "a-db"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported kind error = %v", err)
	}
}

func TestConfiguredDatabaseCollectionUsesFakeRunner(t *testing.T) {
	database := solisconfig.DatabaseObservabilityConfig{VM: "a-db", Kind: "postgresql", Database: "postgres", CollectPGStatStatements: true}
	runtime := testDBRuntime(t, []solisconfig.DatabaseObservabilityConfig{database})
	vm, guestConfig, configured, err := loadDatabaseTarget(runtime, "a-db")
	if err != nil {
		t.Fatal(err)
	}
	runner := completeCLIDBFakeRunner(t, configured.Database)
	var output bytes.Buffer
	if err := runDBStatusWithRunner(context.Background(), *vm, guestConfig, configured, runner, &output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"engine": "postgresql"`, `"name": "postgres"`, `"query_text_collected": false`, `"table_data_collected": false`, `"secrets_collected": false`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("DB JSON missing %q:\n%s", want, output.String())
		}
	}
}

func TestGuestStatusDisabled(t *testing.T) {
	var stdout bytes.Buffer
	err := Run([]string{"guest", "status", "--vm", "a-web", "--json"}, &stdout, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "guest collection is disabled in configuration") {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestLoadGuestTargetRejectsUnknownVM(t *testing.T) {
	runtime := testGuestRuntime(t, nil)
	_, _, _, err := loadGuestTarget(runtime, "missing")
	if err == nil || !strings.Contains(err.Error(), "VM not found: missing") {
		t.Fatalf("loadGuestTarget() error = %v", err)
	}
}

func TestServiceStatusRejectsVMWithoutConfiguredServices(t *testing.T) {
	runtime := testGuestRuntime(t, nil)
	var output bytes.Buffer
	err := runServiceStatus(runtime, "a-web", &output)
	if err == nil || !strings.Contains(err.Error(), "no services configured for VM: a-web") {
		t.Fatalf("runServiceStatus() error = %v", err)
	}
}

func TestConfiguredGuestCollectionUsesFakeRunner(t *testing.T) {
	runtime := testGuestRuntime(t, []solisconfig.ServiceObservabilityConfig{{ID: "web", VM: "a-web"}})
	vm, guestConfig, refs, err := loadGuestTarget(runtime, "a-web")
	if err != nil {
		t.Fatal(err)
	}
	runner := completeCLIFakeRunner()
	var output bytes.Buffer
	if err := runGuestStatusWithRunner(context.Background(), *vm, guestConfig, refs, runner, &output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name": "a-web"`, `"hostname": "a-web"`, `"service_refs": [`, `"web"`, `"process_arguments_collected": false`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("guest JSON missing %q:\n%s", want, output.String())
		}
	}
}

func TestConfiguredServiceCollectionUsesFakeRunner(t *testing.T) {
	services := []solisconfig.ServiceObservabilityConfig{{ID: "web", VM: "a-web", Units: []string{"nginx.service"}}}
	runtime := testGuestRuntime(t, services)
	vm, guestConfig, _, err := loadGuestTarget(runtime, "a-web")
	if err != nil {
		t.Fatal(err)
	}
	runner := completeCLIFakeRunner()
	var output bytes.Buffer
	if err := runServiceStatusWithRunner(context.Background(), *vm, guestConfig, services, runner, &output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name": "web"`, `"id": "nginx.service"`, `"response_body_collected": false`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("service JSON missing %q:\n%s", want, output.String())
		}
	}
}

func testGuestRuntime(t *testing.T, services []solisconfig.ServiceObservabilityConfig) solisconfig.Runtime {
	t.Helper()
	inventoryPath := filepath.Join(t.TempDir(), "vms.csv")
	if err := os.WriteFile(inventoryPath, []byte("name,tenant,network,ip,memory_mb,vcpus,disk_gb,role\na-web,tenant-a,tenant-a-net,192.0.2.20,1024,1,10,web\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := solisconfig.Settings{
		SchemaVersion: solisconfig.SchemaVersion2, InventoryCSV: inventoryPath, CaptureOutputRoot: t.TempDir(), LibvirtURI: "qemu:///system",
		Thresholds: solisconfig.DefaultThresholds(),
		Observability: &solisconfig.ObservabilityConfig{
			Guest:    solisconfig.GuestObservabilityConfig{Enabled: true, Transport: "ssh", User: "flint", ConnectTimeout: "1s", MaxParallel: 1, KnownHosts: filepath.Join(t.TempDir(), "known_hosts")},
			Services: services, Databases: []solisconfig.DatabaseObservabilityConfig{},
		},
	}
	return solisconfig.Runtime{Settings: settings, Source: "test", BaseDir: t.TempDir()}
}

func testDBRuntime(t *testing.T, databases []solisconfig.DatabaseObservabilityConfig) solisconfig.Runtime {
	t.Helper()
	inventoryPath := filepath.Join(t.TempDir(), "vms.csv")
	if err := os.WriteFile(inventoryPath, []byte("name,tenant,network,ip,memory_mb,vcpus,disk_gb,role\na-db,tenant-a,tenant-a-net,192.0.2.30,1024,1,10,db\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := solisconfig.Settings{
		SchemaVersion: solisconfig.SchemaVersion2, InventoryCSV: inventoryPath, CaptureOutputRoot: t.TempDir(), LibvirtURI: "qemu:///system",
		Thresholds: solisconfig.DefaultThresholds(),
		Observability: &solisconfig.ObservabilityConfig{
			Guest:    solisconfig.GuestObservabilityConfig{Transport: "ssh", User: "flint", ConnectTimeout: "1s", KnownHosts: filepath.Join(t.TempDir(), "known_hosts")},
			Services: []solisconfig.ServiceObservabilityConfig{}, Databases: databases,
		},
	}
	return solisconfig.Runtime{Settings: settings, Source: "test", BaseDir: t.TempDir()}
}

func completeCLIFakeRunner() fakeGuestRunner {
	unit, _ := guest.SystemdUnitCommand("nginx.service")
	return fakeGuestRunner{outputs: map[string]string{
		guest.HostnameCommand().Key(): "a-web\n", guest.KernelReleaseCommand().Key(): "7.0.0\n",
		guest.UptimeCommand().Key(): "10 1\n", guest.LoadCommand().Key(): "0.1 0.2 0.3 1/1 1\n",
		guest.MemoryCommand().Key():          "MemTotal: 1024 kB\nMemAvailable: 512 kB\n",
		guest.FilesystemsCommand().Key():     "Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/vda1 1000 100 900 10% /\n",
		guest.NetworkAddressCommand().Key():  "eth0 UP 192.0.2.20/24\n",
		guest.NetworkCountersCommand().Key(): "eth0: 1 1 0 0 0 0 0 0 2 2 0 0 0 0 0 0\n",
		guest.ListeningPortsCommand().Key():  "tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1,fd=3))\n",
		guest.ProcessPressureCommand().Key(): "1 0 nginx 1.0 1.0\n",
		unit.Key():                           "Id=nginx.service\nActiveState=active\nSubState=running\nMainPID=1\nNRestarts=0\n",
	}}
}

func completeCLIDBFakeRunner(t *testing.T, database string) fakeGuestRunner {
	t.Helper()
	version, err := guest.PostgreSQLVersionCommand(database)
	if err != nil {
		t.Fatal(err)
	}
	databases, err := guest.PostgreSQLDatabasesCommand(database)
	if err != nil {
		t.Fatal(err)
	}
	activity, err := guest.PostgreSQLActivityCommand(database)
	if err != nil {
		t.Fatal(err)
	}
	extensions, err := guest.PostgreSQLExtensionsCommand(database)
	if err != nil {
		t.Fatal(err)
	}
	statements, err := guest.PostgreSQLStatementsCommand(database)
	if err != nil {
		t.Fatal(err)
	}
	return fakeGuestRunner{outputs: map[string]string{
		version.Key():    "PostgreSQL 16.4\n",
		databases.Key():  "postgres,2,100,1,10,1000,0\n",
		activity.Key():   "10,postgres,postgres,active,Lock,transactionid,00:00:01\n",
		extensions.Key(): "plpgsql\npg_stat_statements\n",
		statements.Key(): "10,5,100.0,20.0,50\n",
	}}
}

func TestHostStatusOptionsRespectSchemaVersionTwoHostSettings(t *testing.T) {
	settings := solisconfig.Settings{Observability: &solisconfig.ObservabilityConfig{
		Host: solisconfig.HostObservabilityConfig{
			Interval: "250ms", CollectPSI: false, CollectNetwork: true,
		},
	}}
	options, err := hostStatusOptions(settings)
	if err != nil {
		t.Fatal(err)
	}
	if options.Interval != 250*time.Millisecond || options.CollectPSI || !options.CollectNetwork {
		t.Fatalf("options = %#v", options)
	}
}

func TestRunDoctorLabModeIsExplicit(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "solis.json")
	if err := os.WriteFile(configPath, []byte(`{
  "schema_version": "1",
  "inventory_csv": "missing.csv",
  "capture_output_root": "captures",
  "default_report_dir": "reports",
  "libvirt_uri": "qemu:///system",
  "thresholds": {"write_mib_per_sec": 10, "write_syscalls_per_sec": 10000, "dominance_ratio": 2}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		args    []string
		wantLab bool
	}{
		{[]string{"--config", configPath, "doctor"}, false},
		{[]string{"doctor", "--lab", "--config", configPath}, true},
	} {
		var output bytes.Buffer
		if err := Run(test.args, &output, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "Lab checks:") != test.wantLab {
			t.Fatalf("args %v output lab mode mismatch:\n%s", test.args, output.String())
		}
	}
}

func writeExecutable(t *testing.T, directory, name, content string) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestParseEBPFBlockWatchArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    time.Duration
		wantErr string
	}{
		{name: "default", args: []string{"ebpf", "block-watch"}, want: 10 * time.Second},
		{name: "explicit", args: []string{"ebpf", "block-watch", "--duration", "2.5s"}, want: 2500 * time.Millisecond},
		{name: "invalid", args: []string{"ebpf", "block-watch", "--duration", "0s"}, wantErr: "invalid --duration"},
		{name: "unknown option", args: []string{"ebpf", "block-watch", "--interval", "1s"}, wantErr: ebpfBlockWatchUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseEBPFBlockWatchArgs(test.args)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseEBPFBlockWatchArgs() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("duration = %s, want %s", got, test.want)
			}
		})
	}
}

func TestParseRequiredEBPFDuration(t *testing.T) {
	duration, err := parseRequiredEBPFDuration(
		[]string{"ebpf", "block-count", "--duration", "10s"},
		"block-count",
		ebpfBlockCountUsage,
	)
	if err != nil || duration != 10*time.Second {
		t.Fatalf("duration = %s, error = %v", duration, err)
	}

	for _, args := range [][]string{
		{"ebpf", "block-count"},
		{"ebpf", "block-count", "--duration", "0s"},
		{"ebpf", "block-count", "--interval", "1s"},
	} {
		if _, err := parseRequiredEBPFDuration(args, "block-count", ebpfBlockCountUsage); err == nil {
			t.Errorf("args %v: expected error", args)
		}
	}
}

func TestParseEBPFBlockLatencyArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantVictim   string
		wantSuspect  string
		wantDuration time.Duration
		wantErr      string
	}{
		{
			name:         "host wide",
			args:         []string{"ebpf", "block-latency", "--duration", "750ms"},
			wantDuration: 750 * time.Millisecond,
		},
		{
			name:         "VM aware",
			args:         []string{"ebpf", "block-latency", "--suspect", "b-stress", "--duration", "10s", "--victim", "a-web"},
			wantVictim:   "a-web",
			wantSuspect:  "b-stress",
			wantDuration: 10 * time.Second,
		},
		{
			name:    "victim without suspect",
			args:    []string{"ebpf", "block-latency", "--victim", "a-web", "--duration", "10s"},
			wantErr: "--victim and --suspect must be provided together",
		},
		{
			name:    "suspect without victim",
			args:    []string{"ebpf", "block-latency", "--suspect", "b-stress", "--duration", "10s"},
			wantErr: "--victim and --suspect must be provided together",
		},
		{
			name:    "missing duration",
			args:    []string{"ebpf", "block-latency", "--victim", "a-web", "--suspect", "b-stress"},
			wantErr: ebpfBlockLatencyUsage,
		},
		{
			name:    "duplicate option",
			args:    []string{"ebpf", "block-latency", "--duration", "10s", "--duration", "20s"},
			wantErr: "duplicate option --duration",
		},
		{
			name:    "invalid duration",
			args:    []string{"ebpf", "block-latency", "--duration", "0s"},
			wantErr: "invalid --duration",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, err := parseEBPFBlockLatencyArgs(test.args)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if options.Victim != test.wantVictim || options.Suspect != test.wantSuspect || options.Duration != test.wantDuration {
				t.Fatalf("options = %#v", options)
			}
		})
	}
}

func TestParseQEMUIOWatchArgsDefaults(t *testing.T) {
	victim, suspect, duration, interval, err := parseQEMUIOWatchArgs([]string{
		"qemu", "io-watch", "--victim", "tenant-a", "--suspect", "b-stress",
	})
	if err != nil {
		t.Fatalf("parseQEMUIOWatchArgs() error = %v", err)
	}
	if victim != "tenant-a" || suspect != "b-stress" {
		t.Fatalf("selectors = %q, %q, want tenant-a, b-stress", victim, suspect)
	}
	if duration != 30*time.Second || interval != 5*time.Second {
		t.Fatalf("durations = %s, %s, want 30s, 5s", duration, interval)
	}
}

func TestParseQEMUIOWatchArgsRejectsLongInterval(t *testing.T) {
	_, _, _, _, err := parseQEMUIOWatchArgs([]string{
		"qemu", "io-watch",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
		"--duration", "1s",
		"--interval", "2s",
	})
	if err == nil || !strings.Contains(err.Error(), "interval 2s cannot exceed duration 1s") {
		t.Fatalf("parseQEMUIOWatchArgs() error = %v, want interval validation error", err)
	}
}

func TestParseQEMUIOSummaryArgsDefaults(t *testing.T) {
	victim, suspect, duration, interval, err := parseQEMUIOSummaryArgs([]string{
		"qemu", "io-summary", "--victim", "tenant-a", "--suspect", "b-stress",
	})
	if err != nil {
		t.Fatalf("parseQEMUIOSummaryArgs() error = %v", err)
	}
	if victim != "tenant-a" || suspect != "b-stress" {
		t.Fatalf("selectors = %q, %q, want tenant-a, b-stress", victim, suspect)
	}
	if duration != 30*time.Second || interval != 5*time.Second {
		t.Fatalf("durations = %s, %s, want 30s, 5s", duration, interval)
	}
}

func TestParseDiagnoseNoisyNeighborArgsDefaults(t *testing.T) {
	options, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "lab/reports/workload/test",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
	})
	if err != nil {
		t.Fatalf("parseDiagnoseNoisyNeighborArgs() error = %v", err)
	}
	if options.ReportDirectory != "lab/reports/workload/test" || options.Victim != "tenant-a" || options.Suspect != "b-stress" {
		t.Fatalf("options = %#v, want requested report and selectors", options)
	}
	if options.Duration != 10*time.Second || options.Interval != 2*time.Second {
		t.Fatalf("durations = %s, %s, want 10s, 2s", options.Duration, options.Interval)
	}
}

func TestParseDiagnoseNoisyNeighborIncludesEBPFLatency(t *testing.T) {
	options, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--include-ebpf-latency",
		"--report-dir", "report",
		"--victim", "a-web",
		"--suspect", "b-stress",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.IncludeEBPFLatency {
		t.Fatal("IncludeEBPFLatency = false, want true")
	}
}

func TestDiagnoseHelpIsAFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run([]string{"diagnose", "noisy-neighbor", "--help"}, &stdout, &stderr); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(stdout.String(), diagnoseNoisyNeighborUsage) || strings.Contains(stdout.String(), "requires a value") {
		t.Fatalf("help output = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestParseDiagnoseBooleanForms(t *testing.T) {
	for _, test := range []struct {
		name string
		json string
		ebpf string
	}{
		{name: "bare", json: "--json", ebpf: "--include-ebpf-latency"},
		{name: "explicit true", json: "--json=true", ebpf: "--include-ebpf-latency=true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, err := parseDiagnoseNoisyNeighborArgs([]string{
				"diagnose", "noisy-neighbor",
				"--victim", "a-web", "--suspect", "b-stress",
				test.json, test.ebpf,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !options.JSON || !options.IncludeEBPFLatency {
				t.Fatalf("options = %#v", options)
			}
		})
	}
}

func TestRelocateLeadingGlobalJSONForDiagnose(t *testing.T) {
	for _, flag := range []string{"--json", "--json=true"} {
		args, err := relocateLeadingGlobalJSON([]string{
			flag, "diagnose", "noisy-neighbor", "--victim", "a-web", "--suspect", "b-stress",
		})
		if err != nil {
			t.Fatal(err)
		}
		options, err := parseDiagnoseNoisyNeighborArgs(args)
		if err != nil {
			t.Fatal(err)
		}
		if !options.JSON {
			t.Fatalf("%s did not enable JSON: %#v", flag, options)
		}
	}
}

func TestParseDiagnoseBooleanFalseAndInvalid(t *testing.T) {
	options, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor", "--victim", "a-web", "--suspect", "b-stress",
		"--json=false", "--include-ebpf-latency=false",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.JSON || options.IncludeEBPFLatency {
		t.Fatalf("false boolean options = %#v", options)
	}
	_, err = parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor", "--victim", "a-web", "--suspect", "b-stress", "--json=maybe",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid boolean value for --json") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseDiagnoseNoisyNeighborDiscoversSuspects(t *testing.T) {
	options, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--discover-suspects",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.DiscoverSuspects || options.Suspect != "" {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseDiagnoseNoisyNeighborAllowsLiveOnlyMode(t *testing.T) {
	options, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--victim", "a-web",
		"--discover-suspects",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.ReportDirectory != "" || !options.DiscoverSuspects {
		t.Fatalf("options = %#v, want live-only discovery", options)
	}
}

func TestParseDiagnoseNoisyNeighborRequiresSuspectMode(t *testing.T) {
	_, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
	})
	if err == nil || !strings.Contains(err.Error(), "provide either --suspect <vm> or --discover-suspects") {
		t.Fatalf("error = %v, want suspect mode usage error", err)
	}
}

func TestParseDiagnoseNoisyNeighborRejectsSuspectAndDiscovery(t *testing.T) {
	_, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--suspect", "b-stress",
		"--discover-suspects",
	})
	if err == nil || !strings.Contains(err.Error(), "--suspect and --discover-suspects cannot be used together") {
		t.Fatalf("error = %v, want selector conflict", err)
	}
}

func TestParseDiagnoseNoisyNeighborOutputPath(t *testing.T) {
	options, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
		"--output", "reports/diagnosis.txt",
	})
	if err != nil {
		t.Fatalf("parseDiagnoseNoisyNeighborArgs() error = %v", err)
	}
	if options.OutputPath != "reports/diagnosis.txt" || options.OutputDirectory != "" {
		t.Fatalf("output options = %#v, want exact output path", options)
	}
}

func TestParseDiagnoseNoisyNeighborRejectsOutputConflict(t *testing.T) {
	_, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
		"--output", "diagnosis.txt",
		"--output-dir", "reports",
	})
	if err == nil || !strings.Contains(err.Error(), "--output and --output-dir cannot be used together") {
		t.Fatalf("parseDiagnoseNoisyNeighborArgs() error = %v, want output conflict", err)
	}
}

func TestParseCaptureNoisyNeighborDefaults(t *testing.T) {
	options, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--report-dir", "lab/reports/workload/test",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
		"--output-dir", "lab/reports/captures",
	})
	if err != nil {
		t.Fatalf("parseCaptureNoisyNeighborArgs() error = %v", err)
	}
	if options.Duration != 10*time.Second || options.Interval != 2*time.Second {
		t.Fatalf("durations = %s, %s, want 10s, 2s", options.Duration, options.Interval)
	}
	if options.OutputDirectory != "lab/reports/captures" {
		t.Fatalf("OutputDirectory = %q, want lab/reports/captures", options.OutputDirectory)
	}
	if options.DiscoverSuspects {
		t.Fatal("DiscoverSuspects = true in pairwise mode")
	}
}

func TestParseCaptureNoisyNeighborDiscoversSuspects(t *testing.T) {
	options, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--discover-suspects",
		"--output-dir", "captures",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.DiscoverSuspects || options.Suspect != "" {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseCaptureNoisyNeighborAllowsLiveOnlyMode(t *testing.T) {
	options, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--victim", "a-web",
		"--discover-suspects",
		"--output-dir", "captures",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.ReportDirectory != "" || !options.DiscoverSuspects {
		t.Fatalf("options = %#v, want live-only discovery", options)
	}
}

func TestParseCaptureNoisyNeighborRequiresSuspectMode(t *testing.T) {
	_, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--output-dir", "captures",
	})
	if err == nil || !strings.Contains(err.Error(), "provide either --suspect <vm> or --discover-suspects") {
		t.Fatalf("error = %v, want suspect mode usage error", err)
	}
}

func TestParseCaptureNoisyNeighborRejectsSuspectAndDiscovery(t *testing.T) {
	_, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--suspect", "b-stress",
		"--discover-suspects",
		"--output-dir", "captures",
	})
	if err == nil || !strings.Contains(err.Error(), "--suspect and --discover-suspects cannot be used together") {
		t.Fatalf("error = %v, want selector conflict", err)
	}
}

func TestParseCaptureNoisyNeighborIncludesEBPFLatency(t *testing.T) {
	options, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--suspect", "b-stress",
		"--include-ebpf-latency",
		"--output-dir", "captures",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.IncludeEBPFLatency {
		t.Fatal("IncludeEBPFLatency = false, want true")
	}
}

func TestParseCaptureNoisyNeighborExplicitBooleanValues(t *testing.T) {
	options, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor", "--victim", "a-web", "--suspect", "b-stress",
		"--include-ebpf-latency=true", "--output-dir", "captures",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.IncludeEBPFLatency {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseNoisyNeighborRejectsDuplicateEBPFLatencyFlag(t *testing.T) {
	_, err := parseDiagnoseNoisyNeighborArgs([]string{
		"diagnose", "noisy-neighbor",
		"--report-dir", "report",
		"--victim", "a-web",
		"--suspect", "b-stress",
		"--include-ebpf-latency",
		"--include-ebpf-latency",
	})
	if err == nil || !strings.Contains(err.Error(), "--include-ebpf-latency specified more than once") {
		t.Fatalf("error = %v, want duplicate flag error", err)
	}
}

func TestParseCaptureNoisyNeighborRequiresOutputDirectory(t *testing.T) {
	_, err := parseCaptureNoisyNeighborArgs([]string{
		"capture", "noisy-neighbor",
		"--victim", "tenant-a",
		"--suspect", "b-stress",
	})
	if err == nil || !strings.Contains(err.Error(), "missing --output-dir") {
		t.Fatalf("parseCaptureNoisyNeighborArgs() error = %v, want missing output directory", err)
	}
}

func TestParseWatchNoisyNeighbor(t *testing.T) {
	options, err := parseWatchNoisyNeighborArgs([]string{
		"watch", "noisy-neighbor",
		"--victim", "a-web",
		"--discover-suspects",
		"--window", "8s",
		"--every", "20s",
		"--iterations", "3",
		"--include-ebpf-latency",
		"--capture-on-alert",
		"--cooldown", "90s",
		"--output-dir", "captures",
		"--verbose",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Victim != "a-web" || !options.DiscoverSuspects || options.Suspect != "" {
		t.Fatalf("selectors = %#v", options)
	}
	if options.Window != 8*time.Second || options.Every != 20*time.Second || options.Iterations != 3 {
		t.Fatalf("timing = %#v", options)
	}
	if !options.IncludeEBPFLatency || !options.CaptureOnAlert || !options.Verbose {
		t.Fatalf("flags = %#v", options)
	}
	if options.Cooldown != 90*time.Second || options.OutputDirectory != "captures" {
		t.Fatalf("capture options = %#v", options)
	}
}

func TestParseWatchNoisyNeighborExplicitBooleanValues(t *testing.T) {
	options, err := parseWatchNoisyNeighborArgs([]string{
		"watch", "noisy-neighbor", "--victim", "a-web", "--discover-suspects=true",
		"--include-ebpf-latency=true", "--capture-on-alert=true", "--verbose=true",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.DiscoverSuspects || !options.IncludeEBPFLatency || !options.CaptureOnAlert || !options.Verbose {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseWatchNoisyNeighborDefaults(t *testing.T) {
	options, err := parseWatchNoisyNeighborArgs([]string{
		"watch", "noisy-neighbor",
		"--victim", "a-web",
		"--suspect", "b-stress",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Window != 10*time.Second || options.Every != 30*time.Second || options.Cooldown != 2*time.Minute {
		t.Fatalf("defaults = %#v", options)
	}
	if options.OutputDirectory != "lab/reports/captures" || options.Iterations != 0 {
		t.Fatalf("defaults = %#v", options)
	}
}

func TestParseWatchNoisyNeighborSelectorValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing victim",
			args: []string{"watch", "noisy-neighbor", "--discover-suspects"},
			want: "missing --victim",
		},
		{
			name: "missing suspect mode",
			args: []string{"watch", "noisy-neighbor", "--victim", "a-web"},
			want: "provide either --suspect <vm> or --discover-suspects",
		},
		{
			name: "conflicting suspect mode",
			args: []string{
				"watch", "noisy-neighbor",
				"--victim", "a-web",
				"--suspect", "b-stress",
				"--discover-suspects",
			},
			want: "--suspect and --discover-suspects cannot be used together",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseWatchNoisyNeighborArgs(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestWriteWatchCapturePathsIncludesEvidenceJSON(t *testing.T) {
	var output bytes.Buffer
	result := capture.Result{
		Directory: "lab/reports/captures/capture-example",
		Files:     []string{"lab/reports/captures/capture-example/ebpf-vm-block-latency.json"},
	}
	if err := writeWatchCapturePaths(&output, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Capture directory: lab/reports/captures/capture-example",
		"Incident report: lab/reports/captures/capture-example/incident-report.md",
		"Evidence JSON: lab/reports/captures/capture-example/evidence-summary.json",
		"eBPF VM attribution JSON: lab/reports/captures/capture-example/ebpf-vm-block-latency.json",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestParseStatusArgsDefaults(t *testing.T) {
	options, err := parseStatusArgs([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Duration != 3*time.Second || options.Interval != time.Second || options.JSON || options.Watch {
		t.Fatalf("options = %#v", options)
	}
	if options.Every != 2*time.Second || options.Iterations != 0 || !options.Clear || options.Sort != "name" {
		t.Fatalf("watch defaults = %#v", options)
	}
}

func TestParseStatusWatchArgs(t *testing.T) {
	options, err := parseStatusArgs([]string{
		"status",
		"--watch",
		"--duration", "1s",
		"--interval", "1s",
		"--every", "2s",
		"--iterations", "3",
		"--no-clear",
		"--sort", "pressure",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.Watch || options.Every != 2*time.Second || options.Iterations != 3 || options.Clear || options.Sort != "pressure" {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseStatusWatchRejectsJSON(t *testing.T) {
	_, err := parseStatusArgs([]string{"status", "--watch", "--json"})
	want := "solis status --watch does not support --json yet"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestParseStatusRejectsInvalidSort(t *testing.T) {
	_, err := parseStatusArgs([]string{"status", "--watch", "--sort", "latency"})
	if err == nil || !strings.Contains(err.Error(), "invalid --sort field \"latency\"") {
		t.Fatalf("error = %v, want invalid sort field", err)
	}
}

func TestParseStatusArgsJSONAndTiming(t *testing.T) {
	options, err := parseStatusArgs([]string{
		"status", "--json", "--interval", "500ms", "--duration", "2s",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.JSON || options.Duration != 2*time.Second || options.Interval != 500*time.Millisecond {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseStatusArgsValidatesOptions(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"status", "--duration", "0s"}, want: "invalid --duration"},
		{args: []string{"status", "--duration", "1s", "--interval", "2s"}, want: "interval 2s cannot exceed duration 1s"},
		{args: []string{"status", "--verbose"}, want: "unknown option --verbose"},
	} {
		_, err := parseStatusArgs(test.args)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("args %v: error = %v, want %q", test.args, err, test.want)
		}
	}
}

func TestParseTopArgs(t *testing.T) {
	options, err := parseTopArgs([]string{
		"top",
		"--duration", "4s",
		"--interval", "1s",
		"--every", "6s",
		"--ui-refresh", "250ms",
		"--iterations", "3",
		"--include-ebpf-latency",
		"--no-clear",
		"--sort", "ops",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Duration != 4*time.Second || options.Interval != time.Second || options.Every != 6*time.Second || options.UIRefresh != 250*time.Millisecond ||
		options.Iterations != 3 || !options.IncludeEBPFLatency || options.Clear || options.Sort != "ops" {
		t.Fatalf("options = %#v", options)
	}
	defaults, err := parseTopArgs([]string{"top"})
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Duration != 3*time.Second || defaults.Interval != time.Second || defaults.Every != 5*time.Second ||
		defaults.UIRefresh != 0 || defaults.Iterations != 0 || defaults.IncludeEBPFLatency || !defaults.Clear || defaults.Sort != "pressure" {
		t.Fatalf("defaults = %#v", defaults)
	}
}

func TestParseTopBooleanValuesAndValidation(t *testing.T) {
	options, err := parseTopArgs([]string{"top", "--include-ebpf-latency=true", "--clear=false"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.IncludeEBPFLatency || options.Clear {
		t.Fatalf("options = %#v", options)
	}
	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"top", "--duration", "1s", "--interval", "2s"}, want: "cannot exceed duration"},
		{args: []string{"top", "--sort", "tenant"}, want: "invalid --sort field"},
		{args: []string{"top", "--iterations", "0"}, want: "invalid --iterations"},
		{args: []string{"top", "--ui-refresh", "50ms"}, want: "must be at least 100ms"},
		{args: []string{"top", "--clear", "--no-clear"}, want: "cannot be used together"},
		{args: []string{"top", "--json"}, want: "unknown option --json"},
	} {
		if _, err := parseTopArgs(test.args); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("parseTopArgs(%v) error = %v, want %q", test.args, err, test.want)
		}
	}
}

func TestTopHelpUsesImplementedCommandUsage(t *testing.T) {
	var stdout bytes.Buffer
	if err := Run([]string{"top", "--help"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout.String()) != topUsage {
		t.Fatalf("help = %q, want %q", strings.TrimSpace(stdout.String()), topUsage)
	}
}

func TestOperatorCommandExpansion(t *testing.T) {
	monitor, err := expandOperatorCommand([]string{"monitor", "--sort", "ops"}, "/var/lib/solis/captures")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]string{
		{"top"}, {"--application"}, {"--sort", "ops"}, {"--duration", "5s"}, {"--every", "7s"}, {"--ui-refresh", "200ms"}, {"--include-ebpf-latency"},
	} {
		if !containsArguments(monitor, want) {
			t.Errorf("monitor expansion %v missing %v", monitor, want)
		}
	}
	monitorOptions, err := parseTopArgs(monitor)
	if err != nil {
		t.Fatalf("expanded monitor did not parse: %v", err)
	}
	if monitorOptions.Duration != 5*time.Second || monitorOptions.Every != 7*time.Second || monitorOptions.UIRefresh != 200*time.Millisecond ||
		!monitorOptions.IncludeEBPFLatency || !monitorOptions.Application {
		t.Fatalf("monitor defaults = %#v", monitorOptions)
	}

	investigate, err := expandOperatorCommand([]string{"investigate", "a-web", "--json"}, "/var/lib/solis/captures")
	if err != nil {
		t.Fatal(err)
	}
	wantInvestigate := []string{
		"diagnose", "noisy-neighbor", "--victim", "a-web", "--discover-suspects",
		"--include-ebpf-latency", "--json",
	}
	if strings.Join(investigate, " ") != strings.Join(wantInvestigate, " ") {
		t.Fatalf("investigate expansion = %v, want %v", investigate, wantInvestigate)
	}
	investigateOptions, err := parseDiagnoseNoisyNeighborArgs(investigate)
	if err != nil {
		t.Fatalf("expanded investigate did not parse: %v", err)
	}
	if investigateOptions.Victim != "a-web" || !investigateOptions.DiscoverSuspects || !investigateOptions.IncludeEBPFLatency || !investigateOptions.JSON {
		t.Fatalf("investigate options = %#v", investigateOptions)
	}

	bundle, err := expandOperatorCommand([]string{"bundle", "a-web", "b-stress"}, "/var/lib/solis/captures")
	if err != nil {
		t.Fatal(err)
	}
	wantBundle := []string{
		"capture", "noisy-neighbor", "--victim", "a-web", "--suspect", "b-stress",
		"--include-ebpf-latency", "--output-dir", "/var/lib/solis/captures",
	}
	if strings.Join(bundle, " ") != strings.Join(wantBundle, " ") {
		t.Fatalf("bundle expansion = %v, want %v", bundle, wantBundle)
	}
	bundleOptions, err := parseCaptureNoisyNeighborArgs(bundle)
	if err != nil {
		t.Fatalf("expanded bundle did not parse: %v", err)
	}
	if bundleOptions.Victim != "a-web" || bundleOptions.Suspect != "b-stress" ||
		!bundleOptions.IncludeEBPFLatency || bundleOptions.OutputDirectory != "/var/lib/solis/captures" {
		t.Fatalf("bundle options = %#v", bundleOptions)
	}
}

func TestOperatorCommandOverridesAndValidation(t *testing.T) {
	monitor, err := expandOperatorCommand([]string{
		"monitor", "--duration", "9s", "--every", "10s", "--ui-refresh", "300ms", "--include-ebpf-latency=false",
	}, "captures")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.Join(monitor, " "), "--duration") != 1 ||
		strings.Count(strings.Join(monitor, " "), "--every") != 1 ||
		strings.Count(strings.Join(monitor, " "), "--ui-refresh") != 1 ||
		strings.Count(strings.Join(monitor, " "), "--include-ebpf-latency") != 1 {
		t.Fatalf("monitor defaults duplicated explicit options: %v", monitor)
	}
	bundle, err := expandOperatorCommand([]string{"bundle", "a-web", "--output-dir", "/tmp/captures", "--include-ebpf-latency=false"}, "captures")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.Join(bundle, " "), "--output-dir") != 1 ||
		strings.Count(strings.Join(bundle, " "), "--include-ebpf-latency") != 1 {
		t.Fatalf("bundle defaults duplicated explicit options: %v", bundle)
	}
	for _, args := range [][]string{{"investigate"}, {"investigate", "--json"}, {"bundle"}} {
		if _, err := expandOperatorCommand(args, "captures"); err == nil {
			t.Errorf("expandOperatorCommand(%v) unexpectedly succeeded", args)
		}
	}
}

func TestOperatorCommandHelpAndBareNonTerminalBehavior(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"monitor", "--help"}, want: monitorUsage},
		{args: []string{"investigate", "--help"}, want: investigateUsage},
		{args: []string{"bundle", "--help"}, want: bundleUsage},
	} {
		var stdout bytes.Buffer
		if err := Run(test.args, &stdout, &bytes.Buffer{}); err != nil {
			t.Fatalf("Run(%v) error = %v", test.args, err)
		}
		if strings.TrimSpace(stdout.String()) != test.want {
			t.Errorf("Run(%v) help = %q, want %q", test.args, strings.TrimSpace(stdout.String()), test.want)
		}
	}
	var stdout bytes.Buffer
	if err := Run(nil, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Easy operator commands:") || !strings.Contains(stdout.String(), "sudo solis monitor") {
		t.Fatalf("bare non-terminal output did not remain helpful usage:\n%s", stdout.String())
	}
}

func TestTopInventoryProjectionExcludesProcessAndCgroupInternals(t *testing.T) {
	projected := projectTopInventory([]inventory.VM{{
		Name: "a-web", Tenant: "tenant-a", Role: "web", State: "running", Network: "tenant-a-net",
		IPPlan: "192.168.130.20", IPLease: "192.168.130.20", Memory: "2048", VCPUs: "2",
		DiskGB: "20", Disk: "/images/a-web.qcow2", QEMUPID: "1234", QEMUCmdline: "forbidden internal arguments",
	}})
	if len(projected) != 1 {
		t.Fatalf("projection = %#v", projected)
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"qemu_pid", "qemupid", "cmdline", "forbidden internal arguments", "cgroup", "request_pointer"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("inventory projection contains forbidden field %q: %s", forbidden, encoded)
		}
	}
}

func containsArguments(arguments, sequence []string) bool {
	for index := 0; index+len(sequence) <= len(arguments); index++ {
		if strings.Join(arguments[index:index+len(sequence)], "\x00") == strings.Join(sequence, "\x00") {
			return true
		}
	}
	return false
}

func TestParseVMStorageStatsArgs(t *testing.T) {
	options, err := parseVMStorageStatsArgs([]string{
		"vm", "storage-stats", "--victim", "a-web", "--suspect", "b-stress", "--json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Victim != "a-web" || options.Suspect != "b-stress" || options.Duration != 10*time.Second || options.Interval != time.Second || !options.JSON {
		t.Fatalf("options = %#v", options)
	}
	all, err := parseVMStorageStatsArgs([]string{"vm", "storage-stats", "--all-vms", "--duration", "5s", "--interval", "500ms", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if !all.AllVMs || all.Duration != 5*time.Second || all.Interval != 500*time.Millisecond {
		t.Fatalf("all options = %#v", all)
	}
}

func TestParseVMStorageStatsArgsValidation(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"vm", "storage-stats"}, want: "--json is required"},
		{args: []string{"vm", "storage-stats", "--suspect", "b-stress", "--json"}, want: "--suspect requires --victim"},
		{args: []string{"vm", "storage-stats", "--all-vms", "--victim", "a-web", "--json"}, want: "--all-vms cannot be combined"},
		{args: []string{"vm", "storage-stats", "--duration", "1s", "--interval", "2s", "--json"}, want: "--interval must not exceed --duration"},
	} {
		_, err := parseVMStorageStatsArgs(test.args)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("args %v: error = %v, want %q", test.args, err, test.want)
		}
	}
}

func TestSelectVMStorageStatsTargets(t *testing.T) {
	vms := []inventory.VM{
		{Name: "b-stress", State: "running"},
		{Name: "a-web", State: "running"},
		{Name: "a-db", State: "shut off"},
	}
	pair, err := selectVMStorageStatsTargets(vms, vmStorageStatsOptions{Victim: "a-web", Suspect: "b-stress"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pair) != 2 || pair[0].Name != "a-web" || pair[1].Name != "b-stress" {
		t.Fatalf("pair = %#v", pair)
	}
	all, err := selectVMStorageStatsTargets(vms, vmStorageStatsOptions{AllVMs: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].Name != "a-web" || all[1].Name != "b-stress" {
		t.Fatalf("all = %#v", all)
	}
	stopped, err := selectVMStorageStatsTargets(vms, vmStorageStatsOptions{Victim: "a-db"})
	if err != nil || len(stopped) != 1 || stopped[0].State != "shut off" {
		t.Fatalf("stopped explicit target = %#v, error = %v", stopped, err)
	}
	if _, err := selectVMStorageStatsTargets(vms, vmStorageStatsOptions{Victim: "missing"}); err == nil || !strings.Contains(err.Error(), "VM not found: missing") {
		t.Fatalf("unknown VM error = %v", err)
	}
}

func TestWriteVMStorageStatsOutputIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "stats.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	report := storagevm.VMStorageStatsReport{SchemaVersion: storagevm.SchemaVersion, VMs: []storagevm.VMStorageStatsVM{}}
	if err := writeVMStorageStatsOutput(path, report); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
	var decoded storagevm.VMStorageStatsReport
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != storagevm.SchemaVersion {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestWriteVMBlockLatencyOutputIsPrivateAndDeterministic(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "vm-block.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	report := ebpf.VMBlockLatencyReport{
		SchemaVersion: "1", ObservedAtUTC: "2026-08-10T00:00:00Z",
		Mode: "experimental", CollectionMode: "typed_btf_request_correlation_host_only",
		AttributionMethod: "host_request_correlation_no_vm_attribution", AttributionQuality: "unavailable",
		Availability: ebpf.VMBlockLatencyAvailability{Status: "object_unavailable"},
		VMs:          []ebpf.VMBlockLatencyVM{},
	}
	if err := writeVMBlockLatencyOutput(path, report); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeVMBlockLatencyOutput(path, report); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("atomic report output is not deterministic:\n%s\n%s", first, second)
	}
	var decoded ebpf.VMBlockLatencyReport
	if err := json.Unmarshal(second, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Availability.Status != "object_unavailable" {
		t.Fatalf("decoded report = %#v", decoded)
	}
}

func TestRunEBPFVMBlockLatencyWithoutOutputKeepsJSONOnStdout(t *testing.T) {
	directory := t.TempDir()
	inventoryPath := filepath.Join(directory, "vms.csv")
	if err := os.WriteFile(inventoryPath, []byte(
		"name,tenant,network,ip,memory_mb,vcpus,disk_gb,role\n"+
			"a-web,tenant-a,tenant-a-net,192.0.2.10,1024,1,10,web\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, directory, "virsh", "#!/bin/sh\nexit 1\n")
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	runtimeConfig := solisconfig.DevelopmentDefaults()
	runtimeConfig.Settings.InventoryCSV = inventoryPath
	var stdout bytes.Buffer
	if err := runEBPFVMBlockLatency(runtimeConfig, ebpfVMBlockLatencyOptions{
		Victim: "a-web", Duration: time.Second, Interval: time.Second, JSON: true,
	}, &stdout); err != nil {
		t.Fatal(err)
	}
	var decoded ebpf.VMBlockLatencyReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if decoded.CollectionMode != "typed_btf_request_correlation_host_only" || decoded.AttributionMethod != "host_request_correlation_no_vm_attribution" {
		t.Fatalf("stdout report = %#v", decoded)
	}
}
