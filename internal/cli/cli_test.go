package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/capture"
	solisconfig "github.com/safwen511/solis-io/internal/config"
	"github.com/safwen511/solis-io/internal/guest"
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
	result := capture.Result{Directory: "lab/reports/captures/capture-example"}
	if err := writeWatchCapturePaths(&output, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Capture directory: lab/reports/captures/capture-example",
		"Incident report: lab/reports/captures/capture-example/incident-report.md",
		"Evidence JSON: lab/reports/captures/capture-example/evidence-summary.json",
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
