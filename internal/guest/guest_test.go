package guest

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/observability"
)

type fakeRunner struct {
	outputs map[string]string
	errors  map[string]error
	calls   []string
}

// Run executes the receiver's bounded operation and propagates execution failures.
func (runner *fakeRunner) Run(_ context.Context, _ Target, command CommandSpec) (Result, error) {
	key := command.Key()
	runner.calls = append(runner.calls, key)
	if err := runner.errors[key]; err != nil {
		return Result{}, err
	}
	return Result{Output: runner.outputs[key]}, nil
}

// TestCommandAllowlistCannotBeOverridden verifies command allowlist cannot be overridden.
func TestCommandAllowlistCannotBeOverridden(t *testing.T) {
	if _, err := (CommandSpec{}).argv(); err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("zero CommandSpec argv error = %v", err)
	}
	for _, unit := range []string{"nginx.service;id", "nginx.service $(id)", "nginx.service/../../x"} {
		if _, err := SystemdUnitCommand(unit); err == nil {
			t.Errorf("unsafe unit %q accepted", unit)
		}
	}
	commands := []CommandSpec{
		HostnameCommand(), KernelReleaseCommand(), UptimeCommand(), LoadCommand(), MemoryCommand(),
		FilesystemsCommand(), NetworkAddressCommand(), NetworkCountersCommand(), ListeningPortsCommand(), ProcessPressureCommand(),
	}
	for _, command := range commands {
		argv, err := command.argv()
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.ToLower(strings.Join(argv, " "))
		if strings.Contains(joined, "environ") || strings.Contains(joined, "cmdline") || strings.Contains(joined, "args") {
			t.Errorf("command %s contains forbidden process/environment collection: %v", command.Key(), argv)
		}
	}
	argv, err := ProcessPressureCommand().argv()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); !strings.Contains(got, "pid=,ppid=,comm=,%cpu=,%mem=") || strings.Contains(got, "args") {
		t.Fatalf("process command = %q", got)
	}
}

// TestPostgreSQLCommandsAreFixedReadOnlyStatistics verifies PostgreSQL commands are fixed read only
// statistics.
func TestPostgreSQLCommandsAreFixedReadOnlyStatistics(t *testing.T) {
	constructors := []func(string) (CommandSpec, error){
		PostgreSQLVersionCommand, PostgreSQLDatabasesCommand, PostgreSQLActivityCommand,
		PostgreSQLExtensionsCommand, PostgreSQLStatementsCommand,
	}
	for _, construct := range constructors {
		command, err := construct("postgres")
		if err != nil {
			t.Fatal(err)
		}
		argv, err := command.argv()
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(argv, " ")
		for _, want := range []string{"sudo -n -u postgres", "psql", "--csv", "ON_ERROR_STOP=1", "--dbname postgres", "--command SELECT"} {
			if !strings.Contains(joined, want) {
				t.Errorf("command %s missing %q: %s", command.Key(), want, joined)
			}
		}
		lower := strings.ToLower(joined)
		for _, forbidden := range []string{"select query from", "select *", "information_schema", "pg_dump", "insert ", "update ", "delete ", "password", "token"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("command %s contains forbidden SQL/action %q: %s", command.Key(), forbidden, joined)
			}
		}
	}
	for _, database := range []string{"postgres;id", "postgres $(id)", "postgres/name"} {
		if _, err := PostgreSQLVersionCommand(database); err == nil {
			t.Errorf("unsafe database name %q accepted", database)
		}
	}
}

// TestRemoteArgumentQuotingProtectsFixedSQL verifies remote argument quoting protects fixed sql.
func TestRemoteArgumentQuotingProtectsFixedSQL(t *testing.T) {
	command, _ := PostgreSQLActivityCommand("postgres")
	argv, _ := command.argv()
	remote := joinRemoteArgs(argv)
	if !strings.Contains(remote, `'"'"'idle'"'"'`) {
		t.Fatalf("SQL quote was not shell escaped: %s", remote)
	}
	if strings.Contains(remote, "; id") {
		t.Fatalf("unexpected command injection surface: %s", remote)
	}
}

// TestTargetMustComeFromInventory verifies target must come from inventory.
func TestTargetMustComeFromInventory(t *testing.T) {
	vm := inventory.VM{Name: "a-web", IPPlan: "192.0.2.20"}
	target, err := TargetForVM(vm, "flint")
	if err != nil {
		t.Fatal(err)
	}
	if target.VMName() != "a-web" || target.Host() != "192.0.2.20" {
		t.Fatalf("target = %#v", target)
	}
	if _, err := TargetForVM(inventory.VM{Name: "bad", IPPlan: "example.com"}, "flint"); err == nil {
		t.Fatal("non-inventory IP target accepted")
	}
	runner, err := NewSSHRunner(SSHOptions{ConnectTimeout: time.Second, KnownHosts: "/tmp/known_hosts"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), Target{}, HostnameCommand()); err == nil || !strings.Contains(err.Error(), "resolved from inventory") {
		t.Fatalf("zero target error = %v", err)
	}
}

// TestSSHRunnerUsesNonInteractiveKnownHostOptions verifies ssh runner uses non interactive known
// host options.
func TestSSHRunnerUsesNonInteractiveKnownHostOptions(t *testing.T) {
	vm := inventory.VM{Name: "a-web", IPPlan: "192.0.2.20"}
	target, _ := TargetForVM(vm, "flint")
	runner, err := NewSSHRunner(SSHOptions{ConnectTimeout: 1500 * time.Millisecond, KnownHosts: "/safe/known_hosts", MaxOutputBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	argv, _ := ProcessPressureCommand().argv()
	arguments := strings.Join(runner.arguments(target, argv), "\n")
	for _, want := range []string{"BatchMode=yes", "ConnectTimeout=2", "StrictHostKeyChecking=yes", "UserKnownHostsFile=/safe/known_hosts", "flint@192.0.2.20", "pid=,ppid=,comm=,%cpu=,%mem="} {
		if !strings.Contains(arguments, want) {
			t.Errorf("SSH arguments missing %q:\n%s", want, arguments)
		}
	}
	if strings.Contains(arguments, "args") || strings.Contains(arguments, "environ") {
		t.Fatalf("unsafe SSH arguments:\n%s", arguments)
	}
}

// TestSSHOutputBufferIsBounded verifies ssh output buffer is bounded.
func TestSSHOutputBufferIsBounded(t *testing.T) {
	buffer := newBoundedBuffer(4)
	if _, err := buffer.Write([]byte("123456")); err != nil {
		t.Fatal(err)
	}
	if buffer.String() != "1234" || !buffer.exceeded {
		t.Fatalf("buffer = %q exceeded=%t", buffer.String(), buffer.exceeded)
	}
}

// TestCollectWithFakeRunner verifies collect with fake runner.
func TestCollectWithFakeRunner(t *testing.T) {
	runner := completeFakeRunner()
	vm := inventory.VM{Name: "a-web", Tenant: "tenant-a", Role: "web", IPPlan: "192.0.2.20"}
	target, _ := TargetForVM(vm, "flint")
	status, err := Collect(context.Background(), runner, target, vm, CollectOptions{
		CommandTimeout: time.Second, ServiceRefs: []string{"z", "web"},
		Now: func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Availability.Available || status.Hostname != "a-web" || status.Memory.TotalBytes != 1024*1024 {
		t.Fatalf("status = %#v", status)
	}
	if len(status.ListeningPorts) != 2 || status.ListeningPorts[0].Port != 22 || len(status.ProcessPressure) != 2 {
		t.Fatalf("ports/processes = %#v / %#v", status.ListeningPorts, status.ProcessPressure)
	}
	if !reflect.DeepEqual(status.ServiceRefs, []string{"web", "z"}) {
		t.Fatalf("service refs = %v", status.ServiceRefs)
	}
	if status.Privacy != (observability.PrivacyFlags{}) {
		t.Fatalf("privacy = %#v", status.Privacy)
	}
}

// TestCollectCommandFailureIsPartial verifies collect command failure is partial.
func TestCollectCommandFailureIsPartial(t *testing.T) {
	runner := completeFakeRunner()
	runner.errors[MemoryCommand().Key()] = context.DeadlineExceeded
	vm := inventory.VM{Name: "a-web", IPPlan: "192.0.2.20"}
	target, _ := TargetForVM(vm, "flint")
	status, err := Collect(context.Background(), runner, target, vm, CollectOptions{CommandTimeout: time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Availability.Available || status.Sections.Memory.Available || !strings.Contains(status.Availability.Error, "partial") {
		t.Fatalf("availability = %#v, memory = %#v", status.Availability, status.Sections.Memory)
	}
}

// TestProcessParserIgnoresTrailingArguments verifies process parser ignores trailing arguments.
func TestProcessParserIgnoresTrailingArguments(t *testing.T) {
	processes, err := parseProcessPressure("10 1 nginx 9.0 1.0 --password secret\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 1 || processes[0].Command != "nginx" {
		t.Fatalf("processes = %#v", processes)
	}
	data := strings.ToLower(strings.TrimSpace(processes[0].Command))
	if strings.Contains(data, "password") || strings.Contains(data, "secret") {
		t.Fatalf("argument leaked: %#v", processes[0])
	}
}

// TestListeningPortsParserDeterministic verifies listening ports parser deterministic.
func TestListeningPortsParserDeterministic(t *testing.T) {
	output := "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"python3\",pid=2,fd=3))\n" +
		"tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"
	ports, err := parseListeningPorts(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 || ports[0].Port != 22 || ports[0].Process != "sshd" || ports[1].Port != 8080 {
		t.Fatalf("ports = %#v", ports)
	}
}

// TestGuestStatusJSONDeterministicAndPrivate verifies guest status json deterministic and private.
func TestGuestStatusJSONDeterministicAndPrivate(t *testing.T) {
	runner := completeFakeRunner()
	vm := inventory.VM{Name: "a-web", IPPlan: "192.0.2.20"}
	target, _ := TargetForVM(vm, "flint")
	status, err := Collect(context.Background(), runner, target, vm, CollectOptions{CommandTimeout: time.Second, Now: func() time.Time { return time.Unix(0, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	var first, second bytes.Buffer
	if err := observability.WriteGuestStatus(&first, status); err != nil {
		t.Fatal(err)
	}
	if err := observability.WriteGuestStatus(&second, status); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("guest JSON is not deterministic")
	}
	for _, forbidden := range []string{"process_arguments_collected\": true", "environment_collected\": true", "secrets_collected\": true"} {
		if strings.Contains(first.String(), forbidden) {
			t.Fatalf("unsafe JSON:\n%s", first.String())
		}
	}
}

// completeFakeRunner builds complete fake runner from validated inputs.
func completeFakeRunner() *fakeRunner {
	return &fakeRunner{outputs: map[string]string{
		HostnameCommand().Key(): "a-web\n", KernelReleaseCommand().Key(): "7.0.0\n",
		UptimeCommand().Key(): "123.50 42.00\n", LoadCommand().Key(): "0.10 0.20 0.30 1/100 1\n",
		MemoryCommand().Key():          "MemTotal: 1024 kB\nMemAvailable: 512 kB\nSwapTotal: 128 kB\nSwapFree: 64 kB\n",
		FilesystemsCommand().Key():     "Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/vda1 1000 250 750 25% /\n",
		NetworkAddressCommand().Key():  "eth0 UP 192.0.2.20/24\nlo UNKNOWN 127.0.0.1/8\n",
		NetworkCountersCommand().Key(): "Inter-| Receive | Transmit\n eth0: 100 1 2 0 0 0 0 0 200 2 3 0 0 0 0 0\n lo: 10 1 0 0 0 0 0 0 10 1 0 0 0 0 0 0\n",
		ListeningPortsCommand().Key():  "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"python3\",pid=2,fd=3))\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n",
		ProcessPressureCommand().Key(): "2 1 python3 20.0 3.0\n1 0 systemd 1.0 1.0\n",
	}, errors: map[string]error{}}
}
