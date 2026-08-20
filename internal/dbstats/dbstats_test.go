package dbstats

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	solisconfig "github.com/safwen511/solis-io/internal/config"
	"github.com/safwen511/solis-io/internal/guest"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/observability"
)

type fakeRunner struct {
	outputs map[string]string
	errors  map[string]error
	calls   []string
}

// Run executes the receiver's bounded operation and propagates execution failures.
func (runner *fakeRunner) Run(_ context.Context, _ guest.Target, command guest.CommandSpec) (guest.Result, error) {
	key := command.Key()
	runner.calls = append(runner.calls, key)
	if err := runner.errors[key]; err != nil {
		return guest.Result{}, err
	}
	return guest.Result{Output: runner.outputs[key]}, nil
}

// TestParseVersion verifies parse version.
func TestParseVersion(t *testing.T) {
	version, err := parseVersion(`"PostgreSQL 16.4, compiled by gcc"` + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if version != "PostgreSQL 16.4, compiled by gcc" {
		t.Fatalf("version = %q", version)
	}
}

// TestParseDatabaseCountersCSVAndOrdering verifies parse database counters csv and ordering.
func TestParseDatabaseCountersCSVAndOrdering(t *testing.T) {
	output := "template1,1,20,2,5,50,1\n\"customer,west\",3,100,4,10,1000,0\n"
	databases, err := parseDatabaseCounters(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(databases) != 2 || databases[0].Name != "customer,west" || databases[0].Connections != 3 || databases[0].BlocksHit != 1000 {
		t.Fatalf("databases = %#v", databases)
	}
}

// TestParseActivityAggregatesWaitEventsWithoutQueryText verifies parse activity aggregates wait
// events without query text.
func TestParseActivityAggregatesWaitEventsWithoutQueryText(t *testing.T) {
	output := "10,alice,postgres,active,Lock,transactionid,00:00:02.500\n" +
		"11,bob,postgres,active,Lock,transactionid,00:00:03.000\n" +
		"12,carol,postgres,active,IO,DataFileRead,1 day 01:00:00\n" +
		"13,dave,postgres,active,,,00:00:01\n"
	activity, err := parseActivity(output)
	if err != nil {
		t.Fatal(err)
	}
	if activity.ActiveSessions != 4 || activity.WaitingSessions != 3 || activity.OldestActiveSeconds != 90000 {
		t.Fatalf("activity = %#v", activity)
	}
	if len(activity.WaitEvents) != 2 || activity.WaitEvents[1].Type != "Lock" || activity.WaitEvents[1].Count != 2 {
		t.Fatalf("wait events = %#v", activity.WaitEvents)
	}
	if _, err := parseActivity("10,alice,postgres,active,Lock,transactionid,00:00:01,SELECT secret FROM customer\n"); err == nil {
		t.Fatal("activity parser accepted an unexpected query-text column")
	}
}

// TestParseExtensions verifies parse extensions.
func TestParseExtensions(t *testing.T) {
	extensions, err := parseExtensions("plpgsql\npg_stat_statements\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(extensions, ",") != "pg_stat_statements,plpgsql" {
		t.Fatalf("extensions = %v", extensions)
	}
}

// TestParseStatementStatisticsNumericOnly verifies parse statement statistics numeric only.
func TestParseStatementStatisticsNumericOnly(t *testing.T) {
	entries, err := parseStatementStatistics("20,5,100.5,20.1,50\n-10,2,8.0,4.0,4\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].QueryID != "-10" || entries[1].MeanExecutionMS != 20.1 {
		t.Fatalf("entries = %#v", entries)
	}
	if _, err := parseStatementStatistics("20,5,100.5,20.1,50,SELECT secret\n"); err == nil {
		t.Fatal("statement parser accepted query text")
	}
}

// TestMissingPGStatStatementsIsSectionUnavailable verifies missing pg stat statements is section
// unavailable.
func TestMissingPGStatStatementsIsSectionUnavailable(t *testing.T) {
	runner, vm, target, database := completeFixture(t, false)
	status, err := Collect(context.Background(), runner, target, vm, database, fixedOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Availability.Available || status.PGStatStatements.Available || status.Sections.PGStatStatements.Available || !strings.Contains(status.Sections.PGStatStatements.Error, "not installed") {
		t.Fatalf("status = %#v", status)
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(call, string(guest.CommandPostgreSQLStatements)) {
			t.Fatalf("pg_stat_statements queried without extension: %v", runner.calls)
		}
	}
}

// TestPGStatStatementsNumericCollection verifies pg stat statements numeric collection.
func TestPGStatStatementsNumericCollection(t *testing.T) {
	runner, vm, target, database := completeFixture(t, true)
	status, err := Collect(context.Background(), runner, target, vm, database, fixedOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !status.PGStatStatements.Available || len(status.PGStatStatements.Entries) != 2 || status.PGStatStatements.QueryTextCollected {
		t.Fatalf("pg_stat_statements = %#v", status.PGStatStatements)
	}
}

// TestPartialQueryFailureDoesNotAbortStatus verifies partial query failure does not abort status.
func TestPartialQueryFailureDoesNotAbortStatus(t *testing.T) {
	runner, vm, target, database := completeFixture(t, true)
	databases, _ := guest.PostgreSQLDatabasesCommand(database.Database)
	runner.errors[databases.Key()] = context.DeadlineExceeded
	status, err := Collect(context.Background(), runner, target, vm, database, fixedOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Availability.Available || status.Sections.Databases.Available || !strings.Contains(status.Availability.Error, "partial") {
		t.Fatalf("status availability = %#v sections=%#v", status.Availability, status.Sections)
	}
}

// TestPostgreSQLUnavailableReturnsStructuredStatus verifies PostgreSQL unavailable returns
// structured status.
func TestPostgreSQLUnavailableReturnsStructuredStatus(t *testing.T) {
	runner, vm, target, database := completeFixture(t, true)
	for key := range runner.outputs {
		runner.errors[key] = errors.New("postgresql unavailable")
	}
	status, err := Collect(context.Background(), runner, target, vm, database, fixedOptions())
	if err != nil {
		t.Fatal(err)
	}
	if status.Availability.Available || status.Availability.Quality != observability.EvidenceQualityUnavailable {
		t.Fatalf("availability = %#v", status.Availability)
	}
}

// TestDBStatusJSONDeterministicAndPrivate verifies db status json deterministic and private.
func TestDBStatusJSONDeterministicAndPrivate(t *testing.T) {
	runner, vm, target, database := completeFixture(t, true)
	status, err := Collect(context.Background(), runner, target, vm, database, fixedOptions())
	if err != nil {
		t.Fatal(err)
	}
	var first, second bytes.Buffer
	if err := WriteJSON(&first, status); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&second, status); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("DB JSON is not deterministic")
	}
	var decoded map[string]any
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"query_text_collected": false`, `"table_data_collected": false`, `"secrets_collected": false`, `"process_arguments_collected": false`, `"environment_collected": false`} {
		if !strings.Contains(first.String(), want) {
			t.Errorf("DB JSON missing %q:\n%s", want, first.String())
		}
	}
}

// fixedOptions builds fixed options from validated inputs.
func fixedOptions() Options {
	return Options{CommandTimeout: time.Second, Now: func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) }}
}

// completeFixture builds complete fixture from validated inputs.
func completeFixture(t *testing.T, statements bool) (*fakeRunner, inventory.VM, guest.Target, solisconfig.DatabaseObservabilityConfig) {
	t.Helper()
	vm := inventory.VM{Name: "a-db", Tenant: "tenant-a", Role: "db", IPPlan: "192.0.2.30"}
	target, err := guest.TargetForVM(vm, "flint")
	if err != nil {
		t.Fatal(err)
	}
	database := solisconfig.DatabaseObservabilityConfig{VM: vm.Name, Kind: "postgresql", Database: "postgres", CollectPGStatStatements: true}
	version, _ := guest.PostgreSQLVersionCommand(database.Database)
	databases, _ := guest.PostgreSQLDatabasesCommand(database.Database)
	activity, _ := guest.PostgreSQLActivityCommand(database.Database)
	extensions, _ := guest.PostgreSQLExtensionsCommand(database.Database)
	statementCommand, _ := guest.PostgreSQLStatementsCommand(database.Database)
	extensionOutput := "plpgsql\n"
	if statements {
		extensionOutput = "plpgsql\npg_stat_statements\n"
	}
	runner := &fakeRunner{outputs: map[string]string{
		version.Key():          `"PostgreSQL 16.4, compiled by gcc"` + "\n",
		databases.Key():        "template1,1,20,2,5,50,1\npostgres,3,100,4,10,1000,0\n",
		activity.Key():         "10,postgres,postgres,active,Lock,transactionid,00:00:02.500\n",
		extensions.Key():       extensionOutput,
		statementCommand.Key(): "20,5,100.5,20.1,50\n-10,2,8.0,4.0,4\n",
	}, errors: map[string]error{}}
	return runner, vm, target, database
}
