package servicehealth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
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
}

// Run executes the receiver's bounded operation and propagates execution failures.
func (runner fakeRunner) Run(_ context.Context, _ guest.Target, command guest.CommandSpec) (guest.Result, error) {
	if err := runner.errors[command.Key()]; err != nil {
		return guest.Result{}, err
	}
	return guest.Result{Output: runner.outputs[command.Key()]}, nil
}

// TestSystemdParserCollectsOnlyAllowlistedFields verifies systemd parser collects only allowlisted
// fields.
func TestSystemdParserCollectsOnlyAllowlistedFields(t *testing.T) {
	status, err := guest.ParseSystemdUnit("Id=nginx.service\nActiveState=active\nSubState=running\nMainPID=42\nNRestarts=3\nExecMainStartTimestamp=Sun 2026-08-09\nEnvironment=SECRET=value\nExecStart=/bin/nginx --token secret\n")
	if err != nil {
		t.Fatal(err)
	}
	if status.ID != "nginx.service" || status.MainPID != 42 || status.Restarts != 3 {
		t.Fatalf("status = %#v", status)
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"Environment", "ExecStart", "SECRET", "token"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("forbidden property leaked in %s", data)
		}
	}
}

// TestHealthCheckRecordsStatusLatencyAndNoBody verifies health check records status latency and no
// body.
func TestHealthCheckRecordsStatusLatencyAndNoBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		_, _ = w.Write([]byte("SECRET RESPONSE BODY"))
	}))
	defer server.Close()
	host, port := serverAddress(t, server.URL)
	vm := inventory.VM{Name: "a-web", Tenant: "tenant-a", Role: "web", IPPlan: host}
	target, _ := guest.TargetForVM(vm, "flint")
	service := solisconfig.ServiceObservabilityConfig{ID: "web", VM: vm.Name, HealthChecks: []solisconfig.HealthCheckConfig{{Name: "health", Path: "/health", Port: port}}}
	report, err := Collect(context.Background(), fakeRunner{outputs: map[string]string{guest.ListeningPortsCommand().Key(): ""}, errors: map[string]error{}}, target, vm, []solisconfig.ServiceObservabilityConfig{service}, Options{CommandTimeout: time.Second, HealthTimeout: time.Second, Now: func() time.Time { return time.Unix(0, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	health := report.Services[0].HealthChecks[0]
	if !health.Checked || health.StatusCode != http.StatusNoContent || health.LatencyMS < 0 || health.BodyCollected {
		t.Fatalf("health = %#v", health)
	}
	var output bytes.Buffer
	if err := WriteJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "SECRET RESPONSE BODY") {
		t.Fatalf("response body leaked:\n%s", output.String())
	}
}

// TestHealthCheckDoesNotFollowRedirect verifies health check does not follow redirect.
func TestHealthCheckDoesNotFollowRedirect(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { redirected.Add(1); w.WriteHeader(http.StatusOK) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, destination.URL, http.StatusFound)
	}))
	defer source.Close()
	host, port := serverAddress(t, source.URL)
	vm := inventory.VM{Name: "a-web", IPPlan: host}
	target, _ := guest.TargetForVM(vm, "flint")
	service := solisconfig.ServiceObservabilityConfig{VM: vm.Name, HealthChecks: []solisconfig.HealthCheckConfig{{Name: "redirect", Path: "/health", Port: port}}}
	report, err := Collect(context.Background(), fakeRunner{outputs: map[string]string{guest.ListeningPortsCommand().Key(): ""}, errors: map[string]error{}}, target, vm, []solisconfig.ServiceObservabilityConfig{service}, Options{CommandTimeout: time.Second, HealthTimeout: time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if report.Services[0].HealthChecks[0].StatusCode != http.StatusFound || redirected.Load() != 0 {
		t.Fatalf("redirect followed: health=%#v destination calls=%d", report.Services[0].HealthChecks[0], redirected.Load())
	}
}

// TestCollectPartialUnitFailure verifies collect partial unit failure.
func TestCollectPartialUnitFailure(t *testing.T) {
	vm := inventory.VM{Name: "a-web", IPPlan: "192.0.2.20"}
	target, _ := guest.TargetForVM(vm, "flint")
	unit, _ := guest.SystemdUnitCommand("nginx.service")
	runner := fakeRunner{outputs: map[string]string{guest.ListeningPortsCommand().Key(): ""}, errors: map[string]error{unit.Key(): errors.New("timeout")}}
	report, err := Collect(context.Background(), runner, target, vm, []solisconfig.ServiceObservabilityConfig{{VM: vm.Name, Units: []string{"nginx.service"}}}, Options{CommandTimeout: time.Second, HealthTimeout: time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Services) != 1 || len(report.Services[0].Units) != 1 || report.Services[0].Units[0].Availability.Available || !report.Availability.Available {
		t.Fatalf("report = %#v", report)
	}
}

// TestServiceWithNoUnitsAndNoConfiguredServices verifies service with no units and no configured
// services.
func TestServiceWithNoUnitsAndNoConfiguredServices(t *testing.T) {
	vm := inventory.VM{Name: "a-web", IPPlan: "192.0.2.20"}
	target, _ := guest.TargetForVM(vm, "flint")
	runner := fakeRunner{outputs: map[string]string{guest.ListeningPortsCommand().Key(): ""}, errors: map[string]error{}}
	report, err := Collect(context.Background(), runner, target, vm, []solisconfig.ServiceObservabilityConfig{{ID: "metadata-only", VM: vm.Name}}, Options{CommandTimeout: time.Second, HealthTimeout: time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Services) != 1 || len(report.Services[0].Units) != 0 {
		t.Fatalf("report = %#v", report)
	}
	empty, err := Collect(context.Background(), runner, target, vm, nil, Options{CommandTimeout: time.Second, HealthTimeout: time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if empty.Availability.Available || !strings.Contains(empty.Availability.Error, "no services configured") {
		t.Fatalf("empty report = %#v", empty)
	}
}

// TestServiceStatusJSONDeterministicAndPrivate verifies service status json deterministic and
// private.
func TestServiceStatusJSONDeterministicAndPrivate(t *testing.T) {
	report := Report{Services: []observability.ServiceStatus{
		{Name: "z", Units: []observability.SystemdUnitStatus{{ID: "z.service"}}},
		{Name: "a", Units: []observability.SystemdUnitStatus{{ID: "b.service"}, {ID: "a.service"}}},
	}}
	var first, second bytes.Buffer
	if err := WriteJSON(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&second, report); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("service JSON is not deterministic")
	}
	if strings.Index(first.String(), `"name": "a"`) > strings.Index(first.String(), `"name": "z"`) {
		t.Fatalf("services not sorted:\n%s", first.String())
	}
	if !strings.Contains(first.String(), `"response_body_collected": false`) {
		t.Fatalf("privacy missing:\n%s", first.String())
	}
}

// serverAddress builds server address from validated inputs.
func serverAddress(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	host, portValue, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portValue)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
