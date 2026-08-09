package observability

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteGuestStatusDeterministic(t *testing.T) {
	status := GuestStatus{
		VM: VMIdentity{Name: "a-web", Tenant: "tenant-a", Role: "web"},
		Filesystems: []FilesystemStatus{
			{Mountpoint: "/var"},
			{Mountpoint: "/"},
		},
		Network:         []NetworkStatus{{Interface: "eth1"}, {Interface: "eth0"}},
		ProcessPressure: []ProcessPressure{{PID: 20, Command: "nginx"}, {PID: 10, Command: "python3"}},
	}
	output := renderTwice(t, func(buffer *bytes.Buffer) error { return WriteGuestStatus(buffer, status) })
	assertOrdered(t, output, `"mountpoint": "/"`, `"mountpoint": "/var"`)
	assertOrdered(t, output, `"interface": "eth0"`, `"interface": "eth1"`)
	assertOrdered(t, output, `"pid": 10`, `"pid": 20`)
	assertPrivacyFalse(t, output)
}

func TestWriteDBStatusDeterministic(t *testing.T) {
	status := DBStatus{
		Engine:              "postgresql",
		Databases:           []DatabaseCounters{{Name: "template1"}, {Name: "postgres"}},
		Activity:            DatabaseActivity{WaitEvents: []string{"Lock", "IO"}},
		Extensions:          []string{"pg_stat_statements", "plpgsql"},
		StatementStatistics: []StatementStatistics{{QueryID: "20"}, {QueryID: "10"}},
	}
	output := renderTwice(t, func(buffer *bytes.Buffer) error { return WriteDBStatus(buffer, status) })
	assertOrdered(t, output, `"name": "postgres"`, `"name": "template1"`)
	assertOrdered(t, output, `"IO"`, `"Lock"`)
	assertOrdered(t, output, `"query_id": "10"`, `"query_id": "20"`)
	assertPrivacyFalse(t, output)
}

func TestWriteServiceStatusDeterministic(t *testing.T) {
	status := ServiceStatus{
		Name: "web",
		ListeningPorts: []ListeningPort{
			{Protocol: "tcp", Address: "0.0.0.0", Port: 8080},
			{Protocol: "tcp", Address: "0.0.0.0", Port: 80},
		},
		HealthChecks: []AppHealthStatus{{Name: "ready"}, {Name: "health"}},
	}
	output := renderTwice(t, func(buffer *bytes.Buffer) error { return WriteServiceStatus(buffer, status) })
	assertOrdered(t, output, `"port": 80`, `"port": 8080`)
	assertOrdered(t, output, `"name": "health"`, `"name": "ready"`)
	assertPrivacyFalse(t, output)
}

func TestWriteIncidentTimelineDeterministic(t *testing.T) {
	timeline := IncidentTimeline{
		IncidentID: "incident-1",
		Events: []TimelineEvent{
			{OffsetMS: 2000, Source: "qemu", Metric: "write"},
			{OffsetMS: 1000, Source: "host", Metric: "latency"},
		},
		Verdict:      TimelineVerdict{Caveats: []string{"z", "a"}},
		EvidenceRefs: []string{"z.json", "a.json"},
	}
	output := renderTwice(t, func(buffer *bytes.Buffer) error { return WriteIncidentTimeline(buffer, timeline) })
	assertOrdered(t, output, `"offset_ms": 1000`, `"offset_ms": 2000`)
	assertOrdered(t, output, `"a"`, `"z"`)
	assertOrdered(t, output, `"a.json"`, `"z.json"`)
	assertPrivacyFalse(t, output)
}

func TestPrivacyFlagsDefaultToFalse(t *testing.T) {
	data, err := json.Marshal(PrivacyFlags{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]bool
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	wanted := []string{
		"process_arguments_collected", "environment_collected", "guest_files_collected",
		"query_text_collected", "table_data_collected", "request_body_collected",
		"response_body_collected", "secrets_collected",
	}
	for _, name := range wanted {
		value, present := fields[name]
		if !present || value {
			t.Fatalf("privacy field %q = %t, present %t", name, value, present)
		}
	}
}

func TestRendererRejectsUnsafePrivacyFlags(t *testing.T) {
	var output bytes.Buffer
	err := WriteGuestStatus(&output, GuestStatus{Privacy: PrivacyFlags{SecretsCollected: true}})
	if err == nil || !strings.Contains(err.Error(), "cannot record") {
		t.Fatalf("WriteGuestStatus() error = %v", err)
	}
}

func renderTwice(t *testing.T, render func(*bytes.Buffer) error) string {
	t.Helper()
	var first, second bytes.Buffer
	if err := render(&first); err != nil {
		t.Fatal(err)
	}
	if err := render(&second); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("non-deterministic output:\nfirst:\n%s\nsecond:\n%s", first.String(), second.String())
	}
	var decoded any
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, first.String())
	}
	return first.String()
}

func assertOrdered(t *testing.T, output, first, second string) {
	t.Helper()
	firstIndex, secondIndex := strings.Index(output, first), strings.Index(output, second)
	if firstIndex < 0 || secondIndex < 0 || firstIndex >= secondIndex {
		t.Fatalf("expected %q before %q:\n%s", first, second, output)
	}
}

func assertPrivacyFalse(t *testing.T, output string) {
	t.Helper()
	for _, name := range []string{
		"process_arguments_collected", "environment_collected", "guest_files_collected",
		"query_text_collected", "table_data_collected", "request_body_collected",
		"response_body_collected", "secrets_collected",
	} {
		if !strings.Contains(output, `"`+name+`": false`) {
			t.Fatalf("missing false privacy field %q:\n%s", name, output)
		}
	}
}
