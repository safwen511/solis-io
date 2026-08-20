package hostmetrics

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/safwen511/solis-io/internal/observability"
)

// TestWriteJSONDeterministicAndPrivacySafe verifies write json deterministic and privacy safe.
func TestWriteJSONDeterministicAndPrivacySafe(t *testing.T) {
	status := HostStatus{
		Hostname:          "fixture-host",
		Filesystems:       FilesystemSection{Mounts: []FilesystemStatus{{Mountpoint: "/var"}, {Mountpoint: "/"}}},
		Disks:             DiskSection{Devices: []DiskStatus{{Name: "zram0"}, {Name: "sda"}}},
		NetworkInterfaces: NetworkSection{Interfaces: []NetworkInterfaceStatus{{Interface: "zeta"}, {Interface: "alpha"}}},
		QEMUProcesses:     QEMUProcessSection{Processes: []QEMUProcessStatus{{PID: 20}, {PID: 10}}},
	}
	var first, second bytes.Buffer
	if err := WriteJSON(&first, status); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&second, status); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("non-deterministic JSON:\n%s\n%s", first.String(), second.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	assertTextOrder(t, first.String(), `"mountpoint": "/"`, `"mountpoint": "/var"`)
	assertTextOrder(t, first.String(), `"name": "sda"`, `"name": "zram0"`)
	assertTextOrder(t, first.String(), `"interface": "alpha"`, `"interface": "zeta"`)
	assertTextOrder(t, first.String(), `"pid": 10`, `"pid": 20`)
	privacy, ok := decoded["privacy"].(map[string]any)
	if !ok || len(privacy) != 8 {
		t.Fatalf("privacy = %#v", decoded["privacy"])
	}
	for name, value := range privacy {
		if value != false {
			t.Fatalf("privacy field %s = %#v", name, value)
		}
	}
}

// TestWriteJSONRejectsUnsafePrivacy verifies write json rejects unsafe privacy.
func TestWriteJSONRejectsUnsafePrivacy(t *testing.T) {
	var output bytes.Buffer
	err := WriteJSON(&output, HostStatus{Privacy: observability.PrivacyFlags{ProcessArgumentsCollected: true}})
	if err == nil || !strings.Contains(err.Error(), "cannot record") {
		t.Fatalf("WriteJSON() error = %v", err)
	}
}

// assertTextOrder performs assert text order as part of the package workflow.
func assertTextOrder(t *testing.T, output, first, second string) {
	t.Helper()
	left, right := strings.Index(output, first), strings.Index(output, second)
	if left < 0 || right < 0 || left >= right {
		t.Fatalf("expected %q before %q:\n%s", first, second, output)
	}
}
