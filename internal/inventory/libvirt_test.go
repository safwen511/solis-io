package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestVirshCommandIncludesConfiguredURI verifies virsh command includes configured uri.
func TestVirshCommandIncludesConfiguredURI(t *testing.T) {
	command := virshCommand("qemu:///system", "domstate", "a-web")
	want := []string{"virsh", "-c", "qemu:///system", "domstate", "a-web"}
	if !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("command args = %v, want %v", command.Args, want)
	}
}

// TestVirshCommandPreservesLegacyDefault verifies virsh command preserves legacy default.
func TestVirshCommandPreservesLegacyDefault(t *testing.T) {
	command := virshCommand("", "domstate", "a-web")
	want := []string{"virsh", "domstate", "a-web"}
	if !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("command args = %v, want %v", command.Args, want)
	}
}

// TestEnrichCanSkipQEMUProcessArguments verifies enrich can skip qemu process arguments.
func TestEnrichCanSkipQEMUProcessArguments(t *testing.T) {
	directory := t.TempDir()
	marker := filepath.Join(directory, "ps-called")
	writeTestExecutable(t, filepath.Join(directory, "virsh"), `#!/bin/sh
case "$*" in
  *domstate*) printf 'running\n' ;;
  *domifaddr*) printf 'vnet0 x ipv4 192.0.2.50/24\n' ;;
  *domblklist*) printf 'file disk vda /images/privacy-test.qcow2\n' ;;
esac
`)
	writeTestExecutable(t, filepath.Join(directory, "ps"), fmt.Sprintf("#!/bin/sh\ntouch %q\nexit 0\n", marker))
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))

	vms := EnrichWithOptions([]VM{{Name: "privacy-test-vm"}}, EnrichOptions{SkipQEMUProcessArguments: true})
	if len(vms) != 1 || vms[0].QEMUCmdline != "" {
		t.Fatalf("unexpected enriched VM: %#v", vms)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("process argument fallback was invoked: %v", err)
	}
}

// writeTestExecutable renders test executable in the package's stable operator-facing format.
func writeTestExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}
