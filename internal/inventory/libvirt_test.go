package inventory

import (
	"reflect"
	"testing"
)

func TestVirshCommandIncludesConfiguredURI(t *testing.T) {
	command := virshCommand("qemu:///system", "domstate", "a-web")
	want := []string{"virsh", "-c", "qemu:///system", "domstate", "a-web"}
	if !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("command args = %v, want %v", command.Args, want)
	}
}

func TestVirshCommandPreservesLegacyDefault(t *testing.T) {
	command := virshCommand("", "domstate", "a-web")
	want := []string{"virsh", "domstate", "a-web"}
	if !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("command args = %v, want %v", command.Args, want)
	}
}
