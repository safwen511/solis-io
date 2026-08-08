package hoststorage

import (
	"errors"
	"reflect"
	"testing"
)

func TestResolveWithRunner(t *testing.T) {
	var calls [][]string
	run := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		switch name {
		case "findmnt":
			return []byte("/ /dev/mapper/ubuntu--vg-ubuntu--lv ext4\n"), nil
		case "lsblk":
			return []byte("nvme0n1p3\n"), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}

	mapping := resolveWithRunner("/var/lib/libvirt/images/vm.qcow2", run)
	want := Mapping{
		DiskPath:     "/var/lib/libvirt/images/vm.qcow2",
		Mountpoint:   "/",
		SourceDevice: "/dev/mapper/ubuntu--vg-ubuntu--lv",
		Filesystem:   "ext4",
		ParentDevice: "/dev/nvme0n1p3",
	}
	if !reflect.DeepEqual(mapping, want) {
		t.Fatalf("mapping = %#v, want %#v", mapping, want)
	}
	wantCalls := [][]string{
		{"findmnt", "-T", "/var/lib/libvirt/images/vm.qcow2", "-no", "TARGET,SOURCE,FSTYPE"},
		{"lsblk", "-no", "PKNAME", "/dev/mapper/ubuntu--vg-ubuntu--lv"},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestResolveReturnsPartialMappingWhenFindmntFails(t *testing.T) {
	run := func(string, ...string) ([]byte, error) {
		return nil, errors.New("findmnt failed")
	}

	mapping := resolveWithRunner("/images/vm.qcow2", run)
	if mapping.DiskPath != "/images/vm.qcow2" || mapping.Mountpoint != "" || mapping.SourceDevice != "" {
		t.Fatalf("mapping = %#v, want only disk path", mapping)
	}
}

func TestParseFindmntRejectsIncompleteOutput(t *testing.T) {
	if _, _, _, ok := parseFindmnt([]byte("/ /dev/root\n")); ok {
		t.Fatal("parseFindmnt() accepted output without filesystem type")
	}
}

func TestSourceForLSBLKStripsSubvolume(t *testing.T) {
	got := sourceForLSBLK("/dev/nvme0n1p2[/@]")
	if got != "/dev/nvme0n1p2" {
		t.Fatalf("sourceForLSBLK() = %q, want /dev/nvme0n1p2", got)
	}
}
