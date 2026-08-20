package hoststorage

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestResolveWithRunner verifies resolve with runner.
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

	mapping := resolveWithRunnerAndSysfs("/var/lib/libvirt/images/vm.qcow2", run, t.TempDir())
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

// TestResolveDeviceMapperTopology verifies resolve device mapper topology.
func TestResolveDeviceMapperTopology(t *testing.T) {
	sysfs := buildTestSysfs(t)
	run := func(name string, _ ...string) ([]byte, error) {
		switch name {
		case "findmnt":
			return []byte("/ /dev/mapper/test--vg-test--lv ext4\n"), nil
		case "lsblk":
			return nil, errors.New("device mapper node unavailable")
		default:
			return nil, errors.New("unexpected command")
		}
	}

	mapping := resolveWithRunnerAndSysfs("/images/vm.qcow2", run, sysfs)
	if mapping.ParentDevice != "/dev/nvme0n1p3,/dev/sdb1" {
		t.Fatalf("ParentDevice = %q, want sorted backing partitions", mapping.ParentDevice)
	}
	if mapping.PhysicalDisk != "/dev/nvme0n1,/dev/sdb" {
		t.Fatalf("PhysicalDisk = %q, want sorted physical disks", mapping.PhysicalDisk)
	}
}

// TestNormalizeBlockDeviceMapper verifies normalize block device mapper.
func TestNormalizeBlockDeviceMapper(t *testing.T) {
	sysfs := buildTestSysfs(t)
	got := normalizeBlockDeviceWithSysfs("/dev/mapper/test--vg-test--lv", sysfs)
	if got != "/dev/dm-1" {
		t.Fatalf("normalizeBlockDeviceWithSysfs() = %q, want /dev/dm-1", got)
	}
}

// TestNormalizeBlockDeviceNormalPath verifies normalize block device normal path.
func TestNormalizeBlockDeviceNormalPath(t *testing.T) {
	sysfs := buildTestSysfs(t)
	got := normalizeBlockDeviceWithSysfs("/dev/nvme0n1p3", sysfs)
	if got != "/dev/nvme0n1p3" {
		t.Fatalf("normalizeBlockDeviceWithSysfs() = %q, want unchanged partition", got)
	}
}

// TestResolveNormalPartitionTopology verifies resolve normal partition topology.
func TestResolveNormalPartitionTopology(t *testing.T) {
	sysfs := buildTestSysfs(t)
	run := func(name string, _ ...string) ([]byte, error) {
		switch name {
		case "findmnt":
			return []byte("/data /dev/nvme0n1p3 xfs\n"), nil
		case "lsblk":
			return []byte("nvme0n1\n"), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}

	mapping := resolveWithRunnerAndSysfs("/data/vm.qcow2", run, sysfs)
	if mapping.ParentDevice != "/dev/nvme0n1" {
		t.Fatalf("ParentDevice = %q, want /dev/nvme0n1", mapping.ParentDevice)
	}
	if mapping.PhysicalDisk != "/dev/nvme0n1" {
		t.Fatalf("PhysicalDisk = %q, want /dev/nvme0n1", mapping.PhysicalDisk)
	}
}

// TestResolveReturnsPartialMappingWhenFindmntFails verifies resolve returns partial mapping when
// findmnt fails.
func TestResolveReturnsPartialMappingWhenFindmntFails(t *testing.T) {
	run := func(string, ...string) ([]byte, error) {
		return nil, errors.New("findmnt failed")
	}

	mapping := resolveWithRunnerAndSysfs("/images/vm.qcow2", run, t.TempDir())
	if mapping.DiskPath != "/images/vm.qcow2" || mapping.Mountpoint != "" || mapping.SourceDevice != "" {
		t.Fatalf("mapping = %#v, want only disk path", mapping)
	}
}

// TestParseDeviceListSortsAndDeduplicates verifies parse device list sorts and deduplicates.
func TestParseDeviceListSortsAndDeduplicates(t *testing.T) {
	got := parseDeviceList([]byte("sdb\nnvme0n1\nsdb\n"))
	if got != "/dev/nvme0n1,/dev/sdb" {
		t.Fatalf("parseDeviceList() = %q, want sorted unique devices", got)
	}
}

// TestParseFindmntRejectsIncompleteOutput verifies parse findmnt rejects incomplete output.
func TestParseFindmntRejectsIncompleteOutput(t *testing.T) {
	if _, _, _, ok := parseFindmnt([]byte("/ /dev/root\n")); ok {
		t.Fatal("parseFindmnt() accepted output without filesystem type")
	}
}

// TestSourceForLSBLKStripsSubvolume verifies source for lsblk strips subvolume.
func TestSourceForLSBLKStripsSubvolume(t *testing.T) {
	got := sourceForLSBLK("/dev/nvme0n1p2[/@]")
	if got != "/dev/nvme0n1p2" {
		t.Fatalf("sourceForLSBLK() = %q, want /dev/nvme0n1p2", got)
	}
}

// buildTestSysfs builds test sysfs from validated inputs.
func buildTestSysfs(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	sysfs := filepath.Join(tempDir, "class", "block")
	devices := filepath.Join(tempDir, "devices")
	if err := os.MkdirAll(sysfs, 0o755); err != nil {
		t.Fatal(err)
	}

	createDMDevice(t, sysfs, "dm-1", "test--vg-test--lv", []string{"dm-0", "sdb1"})
	createDMDevice(t, sysfs, "dm-0", "crypt-test", []string{"nvme0n1p3"})
	createPhysicalWithPartition(t, sysfs, devices, "nvme0n1", "nvme0n1p3")
	createPhysicalWithPartition(t, sysfs, devices, "sdb", "sdb1")

	return sysfs
}

// createDMDevice performs create dm device as part of the package workflow.
func createDMDevice(t *testing.T, sysfs, device, mapperName string, slaves []string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(sysfs, device, "dm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysfs, device, "slaves"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sysfs, device, "dm", "name"), []byte(mapperName), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, slave := range slaves {
		if err := os.Mkdir(filepath.Join(sysfs, device, "slaves", slave), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// createPhysicalWithPartition creates physical with partition while preserving the package's
// security invariants.
func createPhysicalWithPartition(t *testing.T, sysfs, devices, disk, partition string) {
	t.Helper()
	diskPath := filepath.Join(devices, disk)
	partitionPath := filepath.Join(diskPath, partition)
	if err := os.MkdirAll(partitionPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partitionPath, "partition"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(diskPath, filepath.Join(sysfs, disk)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(partitionPath, filepath.Join(sysfs, partition)); err != nil {
		t.Fatal(err)
	}
}
