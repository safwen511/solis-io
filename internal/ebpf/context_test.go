package ebpf

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
)

func TestNewBlockLatencyVMContextSharedStorage(t *testing.T) {
	resolver := func(path string) hoststorage.Mapping {
		switch path {
		case "/images/a-web.qcow2":
			return hoststorage.Mapping{
				DiskPath:     path,
				Mountpoint:   "/",
				SourceDevice: "/dev/mapper/vg-lv",
				Filesystem:   "ext4",
				ParentDevice: "/dev/nvme0n1p3",
				PhysicalDisk: "/dev/nvme1n1,/dev/nvme0n1",
			}
		case "/images/b-stress.qcow2":
			return hoststorage.Mapping{
				DiskPath:     path,
				Mountpoint:   "/",
				SourceDevice: "/dev/mapper/vg-lv",
				Filesystem:   "ext4",
				ParentDevice: "/dev/nvme0n1p3",
				PhysicalDisk: "/dev/nvme0n1,/dev/sda",
			}
		default:
			t.Fatalf("unexpected disk path %q", path)
			return hoststorage.Mapping{}
		}
	}

	context := newBlockLatencyVMContext(
		inventory.VM{Name: "a-web", QEMUPID: "101", Disk: "/images/a-web.qcow2"},
		inventory.VM{Name: "b-stress", QEMUPID: "202", Disk: "/images/b-stress.qcow2"},
		resolver,
	)
	if !context.SharesPhysicalStorage {
		t.Fatal("SharesPhysicalStorage = false, want true")
	}
	if context.SharedSourceDevice != "/dev/mapper/vg-lv" || context.SharedParentDevice != "/dev/nvme0n1p3" || context.SharedPhysicalDevice != "/dev/nvme0n1" {
		t.Fatalf("shared storage = %#v", context)
	}
	if context.Victim.QEMUPID != "101" || context.Suspect.QEMUPID != "202" {
		t.Fatalf("target PIDs = %q, %q", context.Victim.QEMUPID, context.Suspect.QEMUPID)
	}
}

func TestNewBlockLatencyVMContextDoesNotShareStorage(t *testing.T) {
	resolver := func(path string) hoststorage.Mapping {
		physical := "/dev/nvme0n1"
		if strings.Contains(path, "suspect") {
			physical = "/dev/sda"
		}
		return hoststorage.Mapping{DiskPath: path, PhysicalDisk: physical}
	}
	context := newBlockLatencyVMContext(
		inventory.VM{Name: "victim", Disk: "/images/victim.qcow2"},
		inventory.VM{Name: "suspect", Disk: "/images/suspect.qcow2"},
		resolver,
	)
	if context.SharesPhysicalStorage || context.SharedPhysicalDevice != "" {
		t.Fatalf("context = %#v, want no shared physical storage", context)
	}
}

func TestWriteVMBlockLatencySharedStorage(t *testing.T) {
	context := BlockLatencyVMContext{
		Victim: BlockLatencyVMTarget{
			Name: "a-web", QEMUPID: "101", Disk: "/images/a-web.qcow2", Mountpoint: "/",
			SourceDevice: "/dev/mapper/vg-lv", Filesystem: "ext4", ParentDevice: "/dev/nvme0n1p3", PhysicalDevice: "/dev/nvme0n1",
		},
		Suspect: BlockLatencyVMTarget{
			Name: "b-stress", QEMUPID: "202", Disk: "/images/b-stress.qcow2", Mountpoint: "/",
			SourceDevice: "/dev/mapper/vg-lv", Filesystem: "ext4", ParentDevice: "/dev/nvme0n1p3", PhysicalDevice: "/dev/nvme0n1",
		},
		SharesPhysicalStorage: true,
		SharedSourceDevice:    "/dev/mapper/vg-lv",
		SharedParentDevice:    "/dev/nvme0n1p3",
		SharedPhysicalDevice:  "/dev/nvme0n1",
	}
	var output bytes.Buffer
	if err := WriteVMBlockLatency(&output, BlockLatencyResult{Duration: time.Second}, context); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"VM-aware context:",
		"Victim:  a-web",
		"Suspect: b-stress",
		"101",
		"/images/a-web.qcow2",
		"Shared storage path:",
		"/dev/mapper/vg-lv",
		"/dev/nvme0n1p3",
		"/dev/nvme0n1",
		"not precise per-VM block latency attribution",
		"solis qemu io-summary",
		"Latency histogram:",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestWriteVMBlockLatencyWarnsAndContinuesWhenStorageDiffers(t *testing.T) {
	context := BlockLatencyVMContext{
		Victim:  BlockLatencyVMTarget{Name: "a-web", PhysicalDevice: "/dev/nvme0n1"},
		Suspect: BlockLatencyVMTarget{Name: "b-stress", PhysicalDevice: "/dev/sda"},
	}
	var output bytes.Buffer
	if err := WriteVMBlockLatency(&output, BlockLatencyResult{Duration: time.Second}, context); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"WARNING: victim and suspect do not share a resolved physical storage device",
		"continuing with host-wide latency collection",
		"Latency histogram:",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}
