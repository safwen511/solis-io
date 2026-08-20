package ebpf

import (
	"sort"
	"strings"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
)

// BlockLatencyVMTarget describes one VM and its resolved host storage path.
type BlockLatencyVMTarget struct {
	Name           string
	QEMUPID        string
	Disk           string
	Mountpoint     string
	SourceDevice   string
	Filesystem     string
	ParentDevice   string
	PhysicalDevice string
}

// BlockLatencyVMContext describes the optional VM-aware context around a
// host-wide eBPF block latency observation.
type BlockLatencyVMContext struct {
	Victim                BlockLatencyVMTarget
	Suspect               BlockLatencyVMTarget
	SharesPhysicalStorage bool
	SharedSourceDevice    string
	SharedParentDevice    string
	SharedPhysicalDevice  string
}

type storageMappingResolver func(string) hoststorage.Mapping

// NewBlockLatencyVMContext resolves host storage metadata for two VMs.
func NewBlockLatencyVMContext(victim, suspect inventory.VM) BlockLatencyVMContext {
	return newBlockLatencyVMContext(victim, suspect, hoststorage.Resolve)
}

// newBlockLatencyVMContext constructs block latency VM context wired to the package's production
// dependencies.
func newBlockLatencyVMContext(victim, suspect inventory.VM, resolve storageMappingResolver) BlockLatencyVMContext {
	victimStorage := resolve(victim.Disk)
	suspectStorage := resolve(suspect.Disk)
	sharedPhysical := sharedDeviceValues(victimStorage.PhysicalDisk, suspectStorage.PhysicalDisk)
	return BlockLatencyVMContext{
		Victim:                blockLatencyVMTarget(victim, victimStorage),
		Suspect:               blockLatencyVMTarget(suspect, suspectStorage),
		SharesPhysicalStorage: sharedPhysical != "",
		SharedSourceDevice:    sharedDeviceValues(victimStorage.SourceDevice, suspectStorage.SourceDevice),
		SharedParentDevice:    sharedDeviceValues(victimStorage.ParentDevice, suspectStorage.ParentDevice),
		SharedPhysicalDevice:  sharedPhysical,
	}
}

// blockLatencyVMTarget builds block latency VM target from validated inputs.
func blockLatencyVMTarget(vm inventory.VM, mapping hoststorage.Mapping) BlockLatencyVMTarget {
	disk := mapping.DiskPath
	if strings.TrimSpace(disk) == "" {
		disk = vm.Disk
	}
	return BlockLatencyVMTarget{
		Name:           vm.Name,
		QEMUPID:        vm.QEMUPID,
		Disk:           disk,
		Mountpoint:     mapping.Mountpoint,
		SourceDevice:   mapping.SourceDevice,
		Filesystem:     mapping.Filesystem,
		ParentDevice:   mapping.ParentDevice,
		PhysicalDevice: mapping.PhysicalDisk,
	}
}

// sharedDeviceValues derives stable operator-facing text for shared device values.
func sharedDeviceValues(left, right string) string {
	leftValues := deviceValueSet(left)
	var shared []string
	for value := range deviceValueSet(right) {
		if leftValues[value] {
			shared = append(shared, value)
		}
	}
	sort.Strings(shared)
	return strings.Join(shared, ",")
}

// deviceValueSet builds device value set from validated inputs.
func deviceValueSet(values string) map[string]bool {
	result := make(map[string]bool)
	for _, value := range strings.Split(values, ",") {
		value = strings.TrimSpace(value)
		if value != "" && value != "-" {
			result[value] = true
		}
	}
	return result
}
