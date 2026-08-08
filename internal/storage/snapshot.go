package storage

import (
	"sort"
	"strings"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
)

type mappingResolver func(string) hoststorage.Mapping
type statsReader func(string) DeviceStats

// Capture resolves VM storage and reads cumulative block counters from sysfs.
func Capture(victimSelector, suspectSelector string, victims []inventory.VM, suspect inventory.VM) Snapshot {
	return captureWith(
		victimSelector,
		suspectSelector,
		victims,
		suspect,
		hoststorage.Resolve,
		readDeviceStats,
	)
}

func captureWith(
	victimSelector string,
	suspectSelector string,
	victims []inventory.VM,
	suspect inventory.VM,
	resolveMapping mappingResolver,
	readStats statsReader,
) Snapshot {
	snapshot := Snapshot{
		VictimSelector:  victimSelector,
		SuspectSelector: suspectSelector,
	}

	victims = append([]inventory.VM(nil), victims...)
	sort.Slice(victims, func(i, j int) bool { return victims[i].Name < victims[j].Name })
	targetIndexes := make(map[string]int)
	for _, vm := range victims {
		targetIndexes[vm.Name] = len(snapshot.Targets)
		snapshot.Targets = append(snapshot.Targets, VMTarget{
			TargetType: "victim",
			VM:         vm,
			Storage:    resolveMapping(vm.Disk),
		})
	}
	if index, duplicate := targetIndexes[suspect.Name]; duplicate {
		snapshot.Targets[index].TargetType = "victim,suspect"
	} else {
		snapshot.Targets = append(snapshot.Targets, VMTarget{
			TargetType: "suspect",
			VM:         suspect,
			Storage:    resolveMapping(suspect.Disk),
		})
	}

	physicalDisks := make(map[string]bool)
	for _, target := range snapshot.Targets {
		for _, disk := range strings.Split(target.Storage.PhysicalDisk, ",") {
			disk = strings.TrimSpace(disk)
			if disk != "" && disk != "-" {
				physicalDisks[disk] = true
			}
		}
	}
	var sortedDisks []string
	for disk := range physicalDisks {
		sortedDisks = append(sortedDisks, disk)
	}
	sort.Strings(sortedDisks)
	for _, disk := range sortedDisks {
		snapshot.Devices = append(snapshot.Devices, readStats(disk))
	}
	if len(snapshot.Devices) == 0 {
		snapshot.Devices = []DeviceStats{{}}
	}

	return snapshot
}
