// Package qemuio watches per-QEMU process I/O counters from procfs.
package qemuio

import (
	"sort"

	"github.com/safwen511/solis-io/internal/inventory"
)

// Counters contains the cumulative values exposed by /proc/<pid>/io.
type Counters struct {
	RChar               uint64
	WChar               uint64
	Syscr               uint64
	Syscw               uint64
	ReadBytes           uint64
	WriteBytes          uint64
	CancelledWriteBytes uint64
}

// Rates contains selected per-second process I/O rates.
type Rates struct {
	ReadBytesPerSecond  float64
	WriteBytesPerSecond float64
	ReadMiBPerSecond    float64
	WriteMiBPerSecond   float64
	SyscrPerSecond      float64
	SyscwPerSecond      float64
}

// Target combines a VM with its role in the watch.
type Target struct {
	TargetType string
	VM         inventory.VM
}

// Plan contains the resolved VM targets for a QEMU I/O watch.
type Plan struct {
	VictimSelector  string
	SuspectSelector string
	Targets         []Target
}

// NewPlan creates a deterministic target list from resolved inventory VMs.
func NewPlan(victimSelector, suspectSelector string, victims []inventory.VM, suspect inventory.VM) Plan {
	plan := Plan{
		VictimSelector:  victimSelector,
		SuspectSelector: suspectSelector,
	}

	victims = append([]inventory.VM(nil), victims...)
	sort.Slice(victims, func(i, j int) bool { return victims[i].Name < victims[j].Name })
	targetIndexes := make(map[string]int)
	for _, vm := range victims {
		if _, duplicate := targetIndexes[vm.Name]; duplicate {
			continue
		}
		targetIndexes[vm.Name] = len(plan.Targets)
		plan.Targets = append(plan.Targets, Target{TargetType: "victim", VM: vm})
	}
	if index, duplicate := targetIndexes[suspect.Name]; duplicate {
		plan.Targets[index].TargetType = "victim,suspect"
	} else {
		plan.Targets = append(plan.Targets, Target{TargetType: "suspect", VM: suspect})
	}

	return plan
}
