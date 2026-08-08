// Package traceplan resolves inventory targets and formats future tracing plans.
package traceplan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
)

// Plan contains the inventory targets for a proposed trace.
type Plan struct {
	VictimSelector  string
	SuspectSelector string
	VictimIsTenant  bool
	VictimTargets   []inventory.VM
	SuspectTarget   inventory.VM
	HostStorage     map[string]hoststorage.Mapping
}

// Resolve maps victim and suspect selectors to inventory VMs.
func Resolve(vms []inventory.VM, victim, suspect string) (Plan, error) {
	victim = strings.TrimSpace(victim)
	suspect = strings.TrimSpace(suspect)
	if victim == "" {
		return Plan{}, fmt.Errorf("victim must not be empty")
	}
	if suspect == "" {
		return Plan{}, fmt.Errorf("suspect must not be empty")
	}

	suspectVM, ok := inventory.FindByName(vms, suspect)
	if !ok {
		return Plan{}, fmt.Errorf("suspect VM not found: %s", suspect)
	}

	plan := Plan{
		VictimSelector:  victim,
		SuspectSelector: suspect,
		SuspectTarget:   *suspectVM,
	}
	if victimVM, ok := inventory.FindByName(vms, victim); ok {
		plan.VictimTargets = []inventory.VM{*victimVM}
		return plan, nil
	}

	plan.VictimIsTenant = true
	for _, vm := range vms {
		if vm.Tenant == victim {
			plan.VictimTargets = append(plan.VictimTargets, vm)
		}
	}
	if len(plan.VictimTargets) == 0 {
		return Plan{}, fmt.Errorf("victim tenant or VM not found: %s", victim)
	}
	sort.Slice(plan.VictimTargets, func(i, j int) bool {
		return plan.VictimTargets[i].Name < plan.VictimTargets[j].Name
	})

	return plan, nil
}
