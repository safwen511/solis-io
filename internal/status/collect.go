package status

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
)

// Collect samples all enriched running VMs that have a valid QEMU PID.
func Collect(vms []inventory.VM, duration, interval time.Duration) (Report, error) {
	if duration <= 0 {
		return Report{}, fmt.Errorf("duration must be greater than zero")
	}
	if interval <= 0 {
		return Report{}, fmt.Errorf("interval must be greater than zero")
	}
	if interval > duration {
		return Report{}, fmt.Errorf("interval %s cannot exceed duration %s", interval, duration)
	}
	targets := eligibleVMs(vms)
	if len(targets) == 0 {
		return NewReport(duration, interval, nil), nil
	}

	plan := qemuio.Plan{Targets: make([]qemuio.Target, 0, len(targets))}
	for _, vm := range targets {
		plan.Targets = append(plan.Targets, qemuio.Target{TargetType: "status", VM: vm})
	}
	summary, err := qemuio.CollectSummary(plan, duration, interval)
	if err != nil {
		return Report{}, err
	}

	byName := make(map[string]qemuio.VMSummary, len(summary.VMs))
	for _, vmSummary := range summary.VMs {
		byName[vmSummary.Target.VM.Name] = vmSummary
	}
	samples := make([]Sample, 0, len(targets))
	for _, vm := range targets {
		samples = append(samples, Sample{
			VM:      vm,
			Storage: hoststorage.Resolve(vm.Disk),
			QEMU:    byName[vm.Name],
		})
	}
	return NewReport(duration, interval, samples), nil
}

func eligibleVMs(vms []inventory.VM) []inventory.VM {
	var eligible []inventory.VM
	for _, vm := range vms {
		if strings.ToLower(strings.TrimSpace(vm.State)) != "running" || !validPID(vm.QEMUPID) {
			continue
		}
		eligible = append(eligible, vm)
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].Name < eligible[j].Name })
	return eligible
}

func validPID(value string) bool {
	pid, err := strconv.Atoi(strings.TrimSpace(value))
	return err == nil && pid > 0
}
