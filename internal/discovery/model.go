// Package discovery resolves and ranks same-storage noisy-neighbor candidates.
package discovery

import (
	"fmt"
	"sort"
	"strings"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
	"github.com/safwen511/solis-io/internal/qemuio"
)

// CandidateTarget is a running VM on the victim's physical storage.
type CandidateTarget struct {
	VM         inventory.VM
	Storage    hoststorage.Mapping
	SharedDisk bool
}

// Targets contains the victim and eligible same-storage VMs to sample.
type Targets struct {
	Victim           inventory.VM
	VictimStorage    hoststorage.Mapping
	CandidateTargets []CandidateTarget
}

// Candidate contains one candidate's sampled writer evidence and rank.
type Candidate struct {
	VM         inventory.VM
	Storage    hoststorage.Mapping
	SharedDisk bool
	Summary    qemuio.VMSummary
	Score      string
	Reason     string
}

// Report contains deterministic suspect-discovery results.
type Report struct {
	Victim          inventory.VM
	VictimStorage   hoststorage.Mapping
	VictimSummary   qemuio.VMSummary
	Candidates      []Candidate
	Selected        *Candidate
	SelectionReason string
}

type mappingResolver func(string) hoststorage.Mapping

// Resolve finds a running victim and same-physical-storage running candidates.
func Resolve(vms []inventory.VM, victimName string) (Targets, error) {
	return resolveWith(vms, victimName, hoststorage.Resolve)
}

func resolveWith(vms []inventory.VM, victimName string, resolve mappingResolver) (Targets, error) {
	victim, ok := inventory.FindByName(vms, victimName)
	if !ok {
		return Targets{}, fmt.Errorf("victim VM not found: %s", victimName)
	}
	if !isRunning(*victim) {
		return Targets{}, fmt.Errorf("victim VM is not running: %s", victimName)
	}
	if !hasQEMUPID(*victim) {
		return Targets{}, fmt.Errorf("victim VM has no QEMU PID: %s", victimName)
	}

	targets := Targets{Victim: *victim, VictimStorage: resolve(victim.Disk)}
	for _, vm := range vms {
		if vm.Name == victim.Name || !isRunning(vm) || !hasQEMUPID(vm) {
			continue
		}
		mapping := resolve(vm.Disk)
		if !sharesPhysicalDisk(targets.VictimStorage.PhysicalDisk, mapping.PhysicalDisk) {
			continue
		}
		targets.CandidateTargets = append(targets.CandidateTargets, CandidateTarget{
			VM:         vm,
			Storage:    mapping,
			SharedDisk: true,
		})
	}
	sort.Slice(targets.CandidateTargets, func(i, j int) bool {
		return targets.CandidateTargets[i].VM.Name < targets.CandidateTargets[j].VM.Name
	})
	return targets, nil
}

// SamplingPlan creates a deterministic one-window plan for the victim and all
// eligible candidates.
func SamplingPlan(targets Targets) qemuio.Plan {
	plan := qemuio.Plan{
		VictimSelector: targets.Victim.Name,
		Targets: []qemuio.Target{{
			TargetType: "victim",
			VM:         targets.Victim,
		}},
	}
	for _, candidate := range targets.CandidateTargets {
		plan.Targets = append(plan.Targets, qemuio.Target{
			TargetType: "candidate",
			VM:         candidate.VM,
		})
	}
	return plan
}

// Analyze ranks already sampled candidates using byte counters first and
// write-syscall pressure only when no candidate has meaningful byte activity.
func Analyze(targets Targets, sampled qemuio.SummaryReport) Report {
	summaries := make(map[string]qemuio.VMSummary, len(sampled.VMs))
	for _, summary := range sampled.VMs {
		summaries[summary.Target.VM.Name] = summary
	}
	report := Report{
		Victim:          targets.Victim,
		VictimStorage:   targets.VictimStorage,
		VictimSummary:   summaries[targets.Victim.Name],
		SelectionReason: "no dominant writer observed",
	}
	for _, target := range targets.CandidateTargets {
		report.Candidates = append(report.Candidates, Candidate{
			VM:         target.VM,
			Storage:    target.Storage,
			SharedDisk: target.SharedDisk,
			Summary:    summaries[target.VM.Name],
			Score:      "LOW",
			Reason:     candidateIdleReason(summaries[target.VM.Name]),
		})
	}

	selectedName, selectedReason := selectCandidate(report.VictimSummary, report.Candidates)
	for index := range report.Candidates {
		candidate := &report.Candidates[index]
		switch {
		case candidate.VM.Name == selectedName:
			candidate.Score = "HIGH"
			candidate.Reason = selectedReason
		case candidate.Summary.Available && qemuio.MeaningfulWriteBytes(candidate.Summary.AverageWriteMiBPerSecond):
			candidate.Score = "MEDIUM"
			candidate.Reason = "write activity, not dominant"
		case candidate.Summary.Available && qemuio.MeaningfulWriteSyscalls(candidate.Summary.AverageSyscwPerSecond):
			candidate.Score = "MEDIUM"
			candidate.Reason = "syscall pressure, not dominant"
		}
	}
	sort.SliceStable(report.Candidates, func(i, j int) bool {
		left, right := report.Candidates[i], report.Candidates[j]
		if scoreRank(left.Score) != scoreRank(right.Score) {
			return scoreRank(left.Score) > scoreRank(right.Score)
		}
		if left.Summary.AverageWriteMiBPerSecond != right.Summary.AverageWriteMiBPerSecond {
			return left.Summary.AverageWriteMiBPerSecond > right.Summary.AverageWriteMiBPerSecond
		}
		if left.Summary.AverageSyscwPerSecond != right.Summary.AverageSyscwPerSecond {
			return left.Summary.AverageSyscwPerSecond > right.Summary.AverageSyscwPerSecond
		}
		return left.VM.Name < right.VM.Name
	})
	for index := range report.Candidates {
		if report.Candidates[index].VM.Name == selectedName {
			report.Selected = &report.Candidates[index]
			report.SelectionReason = selectedReason
			break
		}
	}
	return report
}

func selectCandidate(victim qemuio.VMSummary, candidates []Candidate) (string, string) {
	byteCandidates := rankedCandidates(candidates, func(summary qemuio.VMSummary) (float64, float64, bool) {
		return summary.AverageWriteMiBPerSecond, summary.MaxWriteMiBPerSecond,
			summary.Available && qemuio.MeaningfulWriteBytes(summary.AverageWriteMiBPerSecond)
	})
	if len(byteCandidates) > 0 {
		comparison := competingRate(victim, candidates, byteCandidates[0].VM.Name, func(summary qemuio.VMSummary) float64 {
			return summary.AverageWriteMiBPerSecond
		})
		if qemuio.DominantWriteBytes(comparison, byteCandidates[0].Summary.AverageWriteMiBPerSecond) {
			return byteCandidates[0].VM.Name, "dominant byte write rate"
		}
		return "", ""
	}

	syscallCandidates := rankedCandidates(candidates, func(summary qemuio.VMSummary) (float64, float64, bool) {
		return summary.AverageSyscwPerSecond, summary.MaxSyscwPerSecond,
			summary.Available && qemuio.MeaningfulWriteSyscalls(summary.AverageSyscwPerSecond)
	})
	if len(syscallCandidates) > 0 {
		comparison := competingRate(victim, candidates, syscallCandidates[0].VM.Name, func(summary qemuio.VMSummary) float64 {
			return summary.AverageSyscwPerSecond
		})
		if qemuio.DominantWriteSyscalls(comparison, syscallCandidates[0].Summary.AverageSyscwPerSecond) {
			return syscallCandidates[0].VM.Name, "dominant syscall pressure"
		}
	}
	return "", ""
}

type candidateMetric func(qemuio.VMSummary) (average, maximum float64, eligible bool)

func rankedCandidates(candidates []Candidate, metric candidateMetric) []Candidate {
	var ranked []Candidate
	for _, candidate := range candidates {
		_, _, eligible := metric(candidate.Summary)
		if eligible {
			ranked = append(ranked, candidate)
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		leftAverage, leftMaximum, _ := metric(ranked[i].Summary)
		rightAverage, rightMaximum, _ := metric(ranked[j].Summary)
		if leftAverage != rightAverage {
			return leftAverage > rightAverage
		}
		if leftMaximum != rightMaximum {
			return leftMaximum > rightMaximum
		}
		return ranked[i].VM.Name < ranked[j].VM.Name
	})
	return ranked
}

func competingRate(victim qemuio.VMSummary, candidates []Candidate, selectedName string, rate func(qemuio.VMSummary) float64) float64 {
	comparison := float64(0)
	if victim.Available {
		comparison = rate(victim)
	}
	for _, candidate := range candidates {
		if candidate.VM.Name == selectedName || !candidate.Summary.Available {
			continue
		}
		if value := rate(candidate.Summary); value > comparison {
			comparison = value
		}
	}
	return comparison
}

func candidateIdleReason(summary qemuio.VMSummary) string {
	if !summary.Available {
		if reason := strings.TrimSpace(summary.Error); reason != "" {
			return strings.Join(strings.Fields(reason), " ")
		}
		return "I/O counters unavailable"
	}
	return "idle"
}

func scoreRank(score string) int {
	switch score {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	default:
		return 1
	}
}

func isRunning(vm inventory.VM) bool {
	return strings.EqualFold(strings.TrimSpace(vm.State), "running")
}

func hasQEMUPID(vm inventory.VM) bool {
	pid := strings.TrimSpace(vm.QEMUPID)
	return pid != "" && pid != "-"
}

func sharesPhysicalDisk(left, right string) bool {
	leftDevices := deviceSet(left)
	for device := range deviceSet(right) {
		if leftDevices[device] {
			return true
		}
	}
	return false
}

func deviceSet(value string) map[string]bool {
	devices := make(map[string]bool)
	for _, device := range strings.Split(value, ",") {
		device = strings.TrimSpace(device)
		if device != "" && device != "-" {
			devices[device] = true
		}
	}
	return devices
}
