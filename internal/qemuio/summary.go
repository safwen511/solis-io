package qemuio

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	nearZeroWriteMiBPerSecond          = 0.01
	minimumMeaningfulWriteMiBPerSecond = 10.0
	dominantWriteRatio                 = 2.0
	nearZeroWriteSyscallsPerSecond     = 1.0
	minimumMeaningfulSyscwPerSecond    = 10000.0
	dominantSyscwRatio                 = 2.0
	dominantConclusion                 = "Suspect QEMU process is the dominant writer during the observation window."
	noDominantConclusion               = "No dominant QEMU writer identified from process I/O counters."
	noWritePressureConclusion          = "No meaningful QEMU write pressure observed during the observation window."
	syscallPressureConclusion          = "QEMU write syscall pressure observed, but byte counters did not advance meaningfully."
	unavailableConclusion              = "QEMU process I/O counters were unavailable for diagnosis."
)

// VMSummary contains time-weighted process I/O aggregates for one target VM.
type VMSummary struct {
	Target                   Target
	AverageReadMiBPerSecond  float64
	AverageWriteMiBPerSecond float64
	MaxWriteMiBPerSecond     float64
	TotalReadMiB             float64
	TotalWrittenMiB          float64
	AverageSyscrPerSecond    float64
	AverageSyscwPerSecond    float64
	MaxSyscwPerSecond        float64
	Available                bool
	Error                    string
}

// SummaryReport contains the compact result of an observation window.
type SummaryReport struct {
	Plan                            Plan
	Duration                        time.Duration
	Interval                        time.Duration
	VMs                             []VMSummary
	VictimAverageWriteMiBPerSecond  float64
	SuspectAverageWriteMiBPerSecond float64
	VictimAverageSyscwPerSecond     float64
	SuspectAverageSyscwPerSecond    float64
	VictimDataAvailable             bool
	SuspectDataAvailable            bool
	MeaningfulSuspectWritePressure  bool
	SuspectDominant                 bool
	MeaningfulSuspectSyscwPressure  bool
	SuspectSyscwDominant            bool
	WriteRatio                      string
	SyscwRatio                      string
	DominantWriter                  string
	DominantWriteSyscallSource      string
	WriteSyscallPressure            string
	Conclusion                      string
}

type summaryAccumulator struct {
	seconds          float64
	readMiB          float64
	writeMiB         float64
	syscr            float64
	syscw            float64
	maxWriteMiB      float64
	maxSyscw         float64
	successfulSample bool
	err              string
}

// CollectSummary samples the plan and computes per-VM and group aggregates.
func CollectSummary(plan Plan, duration, interval time.Duration) (SummaryReport, error) {
	if err := validateWindow(duration, interval); err != nil {
		return SummaryReport{}, err
	}

	var samples []intervalSample
	err := sampleIntervals(plan, duration, interval, func(sample intervalSample) error {
		samples = append(samples, sample)
		return nil
	})
	if err != nil {
		return SummaryReport{}, err
	}
	return summarizeSamples(plan, duration, interval, samples), nil
}

func summarizeSamples(plan Plan, duration, interval time.Duration, samples []intervalSample) SummaryReport {
	accumulators := make(map[string]*summaryAccumulator, len(plan.Targets))
	for _, target := range plan.Targets {
		accumulators[target.VM.Name] = &summaryAccumulator{}
	}
	for _, sample := range samples {
		accumulator, ok := accumulators[sample.Target.VM.Name]
		if !ok {
			continue
		}
		if sample.Err != nil {
			if accumulator.err == "" {
				accumulator.err = strings.Join(strings.Fields(sample.Err.Error()), " ")
			}
			continue
		}
		seconds := sample.Interval.Seconds()
		if seconds <= 0 {
			continue
		}
		accumulator.seconds += seconds
		accumulator.readMiB += sample.Rates.ReadMiBPerSecond * seconds
		accumulator.writeMiB += sample.Rates.WriteMiBPerSecond * seconds
		accumulator.syscr += sample.Rates.SyscrPerSecond * seconds
		accumulator.syscw += sample.Rates.SyscwPerSecond * seconds
		if !accumulator.successfulSample || sample.Rates.WriteMiBPerSecond > accumulator.maxWriteMiB {
			accumulator.maxWriteMiB = sample.Rates.WriteMiBPerSecond
		}
		if !accumulator.successfulSample || sample.Rates.SyscwPerSecond > accumulator.maxSyscw {
			accumulator.maxSyscw = sample.Rates.SyscwPerSecond
		}
		accumulator.successfulSample = true
	}

	report := SummaryReport{Plan: plan, Duration: duration, Interval: interval}
	for _, target := range plan.Targets {
		accumulator := accumulators[target.VM.Name]
		vmSummary := VMSummary{Target: target, Error: accumulator.err}
		if accumulator.successfulSample && accumulator.seconds > 0 {
			vmSummary.Available = true
			vmSummary.AverageReadMiBPerSecond = accumulator.readMiB / accumulator.seconds
			vmSummary.AverageWriteMiBPerSecond = accumulator.writeMiB / accumulator.seconds
			vmSummary.MaxWriteMiBPerSecond = accumulator.maxWriteMiB
			vmSummary.TotalReadMiB = accumulator.readMiB
			vmSummary.TotalWrittenMiB = accumulator.writeMiB
			vmSummary.AverageSyscrPerSecond = accumulator.syscr / accumulator.seconds
			vmSummary.AverageSyscwPerSecond = accumulator.syscw / accumulator.seconds
			vmSummary.MaxSyscwPerSecond = accumulator.maxSyscw
		}
		report.VMs = append(report.VMs, vmSummary)
	}
	return finalizeSummary(report)
}

// SummaryForPlan reuses already sampled per-VM summaries with a new victim and
// suspect plan. It does not read procfs or start another sampling window.
func SummaryForPlan(source SummaryReport, plan Plan) SummaryReport {
	byName := make(map[string]VMSummary, len(source.VMs))
	for _, summary := range source.VMs {
		byName[summary.Target.VM.Name] = summary
	}
	report := SummaryReport{Plan: plan, Duration: source.Duration, Interval: source.Interval}
	for _, target := range plan.Targets {
		summary, ok := byName[target.VM.Name]
		if !ok {
			summary = VMSummary{Error: "QEMU process I/O summary unavailable"}
		}
		summary.Target = target
		report.VMs = append(report.VMs, summary)
	}
	return finalizeSummary(report)
}

func finalizeSummary(report SummaryReport) SummaryReport {
	for _, vmSummary := range report.VMs {
		target := vmSummary.Target
		if vmSummary.Available && targetHasType(target, "victim") {
			report.VictimDataAvailable = true
			report.VictimAverageWriteMiBPerSecond += vmSummary.AverageWriteMiBPerSecond
			report.VictimAverageSyscwPerSecond += vmSummary.AverageSyscwPerSecond
		}
		if vmSummary.Available && targetHasType(target, "suspect") {
			report.SuspectDataAvailable = true
			report.SuspectAverageWriteMiBPerSecond = vmSummary.AverageWriteMiBPerSecond
			report.SuspectAverageSyscwPerSecond = vmSummary.AverageSyscwPerSecond
		}
	}

	if !report.VictimDataAvailable || !report.SuspectDataAvailable {
		report.WriteRatio = "-"
		report.SyscwRatio = "-"
		report.DominantWriter = "-"
		report.DominantWriteSyscallSource = "-"
		report.WriteSyscallPressure = "-"
		report.Conclusion = unavailableConclusion
		return report
	}

	report.WriteRatio = formatWriteRatio(
		report.SuspectAverageWriteMiBPerSecond,
		report.VictimAverageWriteMiBPerSecond,
	)
	report.MeaningfulSuspectWritePressure =
		report.SuspectAverageWriteMiBPerSecond >= minimumMeaningfulWriteMiBPerSecond
	report.SuspectDominant = suspectIsDominant(
		report.VictimAverageWriteMiBPerSecond,
		report.SuspectAverageWriteMiBPerSecond,
	)
	report.SyscwRatio = formatSyscwRatio(
		report.SuspectAverageSyscwPerSecond,
		report.VictimAverageSyscwPerSecond,
	)
	report.MeaningfulSuspectSyscwPressure =
		report.SuspectAverageSyscwPerSecond >= minimumMeaningfulSyscwPerSecond
	report.SuspectSyscwDominant = suspectSyscwIsDominant(
		report.VictimAverageSyscwPerSecond,
		report.SuspectAverageSyscwPerSecond,
	)
	report.WriteSyscallPressure = syscallPressureClassification(report.MeaningfulSuspectSyscwPressure)
	report.Conclusion = conclusionForSignals(
		report.VictimAverageWriteMiBPerSecond,
		report.SuspectAverageWriteMiBPerSecond,
		report.SuspectAverageSyscwPerSecond,
	)
	if report.SuspectDominant {
		report.DominantWriter = report.Plan.SuspectSelector
	} else {
		report.DominantWriter = "-"
	}
	if report.SuspectSyscwDominant {
		report.DominantWriteSyscallSource = report.Plan.SuspectSelector
	} else {
		report.DominantWriteSyscallSource = "-"
	}
	return report
}

func targetHasType(target Target, targetType string) bool {
	for _, candidate := range strings.Split(target.TargetType, ",") {
		if candidate == targetType {
			return true
		}
	}
	return false
}

func formatWriteRatio(suspect, victim float64) string {
	if suspect < minimumMeaningfulWriteMiBPerSecond {
		return "-"
	}
	if victim <= nearZeroWriteMiBPerSecond {
		return "dominant suspect"
	}
	return fmt.Sprintf("%.2fx", suspect/victim)
}

func suspectIsDominant(victim, suspect float64) bool {
	if suspect < minimumMeaningfulWriteMiBPerSecond {
		return false
	}
	if victim <= nearZeroWriteMiBPerSecond {
		return true
	}
	return suspect/victim >= dominantWriteRatio
}

// MeaningfulWriteBytes reports whether a write-byte rate is large enough for
// byte-counter attribution.
func MeaningfulWriteBytes(averageMiBPerSecond float64) bool {
	return averageMiBPerSecond >= minimumMeaningfulWriteMiBPerSecond
}

// DominantWriteBytes reports whether a meaningful candidate write-byte rate is
// at least the configured dominance ratio above the comparison rate.
func DominantWriteBytes(comparison, candidate float64) bool {
	return suspectIsDominant(comparison, candidate)
}

func formatSyscwRatio(suspect, victim float64) string {
	if suspect < minimumMeaningfulSyscwPerSecond {
		return "-"
	}
	if victim <= nearZeroWriteSyscallsPerSecond {
		return "dominant suspect"
	}
	return fmt.Sprintf("%.2fx", suspect/victim)
}

func suspectSyscwIsDominant(victim, suspect float64) bool {
	if suspect < minimumMeaningfulSyscwPerSecond {
		return false
	}
	if victim <= nearZeroWriteSyscallsPerSecond {
		return true
	}
	return suspect/victim >= dominantSyscwRatio
}

// MeaningfulWriteSyscalls reports whether syscw activity crosses the
// conservative fallback threshold.
func MeaningfulWriteSyscalls(averagePerSecond float64) bool {
	return averagePerSecond >= minimumMeaningfulSyscwPerSecond
}

// DominantWriteSyscalls reports whether meaningful candidate syscw activity is
// at least the configured dominance ratio above the comparison rate.
func DominantWriteSyscalls(comparison, candidate float64) bool {
	return suspectSyscwIsDominant(comparison, candidate)
}

func syscallPressureClassification(meaningful bool) string {
	if meaningful {
		return "HIGH"
	}
	return "NONE"
}

func conclusionForSignals(victimWrite, suspectWrite, suspectSyscw float64) string {
	if suspectWrite >= minimumMeaningfulWriteMiBPerSecond {
		if suspectIsDominant(victimWrite, suspectWrite) {
			return dominantConclusion
		}
		return noDominantConclusion
	}
	if suspectSyscw >= minimumMeaningfulSyscwPerSecond {
		return syscallPressureConclusion
	}
	return noWritePressureConclusion
}

// WriteSummary emits a deterministic, table-like QEMU I/O summary.
func WriteSummary(dst io.Writer, report SummaryReport) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "QEMU I/O Summary")
	fmt.Fprintf(w, "Victim selector:\t%s\n", emptyDash(report.Plan.VictimSelector))
	fmt.Fprintf(w, "Suspect selector:\t%s\n", emptyDash(report.Plan.SuspectSelector))
	fmt.Fprintf(w, "Duration:\t%s\n", report.Duration)
	fmt.Fprintf(w, "Interval:\t%s\n\n", report.Interval)

	fmt.Fprintln(w, "VM targets")
	writeTargetRows(w, report.Plan.Targets)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Per-VM averages")
	fmt.Fprintln(w, "TARGET\tVM\tAVG_READ_MIB/S\tAVG_WRITE_MIB/S\tMAX_WRITE_MIB/S\tTOTAL_READ_MIB\tTOTAL_WRITTEN_MIB\tAVG_SYSCR/S\tAVG_SYSCW/S\tMAX_SYSCW/S\tERROR")
	for _, vm := range report.VMs {
		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			emptyDash(vm.Target.TargetType),
			emptyDash(vm.Target.VM.Name),
			summaryValue(vm.AverageReadMiBPerSecond, vm.Available),
			summaryValue(vm.AverageWriteMiBPerSecond, vm.Available),
			summaryValue(vm.MaxWriteMiBPerSecond, vm.Available),
			summaryValue(vm.TotalReadMiB, vm.Available),
			summaryValue(vm.TotalWrittenMiB, vm.Available),
			summaryValue(vm.AverageSyscrPerSecond, vm.Available),
			summaryValue(vm.AverageSyscwPerSecond, vm.Available),
			summaryValue(vm.MaxSyscwPerSecond, vm.Available),
			emptyDash(vm.Error),
		)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Diagnosis")
	fmt.Fprintf(w, "Victim average write MiB/s:\t%s\n", summaryValue(report.VictimAverageWriteMiBPerSecond, report.VictimDataAvailable))
	fmt.Fprintf(w, "Suspect average write MiB/s:\t%s\n", summaryValue(report.SuspectAverageWriteMiBPerSecond, report.SuspectDataAvailable))
	fmt.Fprintf(w, "Suspect/victim write ratio:\t%s\n", report.WriteRatio)
	fmt.Fprintf(w, "Dominant writer:\t%s\n", report.DominantWriter)
	fmt.Fprintf(w, "Victim average syscw/s:\t%s\n", summaryValue(report.VictimAverageSyscwPerSecond, report.VictimDataAvailable))
	fmt.Fprintf(w, "Suspect average syscw/s:\t%s\n", summaryValue(report.SuspectAverageSyscwPerSecond, report.SuspectDataAvailable))
	fmt.Fprintf(w, "Suspect/victim syscw ratio:\t%s\n", report.SyscwRatio)
	fmt.Fprintf(w, "Suspect write syscall pressure:\t%s\n", report.WriteSyscallPressure)
	fmt.Fprintf(w, "Dominant write syscall source:\t%s\n", report.DominantWriteSyscallSource)
	fmt.Fprintf(w, "Conclusion:\t%s\n", report.Conclusion)
	return w.Flush()
}

func summaryValue(value float64, available bool) string {
	if !available {
		return "-"
	}
	return fmt.Sprintf("%.2f", value)
}
