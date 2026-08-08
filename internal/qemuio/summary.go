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
	dominantConclusion                 = "Suspect QEMU process is the dominant writer during the observation window."
	noDominantConclusion               = "No dominant QEMU writer identified from process I/O counters."
	noWritePressureConclusion          = "No meaningful QEMU write pressure observed during the observation window."
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
	VictimDataAvailable             bool
	SuspectDataAvailable            bool
	MeaningfulSuspectWritePressure  bool
	SuspectDominant                 bool
	WriteRatio                      string
	DominantWriter                  string
	Conclusion                      string
}

type summaryAccumulator struct {
	seconds          float64
	readMiB          float64
	writeMiB         float64
	syscr            float64
	syscw            float64
	maxWriteMiB      float64
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
		}
		report.VMs = append(report.VMs, vmSummary)

		if vmSummary.Available && targetHasType(target, "victim") {
			report.VictimDataAvailable = true
			report.VictimAverageWriteMiBPerSecond += vmSummary.AverageWriteMiBPerSecond
		}
		if vmSummary.Available && targetHasType(target, "suspect") {
			report.SuspectDataAvailable = true
			report.SuspectAverageWriteMiBPerSecond = vmSummary.AverageWriteMiBPerSecond
		}
	}

	if !report.VictimDataAvailable || !report.SuspectDataAvailable {
		report.WriteRatio = "-"
		report.DominantWriter = "-"
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
	report.Conclusion = conclusionForRates(
		report.VictimAverageWriteMiBPerSecond,
		report.SuspectAverageWriteMiBPerSecond,
	)
	if report.SuspectDominant {
		report.DominantWriter = plan.SuspectSelector
	} else {
		report.DominantWriter = "-"
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

func conclusionForRates(victim, suspect float64) string {
	if suspect < minimumMeaningfulWriteMiBPerSecond {
		return noWritePressureConclusion
	}
	if suspectIsDominant(victim, suspect) {
		return dominantConclusion
	}
	return noDominantConclusion
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
	fmt.Fprintln(w, "TARGET\tVM\tAVG_READ_MIB/S\tAVG_WRITE_MIB/S\tMAX_WRITE_MIB/S\tTOTAL_READ_MIB\tTOTAL_WRITTEN_MIB\tAVG_SYSCR/S\tAVG_SYSCW/S\tERROR")
	for _, vm := range report.VMs {
		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			emptyDash(vm.Target.TargetType),
			emptyDash(vm.Target.VM.Name),
			summaryValue(vm.AverageReadMiBPerSecond, vm.Available),
			summaryValue(vm.AverageWriteMiBPerSecond, vm.Available),
			summaryValue(vm.MaxWriteMiBPerSecond, vm.Available),
			summaryValue(vm.TotalReadMiB, vm.Available),
			summaryValue(vm.TotalWrittenMiB, vm.Available),
			summaryValue(vm.AverageSyscrPerSecond, vm.Available),
			summaryValue(vm.AverageSyscwPerSecond, vm.Available),
			emptyDash(vm.Error),
		)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Diagnosis")
	fmt.Fprintf(w, "Victim average write MiB/s:\t%s\n", summaryValue(report.VictimAverageWriteMiBPerSecond, report.VictimDataAvailable))
	fmt.Fprintf(w, "Suspect average write MiB/s:\t%s\n", summaryValue(report.SuspectAverageWriteMiBPerSecond, report.SuspectDataAvailable))
	fmt.Fprintf(w, "Suspect/victim write ratio:\t%s\n", report.WriteRatio)
	fmt.Fprintf(w, "Dominant writer:\t%s\n", report.DominantWriter)
	fmt.Fprintf(w, "Conclusion:\t%s\n", report.Conclusion)
	return w.Flush()
}

func summaryValue(value float64, available bool) string {
	if !available {
		return "-"
	}
	return fmt.Sprintf("%.2f", value)
}
