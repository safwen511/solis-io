package qemuio

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

type processSample struct {
	Counters Counters
	ReadAt   time.Time
	Err      error
}

const watchRowFormat = "%-10s  %-14s  %-10s  %-8s  %12s  %12s  %14s  %14s  %10s  %10s  %s\n"

// Watch repeatedly reads target process counters and writes interval rates.
func Watch(dst io.Writer, plan Plan, duration, interval time.Duration) error {
	if duration <= 0 {
		return fmt.Errorf("duration must be greater than zero")
	}
	if interval <= 0 {
		return fmt.Errorf("interval must be greater than zero")
	}
	if interval > duration {
		return fmt.Errorf("interval %s cannot exceed duration %s", interval, duration)
	}

	if err := writeWatchHeader(dst, plan, duration, interval); err != nil {
		return err
	}

	previous := make([]processSample, len(plan.Targets))
	for i, target := range plan.Targets {
		previous[i] = sampleProcess(target.VM.QEMUPID)
	}

	elapsed := time.Duration(0)
	for elapsed < duration {
		step := interval
		if remaining := duration - elapsed; step > remaining {
			step = remaining
		}
		time.Sleep(step)
		elapsed += step

		for i, target := range plan.Targets {
			current := sampleProcess(target.VM.QEMUPID)
			rates, sampleErr := ratesForSamples(previous[i], current)
			if err := writeWatchRow(dst, elapsed, target, rates, sampleErr); err != nil {
				return err
			}
			previous[i] = current
		}
	}

	return nil
}

func sampleProcess(pid string) processSample {
	counters, err := readProcessIO(pid)
	return processSample{Counters: counters, ReadAt: time.Now(), Err: err}
}

func ratesForSamples(previous, current processSample) (Rates, error) {
	if current.Err != nil {
		return Rates{}, current.Err
	}
	if previous.Err != nil {
		return Rates{}, fmt.Errorf("previous sample unavailable: %w", previous.Err)
	}
	return CalculateDelta(previous.Counters, current.Counters, current.ReadAt.Sub(previous.ReadAt))
}

func writeWatchHeader(dst io.Writer, plan Plan, duration, interval time.Duration) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "QEMU I/O Watch")
	fmt.Fprintf(w, "Victim selector:\t%s\n", emptyDash(plan.VictimSelector))
	fmt.Fprintf(w, "Suspect selector:\t%s\n", emptyDash(plan.SuspectSelector))
	fmt.Fprintf(w, "Duration:\t%s\n", duration)
	fmt.Fprintf(w, "Interval:\t%s\n\n", interval)
	fmt.Fprintln(w, "VM targets")
	fmt.Fprintln(w, "TARGET\tVM\tTENANT\tROLE\tQEMU_PID\tDISK")
	for _, target := range plan.Targets {
		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\n",
			emptyDash(target.TargetType),
			emptyDash(target.VM.Name),
			emptyDash(target.VM.Tenant),
			emptyDash(target.VM.Role),
			emptyDash(target.VM.QEMUPID),
			emptyDash(target.VM.Disk),
		)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Per-interval QEMU I/O")
	fmt.Fprintf(
		w,
		watchRowFormat,
		"ELAPSED_S",
		"TARGET",
		"VM",
		"QEMU_PID",
		"READ_MIB/S",
		"WRITE_MIB/S",
		"READ_BYTES/S",
		"WRITE_BYTES/S",
		"SYSCR/S",
		"SYSCW/S",
		"ERROR",
	)
	return w.Flush()
}

func writeWatchRow(dst io.Writer, elapsed time.Duration, target Target, rates Rates, sampleErr error) error {
	readMiB := rateText(rates.ReadMiBPerSecond, sampleErr)
	writeMiB := rateText(rates.WriteMiBPerSecond, sampleErr)
	readBytes := rateText(rates.ReadBytesPerSecond, sampleErr)
	writeBytes := rateText(rates.WriteBytesPerSecond, sampleErr)
	syscr := rateText(rates.SyscrPerSecond, sampleErr)
	syscw := rateText(rates.SyscwPerSecond, sampleErr)
	errorText := "-"
	if sampleErr != nil {
		errorText = strings.Join(strings.Fields(sampleErr.Error()), " ")
	}

	_, err := fmt.Fprintf(
		dst,
		watchRowFormat,
		fmt.Sprintf("%.3f", elapsed.Seconds()),
		emptyDash(target.TargetType),
		emptyDash(target.VM.Name),
		emptyDash(target.VM.QEMUPID),
		readMiB,
		writeMiB,
		readBytes,
		writeBytes,
		syscr,
		syscw,
		errorText,
	)
	return err
}

func rateText(value float64, sampleErr error) string {
	if sampleErr != nil {
		return "-"
	}
	return fmt.Sprintf("%.2f", value)
}

func emptyDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}
