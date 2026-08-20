package qemuio

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

const watchRowFormat = "%-10s  %-14s  %-10s  %-8s  %12s  %12s  %14s  %14s  %10s  %10s  %s\n"

// Watch repeatedly reads target process counters and writes interval rates.
func Watch(dst io.Writer, plan Plan, duration, interval time.Duration) error {
	if err := validateWindow(duration, interval); err != nil {
		return err
	}

	if err := writeWatchHeader(dst, plan, duration, interval); err != nil {
		return err
	}

	return sampleIntervals(plan, duration, interval, func(sample intervalSample) error {
		return writeWatchRow(dst, sample.Elapsed, sample.Target, sample.Rates, sample.Err)
	})
}

// writeWatchHeader renders watch header in the package's stable operator-facing format.
func writeWatchHeader(dst io.Writer, plan Plan, duration, interval time.Duration) error {
	w := tabwriter.NewWriter(dst, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "QEMU I/O Watch")
	fmt.Fprintf(w, "Victim selector:\t%s\n", emptyDash(plan.VictimSelector))
	fmt.Fprintf(w, "Suspect selector:\t%s\n", emptyDash(plan.SuspectSelector))
	fmt.Fprintf(w, "Duration:\t%s\n", duration)
	fmt.Fprintf(w, "Interval:\t%s\n\n", interval)
	fmt.Fprintln(w, "VM targets")
	writeTargetRows(w, plan.Targets)
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

// writeTargetRows renders target rows in the package's stable operator-facing format.
func writeTargetRows(dst io.Writer, targets []Target) {
	fmt.Fprintln(dst, "TARGET\tVM\tTENANT\tROLE\tQEMU_PID\tDISK")
	for _, target := range targets {
		fmt.Fprintf(
			dst,
			"%s\t%s\t%s\t%s\t%s\t%s\n",
			emptyDash(target.TargetType),
			emptyDash(target.VM.Name),
			emptyDash(target.VM.Tenant),
			emptyDash(target.VM.Role),
			emptyDash(target.VM.QEMUPID),
			emptyDash(target.VM.Disk),
		)
	}
}

// writeWatchRow renders watch row in the package's stable operator-facing format.
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

// rateText formats a measured rate for stable human-readable output.
func rateText(value float64, sampleErr error) string {
	if sampleErr != nil {
		return "-"
	}
	return fmt.Sprintf("%.2f", value)
}

// emptyDash replaces empty text with a dash so table columns remain explicit.
func emptyDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}
