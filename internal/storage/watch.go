package storage

import (
	"fmt"
	"io"
	"time"
)

// Watch repeatedly samples the snapshot's physical disks and writes interval deltas.
func Watch(dst io.Writer, snapshot Snapshot, duration, interval time.Duration) error {
	if duration <= 0 {
		return fmt.Errorf("duration must be greater than zero")
	}
	if interval <= 0 {
		return fmt.Errorf("interval must be greater than zero")
	}
	if interval > duration {
		return fmt.Errorf("interval %s cannot exceed duration %s", interval, duration)
	}

	if err := writeWatchHeader(dst, snapshot, duration, interval); err != nil {
		return err
	}

	previous := append([]DeviceStats(nil), snapshot.Devices...)
	scheduledElapsed := time.Duration(0)
	for scheduledElapsed < duration {
		step := interval
		if remaining := duration - scheduledElapsed; step > remaining {
			step = remaining
		}

		started := time.Now()
		time.Sleep(step)
		actualInterval := time.Since(started)
		scheduledElapsed += step

		for i, previousStats := range previous {
			currentStats := readDeviceStats(previousStats.PhysicalDisk)
			delta, err := CalculateDelta(previousStats, currentStats, actualInterval)
			if err != nil {
				return err
			}
			delta.Elapsed = scheduledElapsed
			if err := writeWatchDelta(dst, delta); err != nil {
				return err
			}
			previous[i] = currentStats
		}
	}

	return nil
}

func writeWatchHeader(dst io.Writer, snapshot Snapshot, duration, interval time.Duration) error {
	if _, err := fmt.Fprintln(dst, "Storage Watch"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst, "Victim selector:  %s\n", snapshot.VictimSelector); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst, "Suspect selector: %s\n", snapshot.SuspectSelector); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst, "Duration:         %s\n", duration); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(dst, "Interval:         %s\n\n", interval); err != nil {
		return err
	}

	if err := writeVMTargets(dst, snapshot.Targets); err != nil {
		return err
	}
	_, err := fmt.Fprintf(
		dst,
		"%-10s  %-18s  %12s  %12s  %16s  %19s  %14s  %20s\n",
		"ELAPSED_S",
		"PHYSICAL_DISK",
		"READS/S",
		"WRITES/S",
		"SECTORS_READ/S",
		"SECTORS_WRITTEN/S",
		"IO_IN_PROGRESS",
		"WEIGHTED_IO_DELTA_MS",
	)
	return err
}

func writeWatchDelta(dst io.Writer, delta DeviceDelta) error {
	_, err := fmt.Fprintf(
		dst,
		"%-10.3f  %-18s  %12s  %12s  %16s  %19s  %14s  %20s\n",
		delta.Elapsed.Seconds(),
		emptyDash(delta.PhysicalDisk),
		rateText(delta.ReadsPerSecond),
		rateText(delta.WritesPerSecond),
		rateText(delta.SectorsReadPerSecond),
		rateText(delta.SectorsWritePerSecond),
		counterText(delta.IOInProgress),
		counterText(delta.WeightedIODeltaMS),
	)
	return err
}

func rateText(rate Rate) string {
	if !rate.Available {
		return "-"
	}
	return fmt.Sprintf("%.2f", rate.Value)
}
