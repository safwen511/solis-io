package storage

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/hoststorage"
)

type layerSample struct {
	LayerType string
	Device    string
	Stats     DeviceStats
}

// Watch repeatedly samples the snapshot's source, parent, and physical devices
// and writes interval deltas.
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

	previous := watchLayerSamples(snapshot.Targets)
	if len(previous) == 0 {
		previous = []layerSample{{LayerType: "-", Device: "-", Stats: DeviceStats{}}}
	}
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

		for i, previousSample := range previous {
			currentStats := readDeviceStats(previousSample.Device)
			delta, err := CalculateDelta(previousSample.Stats, currentStats, actualInterval)
			if err != nil {
				return err
			}
			delta.Elapsed = scheduledElapsed
			delta.LayerType = previousSample.LayerType
			delta.Device = previousSample.Device
			if err := writeWatchDelta(dst, delta); err != nil {
				return err
			}
			previous[i].Stats = currentStats
		}
	}

	return nil
}

func watchLayerSamples(targets []VMTarget) []layerSample {
	return watchLayerSamplesWith(targets, hoststorage.NormalizeBlockDevice, readDeviceStats)
}

func watchLayerSamplesWith(
	targets []VMTarget,
	normalize func(string) string,
	readStats func(string) DeviceStats,
) []layerSample {
	layerOrder := map[string]int{"source": 0, "parent": 1, "physical": 2}
	devices := make(map[string]layerSample)
	for _, target := range targets {
		layers := []struct {
			name    string
			devices string
		}{
			{"source", target.Storage.SourceDevice},
			{"parent", target.Storage.ParentDevice},
			{"physical", target.Storage.PhysicalDisk},
		}
		for _, layer := range layers {
			for _, device := range strings.Split(layer.devices, ",") {
				device = strings.TrimSpace(device)
				if device == "" || device == "-" {
					continue
				}
				normalized := normalize(device)
				if normalized == "" {
					normalized = device
				}
				key := layer.name + "\x00" + normalized
				devices[key] = layerSample{LayerType: layer.name, Device: normalized}
			}
		}
	}

	samples := make([]layerSample, 0, len(devices))
	for _, sample := range devices {
		samples = append(samples, sample)
	}
	sort.Slice(samples, func(i, j int) bool {
		if layerOrder[samples[i].LayerType] != layerOrder[samples[j].LayerType] {
			return layerOrder[samples[i].LayerType] < layerOrder[samples[j].LayerType]
		}
		return samples[i].Device < samples[j].Device
	})
	for i := range samples {
		samples[i].Stats = readStats(samples[i].Device)
	}

	return samples
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
		"%-10s  %-8s  %-18s  %10s  %10s  %12s  %12s  %14s  %16s  %22s  %10s\n",
		"ELAPSED_S",
		"LAYER",
		"DEVICE",
		"READS/S",
		"WRITES/S",
		"READ_MIB/S",
		"WRITE_MIB/S",
		"IO_IN_PROGRESS",
		"IO_TIME_DELTA_MS",
		"WEIGHTED_IO_DELTA_MS",
		"UTIL_PCT",
	)
	return err
}

func writeWatchDelta(dst io.Writer, delta DeviceDelta) error {
	_, err := fmt.Fprintf(
		dst,
		"%-10.3f  %-8s  %-18s  %10s  %10s  %12s  %12s  %14s  %16s  %22s  %10s\n",
		delta.Elapsed.Seconds(),
		emptyDash(delta.LayerType),
		emptyDash(delta.Device),
		rateText(delta.ReadsPerSecond),
		rateText(delta.WritesPerSecond),
		rateText(delta.ReadMiBPerSecond),
		rateText(delta.WriteMiBPerSecond),
		counterText(delta.IOInProgress),
		counterText(delta.IOTimeDeltaMS),
		counterText(delta.WeightedIODeltaMS),
		percentText(delta.UtilPercent),
	)
	return err
}

func percentText(rate Rate) string {
	if !rate.Available {
		return "-"
	}
	return fmt.Sprintf("%.2f%%", rate.Value)
}

func rateText(rate Rate) string {
	if !rate.Available {
		return "-"
	}
	return fmt.Sprintf("%.2f", rate.Value)
}
