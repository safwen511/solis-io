package qemuio

import (
	"fmt"
	"time"
)

type processSample struct {
	Counters Counters
	ReadAt   time.Time
	Err      error
}

type intervalSample struct {
	Elapsed  time.Duration
	Interval time.Duration
	Target   Target
	Rates    Rates
	Err      error
}

// validateWindow validates window against its required contract.
func validateWindow(duration, interval time.Duration) error {
	if duration <= 0 {
		return fmt.Errorf("duration must be greater than zero")
	}
	if interval <= 0 {
		return fmt.Errorf("interval must be greater than zero")
	}
	if interval > duration {
		return fmt.Errorf("interval %s cannot exceed duration %s", interval, duration)
	}
	return nil
}

// sampleIntervals samples intervals for the configured observation interval.
func sampleIntervals(plan Plan, duration, interval time.Duration, consume func(intervalSample) error) error {
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
			sampleInterval := current.ReadAt.Sub(previous[i].ReadAt)
			rates, sampleErr := ratesForSamples(previous[i], current)
			if err := consume(intervalSample{
				Elapsed:  elapsed,
				Interval: sampleInterval,
				Target:   target,
				Rates:    rates,
				Err:      sampleErr,
			}); err != nil {
				return err
			}
			previous[i] = current
		}
	}

	return nil
}

// sampleProcess samples process for the configured observation interval.
func sampleProcess(pid string) processSample {
	counters, err := readProcessIO(pid)
	return processSample{Counters: counters, ReadAt: time.Now(), Err: err}
}

// ratesForSamples builds rates for samples and returns an error when validation or source access
// fails.
func ratesForSamples(previous, current processSample) (Rates, error) {
	if current.Err != nil {
		return Rates{}, current.Err
	}
	if previous.Err != nil {
		return Rates{}, fmt.Errorf("previous sample unavailable: %w", previous.Err)
	}
	return CalculateDelta(previous.Counters, current.Counters, current.ReadAt.Sub(previous.ReadAt))
}
