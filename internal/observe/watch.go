package observe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// WatchOptions controls repeated snapshot collection. Collection duration and
// interval remain part of each Request and rendered snapshot.
type WatchOptions struct {
	Every      time.Duration
	Iterations int
}

// WatchSummary contains non-JSON terminal accounting written to stderr by the
// CLI so stdout remains a valid JSON Lines stream.
type WatchSummary struct {
	IterationsRun int
	OutputPath    string
}

// SnapshotCollector returns one complete observation for a watch iteration.
type SnapshotCollector func(context.Context) (ObserveSnapshot, error)

// Watch writes one compact JSON document per successful iteration.
func Watch(ctx context.Context, dst io.Writer, options WatchOptions, collect SnapshotCollector, summary *WatchSummary) error {
	if dst == nil {
		return errors.New("observe watch output is required")
	}
	if collect == nil {
		return errors.New("observe watch collector is required")
	}
	if summary == nil {
		return errors.New("observe watch summary is required")
	}
	if options.Every <= 0 {
		return errors.New("observe watch refresh interval must be positive")
	}
	if options.Iterations < 0 {
		return errors.New("observe watch iterations must not be negative")
	}

	nextStart := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		snapshot, err := collect(ctx)
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		data, err := MarshalJSON(snapshot)
		if err != nil {
			return err
		}
		if _, err := dst.Write(append(data, '\n')); err != nil {
			return err
		}
		summary.IterationsRun++
		if options.Iterations > 0 && summary.IterationsRun >= options.Iterations {
			return nil
		}

		nextStart = nextStart.Add(options.Every)
		wait := time.Until(nextStart)
		if wait <= 0 {
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// WriteWatchSummary writes no JSON and is intended for stderr.
func WriteWatchSummary(dst io.Writer, summary WatchSummary) error {
	if dst == nil {
		return errors.New("observe watch summary output is required")
	}
	outputPath := summary.OutputPath
	if outputPath == "" {
		outputPath = "-"
	}
	_, err := fmt.Fprintf(dst, "Solis Observe Watch Summary\nIterations run: %d\nOutput file: %s\n", summary.IterationsRun, outputPath)
	return err
}
