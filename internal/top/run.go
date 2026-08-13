package top

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// Source collects one real or test-provided dashboard snapshot.
type Source interface {
	Collect(context.Context, CollectRequest) (Snapshot, error)
}

// Run refreshes the read-only dashboard until the requested iteration count or
// context cancellation. It never places the terminal into raw mode.
func Run(ctx context.Context, dst io.Writer, source Source, options Options) error {
	if source == nil {
		return errors.New("top source is required")
	}
	if options.Duration <= 0 || options.Interval <= 0 || options.Interval > options.Duration {
		return errors.New("top duration and interval must be positive, and interval must not exceed duration")
	}
	if options.Every <= 0 {
		return errors.New("top refresh interval must be positive")
	}
	if options.Iterations < 0 {
		return errors.New("top iterations must not be negative")
	}
	if !ValidSortField(options.Sort) {
		return fmt.Errorf("invalid top sort field %q", options.Sort)
	}

	iteration := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		started := time.Now()
		snapshot, err := source.Collect(ctx, CollectRequest{
			Duration:           options.Duration,
			Interval:           options.Interval,
			IncludeEBPFLatency: options.IncludeEBPFLatency,
		})
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		view, err := BuildView(snapshot, options.Sort)
		if err != nil {
			return err
		}
		iteration++
		if options.Clear {
			if _, err := fmt.Fprint(dst, "\x1b[2J\x1b[H"); err != nil {
				return err
			}
		}
		if err := WriteFrame(dst, view, Frame{Iteration: iteration, Every: options.Every}); err != nil {
			return err
		}
		if options.Iterations > 0 && iteration >= options.Iterations {
			return nil
		}

		wait := time.Until(started.Add(options.Every))
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
