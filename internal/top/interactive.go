package top

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

type interactiveState struct {
	selectedVM string
	sort       string
	showHelp   bool
}

type interactiveCollectionResult struct {
	snapshot Snapshot
	err      error
}

// RunInteractive runs the read-only keyboard-driven dashboard over an already
// configured terminal. Terminal raw-mode setup and restoration remain the CLI
// caller's responsibility so this event loop stays fixture-testable.
func RunInteractive(ctx context.Context, input io.Reader, dst io.Writer, source Source, options Options) error {
	if err := validateOptions(source, options); err != nil {
		return err
	}
	if input == nil {
		return errors.New("top interactive input is required")
	}

	state := interactiveState{sort: options.Sort}
	actions := readKeyActions(input)
	iteration := 0
	var view View
	var timer *time.Timer
	var timerChannel <-chan time.Time
	var resultChannel <-chan interactiveCollectionResult
	var collectionStarted time.Time
	var cancelCollection context.CancelFunc

	startCollection := func() {
		collectionStarted = time.Now()
		collectionContext, cancel := context.WithCancel(ctx)
		cancelCollection = cancel
		results := make(chan interactiveCollectionResult, 1)
		resultChannel = results
		go func() {
			snapshot, err := source.Collect(collectionContext, CollectRequest{
				Duration:           options.Duration,
				Interval:           options.Interval,
				IncludeEBPFLatency: options.IncludeEBPFLatency,
			})
			results <- interactiveCollectionResult{snapshot: snapshot, err: err}
		}()
	}
	finishCollection := func() {
		if cancelCollection != nil {
			cancelCollection()
			cancelCollection = nil
		}
		if resultChannel != nil {
			<-resultChannel
			resultChannel = nil
		}
	}
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = nil
		timerChannel = nil
	}
	render := func() error {
		if len(view.Rows) == 0 && view.ObservedAtUTC.IsZero() {
			return nil
		}
		if options.Clear {
			if _, err := fmt.Fprint(dst, "\x1b[2J\x1b[H"); err != nil {
				return err
			}
		}
		return WriteFrame(dst, view, Frame{
			Iteration:   iteration,
			Every:       options.Every,
			SelectedVM:  state.selectedVM,
			Sort:        state.sort,
			Interactive: true,
			ShowHelp:    state.showHelp,
		})
	}

	startCollection()
	for {
		select {
		case <-ctx.Done():
			stopTimer()
			finishCollection()
			return nil
		case action, open := <-actions:
			if !open {
				actions = nil
				continue
			}
			if action == keyQuit {
				stopTimer()
				finishCollection()
				return nil
			}
			changed := applyInteractiveAction(&view, &state, action)
			if action == keyRefresh && resultChannel == nil {
				stopTimer()
				startCollection()
			}
			if changed {
				if err := render(); err != nil {
					return err
				}
			}
		case result := <-resultChannel:
			resultChannel = nil
			if cancelCollection != nil {
				cancelCollection()
				cancelCollection = nil
			}
			if result.err != nil {
				if ctx.Err() != nil || errors.Is(result.err, context.Canceled) {
					return nil
				}
				return result.err
			}
			var err error
			view, err = BuildView(result.snapshot, state.sort)
			if err != nil {
				return err
			}
			state.selectedVM = retainedSelection(view.Rows, state.selectedVM)
			iteration++
			if err := render(); err != nil {
				return err
			}
			if options.Iterations > 0 && iteration >= options.Iterations {
				return nil
			}
			wait := time.Until(collectionStarted.Add(options.Every))
			if wait <= 0 {
				startCollection()
				continue
			}
			timer = time.NewTimer(wait)
			timerChannel = timer.C
		case <-timerChannel:
			stopTimer()
			startCollection()
		}
	}
}

func applyInteractiveAction(view *View, state *interactiveState, action keyAction) bool {
	if sortField, ok := sortForKey(action); ok {
		state.sort = sortField
		sortRows(view.Rows, state.sort)
		state.selectedVM = retainedSelection(view.Rows, state.selectedVM)
		return true
	}
	switch action {
	case keyUp:
		state.selectedVM = moveSelection(view.Rows, state.selectedVM, -1)
		return len(view.Rows) > 0
	case keyDown:
		state.selectedVM = moveSelection(view.Rows, state.selectedVM, 1)
		return len(view.Rows) > 0
	case keyHelp:
		state.showHelp = !state.showHelp
		return true
	default:
		return false
	}
}

func retainedSelection(rows []VMRow, selected string) string {
	if len(rows) == 0 {
		return ""
	}
	for _, row := range rows {
		if row.Name == selected {
			return selected
		}
	}
	return rows[0].Name
}

func moveSelection(rows []VMRow, selected string, delta int) string {
	if len(rows) == 0 {
		return ""
	}
	index := 0
	for candidate := range rows {
		if rows[candidate].Name == selected {
			index = candidate
			break
		}
	}
	index = (index + delta) % len(rows)
	if index < 0 {
		index += len(rows)
	}
	return rows[index].Name
}
