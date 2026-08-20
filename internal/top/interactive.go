package top

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"
)

type interactiveState struct {
	selectedVM       string
	selectedWorkflow int
	workflowRequest  LaunchRequest
	workflowRunning  bool
	workflowOutput   string
	workflowError    string
	workflowScroll   int
	workflowDetail   *WorkflowDetail
	workflowSaved    string
	workflowSaveErr  string
	sort             string
	showHelp         bool
	panel            dashboardPanel
	application      bool
}

type dashboardPanel string

const (
	panelOverview       dashboardPanel = "overview"
	panelDetails        dashboardPanel = "details"
	panelEvents         dashboardPanel = "events"
	panelWorkflows      dashboardPanel = "workflows"
	panelWorkflowOutput dashboardPanel = "workflow_output"
)

type interactiveCollectionResult struct {
	snapshot Snapshot
	err      error
}

type interactiveWorkflowResult struct {
	result WorkflowResult
	err    error
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

	state := interactiveState{sort: options.Sort, panel: panelOverview, application: options.Application}
	resourceMeter := newProcessResourceMeter(time.Now())
	var events eventTracker
	var history vmHistoryTracker
	actions := readKeyActions(input)
	iteration := 0
	view := View{
		Duration:    options.Duration.String(),
		Interval:    options.Interval.String(),
		StatusState: "collecting",
		Host:        HostView{Status: "collecting"},
		Attribution: AttributionView{Requested: options.IncludeEBPFLatency, Status: "collecting", Quality: AttributionUnavailable},
	}
	var timer *time.Timer
	var timerChannel <-chan time.Time
	var uiTicker *time.Ticker
	var uiTickerChannel <-chan time.Time
	var resultChannel <-chan interactiveCollectionResult
	var workflowResultChannel <-chan interactiveWorkflowResult
	var collectionStarted time.Time
	var nextCollectionAt time.Time
	var cancelCollection context.CancelFunc
	var cancelWorkflow context.CancelFunc
	collecting := false
	rendered := false
	if options.UIRefresh > 0 {
		uiTicker = time.NewTicker(options.UIRefresh)
		uiTickerChannel = uiTicker.C
		defer uiTicker.Stop()
	}

	startCollection := func() {
		collectionStarted = time.Now()
		nextCollectionAt = time.Time{}
		collecting = true
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
		collecting = false
	}
	finishWorkflow := func() {
		if cancelWorkflow != nil {
			cancelWorkflow()
			cancelWorkflow = nil
		}
		if workflowResultChannel != nil {
			<-workflowResultChannel
			workflowResultChannel = nil
		}
		state.workflowRunning = false
	}
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = nil
		timerChannel = nil
	}
	render := func(now time.Time) error {
		if len(view.Rows) == 0 && view.ObservedAtUTC.IsZero() && !options.Application {
			return nil
		}
		var frame strings.Builder
		width, height, _ := TerminalDimensions(dst)
		if err := WriteFrame(&frame, view, Frame{
			Iteration:         iteration,
			Every:             options.Every,
			UIRefresh:         options.UIRefresh,
			WindowDuration:    options.Duration,
			Now:               now,
			CollectionStarted: collectionStarted,
			NextCollectionAt:  nextCollectionAt,
			Collecting:        collecting,
			ShowBanner:        options.Application && !rendered,
			SelectedVM:        state.selectedVM,
			Sort:              state.sort,
			Interactive:       true,
			ShowHelp:          state.showHelp,
			ActivePanel:       state.panel,
			Events:            events.snapshot(),
			History:           history.ForVM(state.selectedVM),
			SelectedWorkflow:  state.selectedWorkflow,
			WorkflowRequest:   state.workflowRequest,
			WorkflowRunning:   state.workflowRunning,
			WorkflowOutput:    state.workflowOutput,
			WorkflowError:     state.workflowError,
			WorkflowScroll:    state.workflowScroll,
			WorkflowDetail:    state.workflowDetail != nil,
			WorkflowSavedPath: state.workflowSaved,
			WorkflowSaveError: state.workflowSaveErr,
			ProcessResources:  resourceMeter.Sample(now),
			Application:       options.Application,
			Width:             width,
			Height:            height,
		}); err != nil {
			return err
		}
		contents := frame.String()
		if options.Color {
			contents = colorizeApplicationFrame(contents)
		}
		var output strings.Builder
		if options.Clear && options.Application {
			writeApplicationFrame(&output, contents)
		} else {
			if options.Clear {
				output.WriteString("\x1b[2J\x1b[H")
			}
			output.WriteString(contents)
		}
		_, err := io.WriteString(dst, output.String())
		if err == nil {
			rendered = true
		}
		return err
	}

	startCollection()
	if options.Application {
		if err := render(time.Now()); err != nil {
			finishCollection()
			return err
		}
	}
	for {
		select {
		case <-ctx.Done():
			stopTimer()
			finishCollection()
			finishWorkflow()
			return nil
		case action, open := <-actions:
			if !open {
				actions = nil
				continue
			}
			if action == keyQuit {
				stopTimer()
				finishCollection()
				finishWorkflow()
				return nil
			}
			if state.panel == panelWorkflowOutput {
				changed := false
				switch action {
				case keyUp:
					if state.workflowScroll > 0 {
						state.workflowScroll--
					}
					changed = true
				case keyDown:
					state.workflowScroll++
					changed = true
				case keyHelp:
					state.showHelp = !state.showHelp
					changed = true
				case keyBack:
					if !state.workflowRunning {
						state.panel = panelWorkflows
						state.workflowRequest = LaunchRequest{}
						state.workflowOutput = ""
						state.workflowError = ""
						state.workflowScroll = 0
						state.workflowDetail = nil
						state.workflowSaved = ""
						state.workflowSaveErr = ""
						if resultChannel == nil {
							startCollection()
						}
						changed = true
					}
				case keySaveDetail:
					if !state.workflowRunning && state.workflowDetail != nil && options.SaveWorkflowDetail != nil {
						path, err := options.SaveWorkflowDetail(*state.workflowDetail)
						if err != nil {
							state.workflowSaveErr = err.Error()
							state.workflowSaved = ""
						} else {
							state.workflowSaved = path
							state.workflowSaveErr = ""
						}
						changed = true
					}
				}
				if changed {
					if err := render(time.Now()); err != nil {
						finishCollection()
						finishWorkflow()
						return err
					}
				}
				continue
			}
			if action == keyOpenPanel && state.panel == panelWorkflows && options.RunWorkflow != nil {
				request, available := selectedWorkflowRequest(state.selectedWorkflow, state.selectedVM)
				if available {
					stopTimer()
					finishCollection()
					state.panel = panelWorkflowOutput
					state.workflowRequest = request
					state.workflowRunning = true
					state.workflowOutput = ""
					state.workflowError = ""
					state.workflowScroll = 0
					state.workflowDetail = nil
					state.workflowSaved = ""
					state.workflowSaveErr = ""
					workflowContext, cancel := context.WithCancel(ctx)
					cancelWorkflow = cancel
					results := make(chan interactiveWorkflowResult, 1)
					workflowResultChannel = results
					go func() {
						result, err := options.RunWorkflow(workflowContext, request)
						results <- interactiveWorkflowResult{result: result, err: err}
					}()
					if err := render(time.Now()); err != nil {
						finishWorkflow()
						return err
					}
					continue
				}
			}
			changed := applyInteractiveAction(&view, &state, action)
			if action == keyRefresh && resultChannel == nil {
				stopTimer()
				startCollection()
				changed = true
			}
			if changed {
				if err := render(time.Now()); err != nil {
					finishCollection()
					return err
				}
			}
		case result := <-resultChannel:
			resultChannel = nil
			collecting = false
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
			events.Update(view)
			history.Update(view)
			iteration++
			if options.Iterations > 0 && iteration >= options.Iterations {
				if err := render(time.Now()); err != nil {
					return err
				}
				return nil
			}
			nextCollectionAt = collectionStarted.Add(options.Every)
			wait := time.Until(nextCollectionAt)
			if wait <= 0 {
				startCollection()
				if err := render(time.Now()); err != nil {
					finishCollection()
					return err
				}
				continue
			}
			if err := render(time.Now()); err != nil {
				return err
			}
			timer = time.NewTimer(wait)
			timerChannel = timer.C
		case result := <-workflowResultChannel:
			workflowResultChannel = nil
			if cancelWorkflow != nil {
				cancelWorkflow()
				cancelWorkflow = nil
			}
			state.workflowRunning = false
			state.workflowOutput = result.result.Output
			state.workflowDetail = result.result.Detail
			if result.err != nil {
				state.workflowError = result.err.Error()
			}
			if err := render(time.Now()); err != nil {
				return err
			}
		case <-timerChannel:
			stopTimer()
			startCollection()
			if err := render(time.Now()); err != nil {
				finishCollection()
				return err
			}
		case now := <-uiTickerChannel:
			if err := render(now); err != nil {
				finishCollection()
				return err
			}
		}
	}
}

// writeApplicationFrame renders application frame in the package's stable operator-facing format.
func writeApplicationFrame(output *strings.Builder, contents string) {
	output.WriteString("\x1b[H")
	lines := strings.Split(contents, "\n")
	for index, line := range lines {
		// Clear each row before repainting it so shorter data never retains a
		// suffix from the previous frame. The carriage return also makes this
		// independent of terminal newline translation.
		output.WriteString("\x1b[2K\r")
		output.WriteString(line)
		if index+1 < len(lines) {
			output.WriteByte('\n')
		}
	}
	output.WriteString("\x1b[J")
}

// colorizeApplicationFrame adds terminal-only semantic color after layout has
// been calculated. Keeping ANSI escapes out of WriteFrame preserves exact box
// widths and guarantees redirected/plain output remains escape-free.
func colorizeApplicationFrame(contents string) string {
	const (
		reset    = "\x1b[0m"
		boldCyan = "\x1b[1;36m"
		cyan     = "\x1b[36m"
		green    = "\x1b[32m"
		yellow   = "\x1b[33m"
		red      = "\x1b[31m"
		dim      = "\x1b[2m"
	)
	colors := map[string]string{
		"AVAILABLE": green, "COMPLETE": green, "READY": green, "SAVED": green,
		"RUNNING": cyan, "MEASURED": cyan, "COLLECTING": cyan,
		"DEGRADED": yellow, "LOW": yellow, "PAUSED": yellow,
		"UNAVAILABLE": red, "FAILED": red, "HIGH": red,
		"IDLE": dim, "NOT_RUNNING": dim,
	}
	lines := strings.Split(contents, "\n")
	for index, line := range lines {
		switch {
		case strings.HasPrefix(line, "╭─"):
			lines[index] = boldCyan + line + reset
			continue
		case strings.Contains(line, "████") || strings.Contains(line, "██╔") || strings.Contains(line, "██║") || strings.Contains(line, "╚═"):
			lines[index] = boldCyan + line + reset
			continue
		case strings.Contains(line, "▶"):
			lines[index] = boldCyan + line + reset
			continue
		case strings.HasPrefix(line, "Keys:") || strings.HasPrefix(line, "Safety:") || strings.HasPrefix(line, "Caveat:"):
			lines[index] = dim + line + reset
			continue
		}
		if open := strings.IndexByte(line, '['); open >= 0 {
			if relativeClose := strings.IndexByte(line[open:], ']'); relativeClose >= 0 {
				closeIndex := open + relativeClose + 1
				lines[index] = line[:open] + boldCyan + line[open:closeIndex] + reset + line[closeIndex:]
				continue
			}
		}
		var styled strings.Builder
		for position := 0; position < len(line); {
			if (line[position] >= 'A' && line[position] <= 'Z') || line[position] == '_' {
				end := position + 1
				for end < len(line) && ((line[end] >= 'A' && line[end] <= 'Z') || line[end] == '_') {
					end++
				}
				word := line[position:end]
				if color, ok := colors[word]; ok {
					styled.WriteString(color)
					styled.WriteString(word)
					styled.WriteString(reset)
				} else {
					styled.WriteString(word)
				}
				position = end
				continue
			}
			styled.WriteByte(line[position])
			position++
		}
		lines[index] = styled.String()
	}
	return strings.Join(lines, "\n")
}

// applyInteractiveAction applies interactive action to the current model.
func applyInteractiveAction(view *View, state *interactiveState, action keyAction) bool {
	if sortField, ok := sortForKey(action); ok {
		state.sort = sortField
		sortRows(view.Rows, state.sort)
		state.selectedVM = retainedSelection(view.Rows, state.selectedVM)
		return true
	}
	switch action {
	case keyUp:
		if state.panel == panelWorkflows {
			state.selectedWorkflow = normalizedWorkflowIndex(state.selectedWorkflow - 1)
			return workflowCount() > 0
		}
		state.selectedVM = moveSelection(view.Rows, state.selectedVM, -1)
		return len(view.Rows) > 0
	case keyDown:
		if state.panel == panelWorkflows {
			state.selectedWorkflow = normalizedWorkflowIndex(state.selectedWorkflow + 1)
			return workflowCount() > 0
		}
		state.selectedVM = moveSelection(view.Rows, state.selectedVM, 1)
		return len(view.Rows) > 0
	case keyHelp:
		state.showHelp = !state.showHelp
		return true
	case keyNextPanel:
		state.panel = movePanel(state.panel, 1, state.application)
		return true
	case keyPreviousPanel:
		state.panel = movePanel(state.panel, -1, state.application)
		return true
	case keyOpenPanel:
		if state.panel == panelWorkflows {
			return false
		}
		state.panel = panelDetails
		return true
	case keyBack:
		state.panel = panelOverview
		return true
	case keyHomePanel:
		state.panel = panelOverview
		return true
	case keyDetailsPanel:
		state.panel = panelDetails
		return true
	case keyEventsPanel:
		state.panel = panelEvents
		return true
	case keyWorkflowsPanel:
		if !state.application {
			return false
		}
		state.panel = panelWorkflows
		return true
	default:
		return false
	}
}

// movePanel builds move panel from validated inputs.
func movePanel(current dashboardPanel, delta int, application bool) dashboardPanel {
	panels := []dashboardPanel{panelOverview, panelDetails, panelEvents}
	if application {
		panels = append(panels, panelWorkflows)
	}
	index := 0
	for candidate := range panels {
		if panels[candidate] == current {
			index = candidate
			break
		}
	}
	index = (index + delta) % len(panels)
	if index < 0 {
		index += len(panels)
	}
	return panels[index]
}

// retainedSelection derives stable operator-facing text for retained selection.
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

// moveSelection derives stable operator-facing text for move selection.
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
