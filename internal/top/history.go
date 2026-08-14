package top

import "time"

const maxVMInvestigationSamples = 8

// VMInvestigationSample is one completed, privacy-safe dashboard measurement
// retained in memory for the selected-VM investigation panel.
type VMInvestigationSample struct {
	CompletedAtUTC       time.Time
	Pressure             string
	WriteMiBPerSecond    float64
	WriteAvailable       bool
	AttributedOps        uint64
	LatencyP95MS         float64
	AttributionAvailable bool
	AttributionState     string
}

type vmHistoryTracker struct {
	samples map[string][]VMInvestigationSample
}

func (tracker *vmHistoryTracker) Update(view View) {
	if tracker.samples == nil {
		tracker.samples = make(map[string][]VMInvestigationSample)
	}
	for _, row := range view.Rows {
		if row.Name == "" {
			continue
		}
		sample := VMInvestigationSample{
			CompletedAtUTC:       view.CompletedAtUTC,
			Pressure:             row.Pressure,
			WriteMiBPerSecond:    row.WriteMiBPerSecond,
			WriteAvailable:       row.WriteAvailable,
			AttributedOps:        row.AttributedOps,
			LatencyP95MS:         row.LatencyP95MS,
			AttributionAvailable: row.AttributionAvailable,
			AttributionState:     row.AttributionState,
		}
		history := append(tracker.samples[row.Name], sample)
		if len(history) > maxVMInvestigationSamples {
			history = append([]VMInvestigationSample(nil), history[len(history)-maxVMInvestigationSamples:]...)
		}
		tracker.samples[row.Name] = history
	}
}

func (tracker *vmHistoryTracker) ForVM(name string) []VMInvestigationSample {
	if tracker == nil || tracker.samples == nil {
		return nil
	}
	return append([]VMInvestigationSample(nil), tracker.samples[name]...)
}
