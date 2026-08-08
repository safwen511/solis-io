// Package capture writes a reproducible bundle of Solis incident evidence.
package capture

import (
	"time"

	"github.com/safwen511/solis-io/internal/diagnose"
	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/experiment"
	"github.com/safwen511/solis-io/internal/incident"
	"github.com/safwen511/solis-io/internal/qemuio"
	"github.com/safwen511/solis-io/internal/storage"
	"github.com/safwen511/solis-io/internal/traceplan"
)

const commandName = "solis capture noisy-neighbor"

// Inputs contains capture selectors and output settings.
type Inputs struct {
	OutputDirectory    string
	ReportDirectory    string
	Victim             string
	Suspect            string
	Duration           time.Duration
	Interval           time.Duration
	IncludeEBPFLatency bool
}

// Evidence contains the already parsed, resolved, and sampled capture data.
type Evidence struct {
	Experiment  experiment.Report
	Incident    incident.Explanation
	TracePlan   traceplan.Plan
	Storage     storage.Snapshot
	QEMU        qemuio.SummaryReport
	EBPFLatency *ebpf.BlockLatencyEvidence
	Diagnosis   diagnose.Report
}

// Result identifies the created capture directory and files.
type Result struct {
	Directory string
	Files     []string
}
