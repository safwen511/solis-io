// Package observe builds one privacy-safe, window-correlated bird's-eye snapshot
// from existing Solis collectors.
package observe

import (
	"time"

	"github.com/safwen511/solis-io/internal/hostmetrics"
	"github.com/safwen511/solis-io/internal/observability"
	"github.com/safwen511/solis-io/internal/servicehealth"
	statusview "github.com/safwen511/solis-io/internal/status"
)

const SchemaVersion = "1"

type EvidenceState string

const (
	EvidenceMeasured      EvidenceState = "measured"
	EvidenceDerived       EvidenceState = "derived"
	EvidenceUnavailable   EvidenceState = "unavailable"
	EvidencePartial       EvidenceState = "partial"
	EvidenceDisabled      EvidenceState = "disabled"
	EvidenceNotConfigured EvidenceState = "not_configured"
	EvidenceUnsupported   EvidenceState = "unsupported"
	EvidenceError         EvidenceState = "error"
)

type Target struct {
	Name    string `json:"name"`
	Tenant  string `json:"tenant"`
	Role    string `json:"role"`
	State   string `json:"state"`
	IP      string `json:"ip"`
	QEMUPID int    `json:"qemu_pid"`
	Disk    string `json:"disk"`
}

type SectionQuality struct {
	Section string        `json:"section"`
	State   EvidenceState `json:"state"`
	Source  string        `json:"source"`
	Error   string        `json:"error"`
}

type EvidenceQuality struct {
	Overall  EvidenceState    `json:"overall"`
	Sections []SectionQuality `json:"sections"`
}

type UnavailableSection struct {
	Section string        `json:"section"`
	State   EvidenceState `json:"state"`
	Reason  string        `json:"reason"`
}

type StorageTarget struct {
	TargetType   string `json:"target_type"`
	VM           string `json:"vm"`
	Disk         string `json:"disk"`
	Mountpoint   string `json:"mountpoint"`
	SourceDevice string `json:"source_device"`
	ParentDevice string `json:"parent_device"`
	PhysicalDisk string `json:"physical_disk"`
}

type StorageTopology struct {
	Available          bool            `json:"available"`
	SharedPhysicalDisk bool            `json:"shared_physical_disk"`
	PhysicalDisk       string          `json:"physical_disk"`
	Targets            []StorageTarget `json:"targets"`
}

type QEMUVM struct {
	TargetType       string  `json:"target_type"`
	VM               string  `json:"vm"`
	Available        bool    `json:"available"`
	AverageReadMiBS  float64 `json:"avg_read_mib_s"`
	AverageWriteMiBS float64 `json:"avg_write_mib_s"`
	MaxWriteMiBS     float64 `json:"max_write_mib_s"`
	AverageSyscrS    float64 `json:"avg_syscr_s"`
	AverageSyscwS    float64 `json:"avg_syscw_s"`
	MaxSyscwS        float64 `json:"max_syscw_s"`
	Error            string  `json:"error"`
}

type QEMUEvidence struct {
	Available                  bool     `json:"available"`
	VMs                        []QEMUVM `json:"vms"`
	VictimAverageWriteMiBS     float64  `json:"victim_avg_write_mib_s"`
	SuspectAverageWriteMiBS    float64  `json:"suspect_avg_write_mib_s"`
	VictimAverageSyscwS        float64  `json:"victim_avg_syscw_s"`
	SuspectAverageSyscwS       float64  `json:"suspect_avg_syscw_s"`
	MeaningfulSuspectPressure  bool     `json:"meaningful_suspect_pressure"`
	SuspectDominant            bool     `json:"suspect_dominant"`
	DominantWriter             string   `json:"dominant_writer"`
	DominantWriteSyscallSource string   `json:"dominant_write_syscall_source"`
	Conclusion                 string   `json:"conclusion"`
}

type DiscoveryCandidate struct {
	Name             string  `json:"name"`
	Tenant           string  `json:"tenant"`
	Role             string  `json:"role"`
	SharedDisk       bool    `json:"shared_disk"`
	AverageWriteMiBS float64 `json:"avg_write_mib_s"`
	MaxWriteMiBS     float64 `json:"max_write_mib_s"`
	AverageSyscwS    float64 `json:"avg_syscw_s"`
	MaxSyscwS        float64 `json:"max_syscw_s"`
	Score            string  `json:"score"`
	Reason           string  `json:"reason"`
}

type DiscoveryEvidence struct {
	Enabled            bool                 `json:"enabled"`
	Available          bool                 `json:"available"`
	Victim             string               `json:"victim"`
	VictimPhysicalDisk string               `json:"victim_physical_disk"`
	SelectedSuspect    string               `json:"selected_suspect"`
	SelectionReason    string               `json:"selection_reason"`
	Candidates         []DiscoveryCandidate `json:"candidates"`
}

type Correlation struct {
	Name         string   `json:"name"`
	Present      bool     `json:"present"`
	Severity     string   `json:"severity"`
	Explanation  string   `json:"explanation"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type ObserveSnapshot struct {
	SchemaVersion        string                     `json:"schema_version"`
	ObservedAtUTC        string                     `json:"observed_at_utc"`
	WindowID             string                     `json:"window_id"`
	Duration             string                     `json:"duration"`
	Interval             string                     `json:"interval"`
	ConfigSource         string                     `json:"config_source"`
	Victim               Target                     `json:"victim"`
	SelectedSuspect      string                     `json:"selected_suspect"`
	SuspectMode          string                     `json:"suspect_mode"`
	HostStatus           *hostmetrics.HostStatus    `json:"host_status"`
	VMStatus             statusview.Report          `json:"vm_status"`
	VictimGuestStatus    *observability.GuestStatus `json:"victim_guest_status"`
	VictimServiceStatus  *servicehealth.Report      `json:"victim_service_status"`
	VictimDBStatus       *observability.DBStatus    `json:"victim_db_status"`
	SuspectGuestStatus   *observability.GuestStatus `json:"suspect_guest_status"`
	SuspectServiceStatus *servicehealth.Report      `json:"suspect_service_status"`
	SuspectDBStatus      *observability.DBStatus    `json:"suspect_db_status"`
	StorageTopology      StorageTopology            `json:"storage_topology"`
	QEMUEvidence         QEMUEvidence               `json:"qemu_evidence"`
	Discovery            DiscoveryEvidence          `json:"discovery"`
	Correlations         []Correlation              `json:"correlations"`
	EvidenceQuality      EvidenceQuality            `json:"evidence_quality"`
	Privacy              observability.PrivacyFlags `json:"privacy"`
	UnavailableSections  []UnavailableSection       `json:"unavailable_sections"`
	Caveats              []string                   `json:"caveats"`
}

// NewUnavailableSnapshot creates a valid privacy-safe artifact when a higher-
// level workflow cannot collect live observation evidence. The failure is
// represented as evidence rather than disguised as measured data.
func NewUnavailableSnapshot(victim, suspect, mode string, duration, interval time.Duration, configSource, reason string, observedAt time.Time) ObserveSnapshot {
	if suspect == "" {
		suspect = "-"
	}
	if mode == "" {
		mode = "victim-only"
	}
	if configSource == "" {
		configSource = "built-in defaults"
	}
	reason = oneLine(reason)
	if reason == "" {
		reason = "observe snapshot evidence unavailable"
	}
	observedAt = observedAt.UTC()
	return ObserveSnapshot{
		SchemaVersion: SchemaVersion, ObservedAtUTC: observedAt.Format(time.RFC3339Nano),
		WindowID: "observe-unavailable-" + observedAt.Format("20060102T150405.000000000Z"),
		Duration: duration.String(), Interval: interval.String(), ConfigSource: configSource,
		Victim: Target{Name: victim}, SelectedSuspect: suspect, SuspectMode: mode,
		VMStatus:            statusview.Report{SchemaVersion: statusview.SchemaVersion, Duration: duration.String(), Interval: interval.String(), VMs: []statusview.VMStatus{}},
		StorageTopology:     StorageTopology{PhysicalDisk: "-", Targets: []StorageTarget{}},
		QEMUEvidence:        QEMUEvidence{VMs: []QEMUVM{}, DominantWriter: "-", DominantWriteSyscallSource: "-", Conclusion: "Observation evidence unavailable."},
		Discovery:           DiscoveryEvidence{Enabled: mode == "discover-suspects", Victim: victim, VictimPhysicalDisk: "-", SelectedSuspect: "-", SelectionReason: reason, Candidates: []DiscoveryCandidate{}},
		Correlations:        []Correlation{},
		EvidenceQuality:     EvidenceQuality{Overall: EvidenceUnavailable, Sections: []SectionQuality{{Section: "observe_snapshot", State: EvidenceError, Source: "unified observation collector", Error: reason}}},
		UnavailableSections: []UnavailableSection{{Section: "observe_snapshot", State: EvidenceError, Reason: reason}},
		Caveats: []string{
			"Application/DB impact evidence unavailable; snapshot can show infrastructure pressure only.",
			"Unified observation evidence unavailable: " + reason,
		},
	}
}
