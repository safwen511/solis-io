// Package observability defines versioned, collector-independent models for
// future host, guest, service, database, and incident timeline evidence.
//
// This package performs no collection and has no transport, SSH, guest-agent,
// or database dependencies.
package observability

const SchemaVersion = "1"

// EvidenceQuality describes how an observation was obtained or why it should
// be treated cautiously.
type EvidenceQuality string

const (
	EvidenceQualityMeasured    EvidenceQuality = "measured"
	EvidenceQualityDerived     EvidenceQuality = "derived"
	EvidenceQualityUnavailable EvidenceQuality = "unavailable"
	EvidenceQualityStale       EvidenceQuality = "stale"
)

// PrivacyFlags records the categories that a collector did not inspect.
// Solis observability renderers reject models with any field set to true.
type PrivacyFlags struct {
	ProcessArgumentsCollected bool `json:"process_arguments_collected"`
	EnvironmentCollected      bool `json:"environment_collected"`
	GuestFilesCollected       bool `json:"guest_files_collected"`
	QueryTextCollected        bool `json:"query_text_collected"`
	TableDataCollected        bool `json:"table_data_collected"`
	RequestBodyCollected      bool `json:"request_body_collected"`
	ResponseBodyCollected     bool `json:"response_body_collected"`
	SecretsCollected          bool `json:"secrets_collected"`
}

// Availability records whether a source was usable for one observation.
type Availability struct {
	Available bool            `json:"available"`
	Stale     bool            `json:"stale"`
	Source    string          `json:"source"`
	Quality   EvidenceQuality `json:"quality"`
	Error     string          `json:"error"`
}

// VMIdentity identifies one inventory VM without duplicating runtime details.
type VMIdentity struct {
	Name   string `json:"name"`
	Tenant string `json:"tenant"`
	Role   string `json:"role"`
}

// GuestCPUStatus contains guest-visible CPU pressure metadata.
type GuestCPUStatus struct {
	UtilizationPercent float64 `json:"utilization_percent"`
	Load1              float64 `json:"load_1m"`
	Load5              float64 `json:"load_5m"`
	Load15             float64 `json:"load_15m"`
	PSISomePercent     float64 `json:"psi_some_percent"`
	PSIFullPercent     float64 `json:"psi_full_percent"`
}

// GuestMemoryStatus contains guest-visible memory capacity and pressure.
type GuestMemoryStatus struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	SwapUsedBytes  uint64  `json:"swap_used_bytes"`
	PSISomePercent float64 `json:"psi_some_percent"`
	PSIFullPercent float64 `json:"psi_full_percent"`
}

// FilesystemStatus contains capacity metadata only, never file contents.
type FilesystemStatus struct {
	Mountpoint  string  `json:"mountpoint"`
	Filesystem  string  `json:"filesystem"`
	SizeBytes   uint64  `json:"size_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

// NetworkStatus contains counter metadata for one guest interface.
type NetworkStatus struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	RXBytes   uint64 `json:"rx_bytes"`
	TXBytes   uint64 `json:"tx_bytes"`
	RXErrors  uint64 `json:"rx_errors"`
	TXErrors  uint64 `json:"tx_errors"`
}

// ProcessPressure contains sanitized process accounting. Command is the short
// executable name; command-line arguments are intentionally absent.
type ProcessPressure struct {
	PID           int     `json:"pid"`
	Command       string  `json:"command"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
}

// GuestStatus is one versioned guest health snapshot.
type GuestStatus struct {
	SchemaVersion   string             `json:"schema_version"`
	ObservedAtUTC   string             `json:"observed_at_utc"`
	WindowID        string             `json:"window_id"`
	VM              VMIdentity         `json:"vm"`
	Availability    Availability       `json:"availability"`
	CPU             GuestCPUStatus     `json:"cpu"`
	Memory          GuestMemoryStatus  `json:"memory"`
	Filesystems     []FilesystemStatus `json:"filesystems"`
	Network         []NetworkStatus    `json:"network"`
	ProcessPressure []ProcessPressure  `json:"process_pressure"`
	Privacy         PrivacyFlags       `json:"privacy"`
}

// DatabaseCounters contains PostgreSQL statistics counters without table data
// or SQL text.
type DatabaseCounters struct {
	Name         string `json:"name"`
	Connections  int    `json:"connections"`
	XactCommit   uint64 `json:"xact_commit"`
	XactRollback uint64 `json:"xact_rollback"`
	BlocksRead   uint64 `json:"blocks_read"`
	BlocksHit    uint64 `json:"blocks_hit"`
	Deadlocks    uint64 `json:"deadlocks"`
}

// DatabaseActivity summarizes active and waiting sessions without query text.
type DatabaseActivity struct {
	ActiveSessions      int      `json:"active_sessions"`
	WaitingSessions     int      `json:"waiting_sessions"`
	OldestActiveSeconds float64  `json:"oldest_active_seconds"`
	WaitEvents          []string `json:"wait_events"`
}

// StatementStatistics contains numeric pg_stat_statements evidence only.
type StatementStatistics struct {
	QueryID          string  `json:"query_id"`
	Calls            uint64  `json:"calls"`
	TotalExecutionMS float64 `json:"total_execution_ms"`
	MeanExecutionMS  float64 `json:"mean_execution_ms"`
	Rows             int64   `json:"rows"`
}

// DBStatus is one versioned database statistics snapshot.
type DBStatus struct {
	SchemaVersion       string                `json:"schema_version"`
	ObservedAtUTC       string                `json:"observed_at_utc"`
	WindowID            string                `json:"window_id"`
	VM                  VMIdentity            `json:"vm"`
	Engine              string                `json:"engine"`
	Version             string                `json:"version"`
	Availability        Availability          `json:"availability"`
	Databases           []DatabaseCounters    `json:"databases"`
	Activity            DatabaseActivity      `json:"activity"`
	Extensions          []string              `json:"extensions"`
	StatementStatistics []StatementStatistics `json:"statement_statistics"`
	Privacy             PrivacyFlags          `json:"privacy"`
}

// ListeningPort contains service socket metadata only.
type ListeningPort struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

// AppHealthStatus contains the result metadata for an allowlisted health
// endpoint. Request and response bodies are not represented.
type AppHealthStatus struct {
	Name         string       `json:"name"`
	Path         string       `json:"path"`
	Checked      bool         `json:"checked"`
	StatusCode   int          `json:"status_code"`
	LatencyMS    float64      `json:"latency_ms"`
	Availability Availability `json:"availability"`
}

// ServiceStatus is one versioned service metadata snapshot.
type ServiceStatus struct {
	SchemaVersion  string            `json:"schema_version"`
	ObservedAtUTC  string            `json:"observed_at_utc"`
	WindowID       string            `json:"window_id"`
	VM             VMIdentity        `json:"vm"`
	Name           string            `json:"name"`
	SystemdUnit    string            `json:"systemd_unit"`
	ActiveState    string            `json:"active_state"`
	SubState       string            `json:"sub_state"`
	MainPID        int               `json:"main_pid"`
	ListeningPorts []ListeningPort   `json:"listening_ports"`
	HealthChecks   []AppHealthStatus `json:"health_checks"`
	Availability   Availability      `json:"availability"`
	Privacy        PrivacyFlags      `json:"privacy"`
}

// TimelineEvent is one time-aligned numeric observation. Arbitrary payloads
// are intentionally not supported.
type TimelineEvent struct {
	ObservedAtUTC string          `json:"observed_at_utc"`
	OffsetMS      int64           `json:"offset_ms"`
	Source        string          `json:"source"`
	Scope         string          `json:"scope"`
	Metric        string          `json:"metric"`
	Value         float64         `json:"value"`
	Unit          string          `json:"unit"`
	Quality       EvidenceQuality `json:"quality"`
}

// IncidentWindow identifies the common observation interval.
type IncidentWindow struct {
	StartUTC string `json:"start_utc"`
	EndUTC   string `json:"end_utc"`
	Duration string `json:"duration"`
}

// TimelineVerdict records a cautious conclusion and its caveats.
type TimelineVerdict struct {
	Text     string   `json:"text"`
	Severity string   `json:"severity"`
	Caveats  []string `json:"caveats"`
}

// IncidentTimeline is a versioned, correlation-ready evidence timeline.
type IncidentTimeline struct {
	SchemaVersion   string          `json:"schema_version"`
	IncidentID      string          `json:"incident_id"`
	Window          IncidentWindow  `json:"window"`
	Victim          string          `json:"victim"`
	SelectedSuspect string          `json:"selected_suspect"`
	Events          []TimelineEvent `json:"events"`
	Verdict         TimelineVerdict `json:"verdict"`
	EvidenceRefs    []string        `json:"evidence_refs"`
	Privacy         PrivacyFlags    `json:"privacy"`
}
