// Package top builds the read-only live Solis terminal dashboard.
package top

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/hostmetrics"
	statusview "github.com/safwen511/solis-io/internal/status"
)

const (
	AttributionNotRequested = "not_requested"
	AttributionUnavailable  = "unavailable"
)

// Options controls dashboard sampling and refresh behavior.
type Options struct {
	Duration           time.Duration
	Interval           time.Duration
	Every              time.Duration
	UIRefresh          time.Duration
	Iterations         int
	Clear              bool
	Sort               string
	IncludeEBPFLatency bool
	Application        bool
	Color              bool
	// RunWorkflow executes one fixed application workflow after live collection
	// is paused. Its bounded summary is rendered inside the application. A
	// workflow may also return private detail which remains in memory until the
	// operator explicitly saves or discards it.
	RunWorkflow func(context.Context, LaunchRequest) (WorkflowResult, error)
	// SaveWorkflowDetail persists an explicitly requested detailed artifact.
	// The CLI supplies the hardened private atomic writer; the dashboard never
	// invents paths or writes files itself.
	SaveWorkflowDetail func(WorkflowDetail) (string, error)
}

// CollectRequest identifies one bounded dashboard observation window.
type CollectRequest struct {
	Duration           time.Duration
	Interval           time.Duration
	IncludeEBPFLatency bool
}

// Snapshot contains only the reports needed by the dashboard. The renderer
// deliberately excludes cgroup IDs, process metadata, raw diagnostics, and
// other internal collector details.
type Snapshot struct {
	ObservedAtUTC        time.Time
	CompletedAtUTC       time.Time
	Inventory            []InventoryVM
	Status               statusview.Report
	StatusAvailable      bool
	StatusState          string
	Host                 *hostmetrics.HostStatus
	HostUnavailableState string
	EBPFLatencyRequested bool
	EBPFLatency          *ebpf.VMBlockLatencyReport
	EBPFUnavailableState string
}

// InventoryVM is the bounded identity and runtime-state projection used by the
// application. It deliberately excludes process arguments, cgroup identity,
// raw diagnostics, and guest data.
type InventoryVM struct {
	Name      string
	Tenant    string
	Role      string
	State     string
	Network   string
	PlannedIP string
	LeaseIP   string
	MemoryMB  string
	VCPUs     string
	DiskGB    string
	DiskPath  string
}

// View is the deterministic, privacy-safe dashboard projection.
type View struct {
	ObservedAtUTC  time.Time
	CompletedAtUTC time.Time
	Duration       string
	Interval       string
	Storage        []StorageView
	Pressures      statusview.PressureCounts
	StatusState    string
	Host           HostView
	Attribution    AttributionView
	VMs            VMCounts
	Rows           []VMRow
}

// VMCounts summarizes the complete configured inventory, including VMs that
// are not running and therefore cannot have live pressure or eBPF samples.
type VMCounts struct {
	Total      int
	Running    int
	NotRunning int
	Unknown    int
}

// HostView contains a small provider-side host summary. Availability is kept
// per metric so missing procfs/PSI data is never rendered as a measured zero.
type HostView struct {
	Available              bool
	Status                 string
	CPUBusyPercent         float64
	CPUAvailable           bool
	IOWaitPercent          float64
	IOWaitAvailable        bool
	IOPSISomeAvg10         float64
	IOPSIAvailable         bool
	MemoryAvailablePercent float64
	MemoryAvailable        bool
}

// StorageView is one mapped physical device's host diskstats rate projection.
type StorageView struct {
	Device            string
	Available         bool
	ReadMiBPerSecond  float64
	WriteMiBPerSecond float64
	ReadOpsPerSecond  float64
	WriteOpsPerSecond float64
	IOInProgress      uint64
}

// AttributionView summarizes host collection and VM-attribution coverage.
type AttributionView struct {
	Requested              bool
	CollectorAvailable     bool
	AttributionAvailable   bool
	Status                 string
	Quality                string
	HostTotalOps           uint64
	HostP95MS              float64
	AttributedOps          uint64
	AttributedPercent      float64
	UnattributedOps        uint64
	UnattributedPercent    float64
	MatchedVMCount         int
	PercentilesApproximate bool
	Loss                   AttributionLossView
}

// AttributionLossView keeps the most actionable bounded attribution-loss and
// lifecycle counters visible without exposing internal identities.
type AttributionLossView struct {
	MissingBio            uint64
	MissingBlkcg          uint64
	UnmappedCgroup        uint64
	LookupMiss            uint64
	IncompleteAtWindowEnd uint64
	MapFull               uint64
	DroppedEvents         uint64
	RingBufferLost        uint64
}

// VMRow is one compact dashboard row. Availability booleans distinguish a
// measured zero from missing evidence.
type VMRow struct {
	Name                   string
	Tenant                 string
	Role                   string
	State                  string
	Network                string
	PlannedIP              string
	LeaseIP                string
	MemoryMB               string
	VCPUs                  string
	DiskGB                 string
	DiskPath               string
	PhysicalDisk           string
	Running                bool
	Pressure               string
	PressureReason         string
	WriteMiBPerSecond      float64
	MaxWriteMiBPerSecond   float64
	WriteSyscallsPerSecond float64
	WriteAvailable         bool
	ReadOps                uint64
	WriteOps               uint64
	FlushOps               uint64
	DiscardOps             uint64
	UnknownOps             uint64
	AttributedOps          uint64
	LatencyP50MS           float64
	LatencyP95MS           float64
	LatencyP99MS           float64
	LatencyMaxMS           float64
	AttributionAvailable   bool
	AttributionState       string
	MappingQuality         string
	Devices                []string
	DeviceOperations       []DeviceOperationView
}

// DeviceOperationView is a bounded, pointer-free detail row for one selected
// VM, block device, and operation.
type DeviceOperationView struct {
	Device       string
	Operation    string
	Count        uint64
	LatencyP95MS float64
}

// ValidSortField reports whether a dashboard sort key is supported.
func ValidSortField(field string) bool {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "name", "pressure", "write", "ops", "latency":
		return true
	default:
		return false
	}
}

// BuildView converts collector reports into a bounded public terminal view.
func BuildView(snapshot Snapshot, sortField string) (View, error) {
	if !ValidSortField(sortField) {
		return View{}, fmt.Errorf("invalid top sort field %q", sortField)
	}
	view := View{
		ObservedAtUTC:  snapshot.ObservedAtUTC.UTC(),
		CompletedAtUTC: snapshot.CompletedAtUTC.UTC(),
		Duration:       snapshot.Status.Duration,
		Interval:       snapshot.Status.Interval,
		StatusState:    statusEvidenceState(snapshot),
		Attribution: AttributionView{
			Requested: snapshot.EBPFLatencyRequested,
			Status:    AttributionNotRequested,
			Quality:   AttributionUnavailable,
		},
	}
	if view.ObservedAtUTC.IsZero() {
		view.ObservedAtUTC = time.Now().UTC()
	}
	if view.CompletedAtUTC.IsZero() {
		view.CompletedAtUTC = view.ObservedAtUTC
	}

	rows := make(map[string]VMRow, len(snapshot.Inventory)+len(snapshot.Status.VMs))
	storage := make(map[string]struct{})
	for _, vm := range snapshot.Inventory {
		name := strings.TrimSpace(vm.Name)
		if name == "" {
			continue
		}
		state := normalizedVMState(vm.State)
		running := state == "running"
		pressure := "not_running"
		pressureReason := "VM is not running"
		switch state {
		case "running":
			pressure = AttributionUnavailable
			pressureReason = "live QEMU pressure is unavailable"
		case "unknown":
			pressure = AttributionUnavailable
			pressureReason = "libvirt runtime state is unavailable"
		}
		rows[name] = VMRow{
			Name:             displayText(name),
			Tenant:           displayText(vm.Tenant),
			Role:             displayText(vm.Role),
			State:            displayText(state),
			Network:          displayText(vm.Network),
			PlannedIP:        displayText(vm.PlannedIP),
			LeaseIP:          displayText(vm.LeaseIP),
			MemoryMB:         displayText(vm.MemoryMB),
			VCPUs:            displayText(vm.VCPUs),
			DiskGB:           displayText(vm.DiskGB),
			DiskPath:         displayText(vm.DiskPath),
			Running:          running,
			Pressure:         pressure,
			PressureReason:   pressureReason,
			AttributionState: stateForVMState(state),
		}
	}
	for _, vm := range snapshot.Status.VMs {
		name := strings.TrimSpace(vm.Name)
		if name == "" {
			continue
		}
		pressure := strings.ToLower(strings.TrimSpace(vm.Pressure))
		if !vm.IOAvailable {
			pressure = AttributionUnavailable
		}
		row := rows[name]
		row.Name = displayText(name)
		row.Tenant = displayText(vm.Tenant)
		row.Role = displayText(vm.Role)
		row.State = displayText(firstNonEmpty(vm.State, row.State, "running"))
		row.Running = normalizedVMState(row.State) == "running"
		row.Pressure = displayText(pressure)
		row.PressureReason = safePressureReason(vm.Reason, vm.IOAvailable)
		row.WriteMiBPerSecond = vm.AverageWriteMiBPerSecond
		row.MaxWriteMiBPerSecond = vm.MaxWriteMiBPerSecond
		row.WriteSyscallsPerSecond = vm.AverageSyscwPerSecond
		row.WriteAvailable = vm.IOAvailable
		row.PhysicalDisk = displayText(vm.PhysicalDisk)
		row.AttributionState = AttributionNotRequested
		if row.DiskPath == "-" || row.DiskPath == "" {
			row.DiskPath = displayText(vm.Disk)
		}
		rows[name] = row
		device := strings.TrimSpace(vm.PhysicalDisk)
		if device != "" && device != "-" {
			storage[device] = struct{}{}
		}
	}
	for _, row := range rows {
		view.VMs.Total++
		switch normalizedVMState(row.State) {
		case "running":
			view.VMs.Running++
		case "unknown":
			view.VMs.Unknown++
		default:
			view.VMs.NotRunning++
		}
		switch row.Pressure {
		case statusview.PressureHigh:
			view.Pressures.High++
		case statusview.PressureLow:
			view.Pressures.Low++
		case statusview.PressureIdle:
			view.Pressures.Idle++
		}
	}

	if snapshot.EBPFLatencyRequested {
		view.Attribution.Status = firstNonEmpty(snapshot.EBPFUnavailableState, AttributionUnavailable)
		for name, row := range rows {
			if row.Running {
				row.AttributionState = view.Attribution.Status
			}
			rows[name] = row
		}
	}
	if report := snapshot.EBPFLatency; snapshot.EBPFLatencyRequested && report != nil {
		view.Attribution.CollectorAvailable = report.Availability.Available
		view.Attribution.Status = displayText(report.Availability.Status)
		view.Attribution.Quality = displayText(report.AttributionQuality)
		if report.Availability.Available {
			view.Attribution.HostTotalOps = report.HostSummary.TotalOps
			view.Attribution.HostP95MS = report.HostSummary.LatencyP95MS
			view.Attribution.AttributedOps = report.AttributionSummary.AttributedOps
			view.Attribution.AttributedPercent = report.AttributionSummary.AttributedPercent
			view.Attribution.UnattributedOps = report.AttributionSummary.UnattributedOps
			view.Attribution.UnattributedPercent = report.Unattributed.UnattributedPercent
			view.Attribution.MatchedVMCount = report.AttributionSummary.MatchedVMCount
			view.Attribution.PercentilesApproximate = report.HostSummary.PercentilesApproximate
		}
		view.Attribution.AttributionAvailable = report.Availability.Available &&
			report.VMAttributionPreflight.Available && report.VMAttributionPreflight.Status == "enabled" &&
			(report.AttributionQuality == "available" || report.AttributionQuality == "degraded")

		for _, vm := range report.VMs {
			name := strings.TrimSpace(vm.Name)
			if name == "" {
				continue
			}
			row, exists := rows[name]
			if !exists {
				row = VMRow{
					Name:             displayText(name),
					Tenant:           displayText(vm.Tenant),
					Role:             displayText(vm.Role),
					State:            "running",
					Running:          true,
					Pressure:         AttributionUnavailable,
					AttributionState: view.Attribution.Status,
				}
			}
			if view.Attribution.AttributionAvailable {
				row.ReadOps = vm.ReadOps
				row.WriteOps = vm.WriteOps
				row.FlushOps = vm.FlushOps
				row.DiscardOps = vm.DiscardOps
				row.UnknownOps = vm.UnknownOps
				row.AttributedOps = vm.TotalOps
				row.LatencyP50MS = vm.LatencyP50MS
				row.LatencyP95MS = vm.LatencyP95MS
				row.LatencyP99MS = vm.LatencyP99MS
				row.LatencyMaxMS = vm.LatencyMaxMS
				row.AttributionAvailable = true
				row.AttributionState = firstNonEmpty(vm.AttributionQuality, report.AttributionQuality)
				row.MappingQuality = displayText(vm.MappingQuality)
				row.Devices = make([]string, 0, len(vm.Devices))
				for _, device := range vm.Devices {
					row.Devices = append(row.Devices, displayText(device))
				}
				sort.Strings(row.Devices)
				row.DeviceOperations = projectDeviceOperations(vm.DeviceOperations)
			} else {
				row.AttributionState = firstNonEmpty(report.AttributionQuality, report.Availability.Status, AttributionUnavailable)
			}
			rows[name] = row
		}
		view.Attribution.Loss = AttributionLossView{
			MissingBio:            report.Unattributed.MissingBio,
			MissingBlkcg:          report.Unattributed.MissingBlkcg,
			UnmappedCgroup:        report.Unattributed.UnmappedCgroup,
			LookupMiss:            report.Unattributed.LookupMiss,
			IncompleteAtWindowEnd: report.Unattributed.IncompleteAtWindowEnd,
			MapFull:               report.Unattributed.MapFull,
			DroppedEvents:         report.Unattributed.DroppedEvents,
			RingBufferLost:        report.Unattributed.RingBufferLost,
		}
	}

	view.Host = buildHostView(snapshot.Host, snapshot.HostUnavailableState)
	view.Storage = buildStorageViews(storage, snapshot.Host)
	view.Rows = make([]VMRow, 0, len(rows))
	for _, row := range rows {
		view.Rows = append(view.Rows, row)
	}
	sortRows(view.Rows, sortField)
	return view, nil
}

func projectDeviceOperations(operations []ebpf.VMBlockLatencyDeviceOperation) []DeviceOperationView {
	projected := make([]DeviceOperationView, 0, len(operations))
	for _, operation := range operations {
		projected = append(projected, DeviceOperationView{
			Device:       displayText(operation.Device),
			Operation:    displayText(operation.Operation),
			Count:        operation.Count,
			LatencyP95MS: operation.LatencyP95MS,
		})
	}
	sort.Slice(projected, func(i, j int) bool {
		if projected[i].Device != projected[j].Device {
			return projected[i].Device < projected[j].Device
		}
		return projected[i].Operation < projected[j].Operation
	})
	return projected
}

func safePressureReason(reason string, available bool) string {
	if !available {
		return AttributionUnavailable
	}
	switch strings.TrimSpace(reason) {
	case "dominant byte write rate", "high syscall pressure", "low write activity", "idle":
		return strings.TrimSpace(reason)
	default:
		return "available"
	}
}

func normalizedVMState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "running":
		return "running"
	case "shut off", "shutoff", "stopped", "paused", "pmsuspended", "crashed", "blocked":
		return strings.ToLower(strings.TrimSpace(state))
	default:
		return "unknown"
	}
}

func stateForVMState(state string) string {
	switch normalizedVMState(state) {
	case "running":
		return AttributionNotRequested
	case "unknown":
		return AttributionUnavailable
	default:
		return "not_running"
	}
}

func statusEvidenceState(snapshot Snapshot) string {
	if !snapshot.StatusAvailable {
		return normalizedState(snapshot.StatusState, false)
	}
	if len(snapshot.Status.VMs) == 0 {
		return "no_eligible_vms"
	}
	available := 0
	for _, vm := range snapshot.Status.VMs {
		if vm.IOAvailable {
			available++
		}
	}
	switch {
	case available == len(snapshot.Status.VMs):
		return "available"
	case available > 0:
		return "partial"
	default:
		return AttributionUnavailable
	}
}

func buildHostView(report *hostmetrics.HostStatus, unavailableState string) HostView {
	view := HostView{Status: firstNonEmpty(unavailableState, AttributionUnavailable)}
	if report == nil {
		return view
	}
	view.Available = report.Availability.Available
	view.Status = firstNonEmpty(string(report.Availability.Quality), boolState(report.Availability.Available))
	if report.CPU.Availability.Available {
		view.CPUAvailable = true
		view.IOWaitAvailable = true
		view.CPUBusyPercent = report.CPU.TotalBusyPercent
		view.IOWaitPercent = report.CPU.IOWaitPercent
	}
	if report.PSI.IO.Some.Availability.Available {
		view.IOPSIAvailable = true
		view.IOPSISomeAvg10 = report.PSI.IO.Some.Avg10
	}
	if report.Memory.Availability.Available {
		view.MemoryAvailable = true
		view.MemoryAvailablePercent = report.Memory.MemAvailablePercent
	}
	return view
}

func buildStorageViews(devices map[string]struct{}, report *hostmetrics.HostStatus) []StorageView {
	byName := make(map[string]hostmetrics.DiskStatus)
	if report != nil {
		for _, device := range report.Disks.Devices {
			byName[device.Name] = device
		}
	}
	views := make([]StorageView, 0, len(devices))
	for path := range devices {
		view := StorageView{Device: displayText(path)}
		if device, ok := byName[filepath.Base(path)]; ok && device.RateAvailability.Available {
			view.Available = true
			view.ReadMiBPerSecond = sectorsPerSecondToMiB(device.ReadSectorsPerSecond)
			view.WriteMiBPerSecond = sectorsPerSecondToMiB(device.WriteSectorsPerSecond)
			view.ReadOpsPerSecond = device.ReadsPerSecond
			view.WriteOpsPerSecond = device.WritesPerSecond
			view.IOInProgress = device.IOInProgress
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Device < views[j].Device })
	return views
}

func sectorsPerSecondToMiB(sectors float64) float64 {
	return sectors * 512 / (1024 * 1024)
}

func boolState(available bool) string {
	if available {
		return "available"
	}
	return AttributionUnavailable
}

func sortRows(rows []VMRow, field string) {
	sort.SliceStable(rows, func(i, j int) bool {
		left, right := rows[i], rows[j]
		switch strings.ToLower(strings.TrimSpace(field)) {
		case "pressure":
			if pressureRank(left.Pressure) != pressureRank(right.Pressure) {
				return pressureRank(left.Pressure) < pressureRank(right.Pressure)
			}
			// Within the same coarse QEMU pressure class, keep the most
			// consequential measured I/O visible first. This avoids hiding a
			// rate-limited but dominant eBPF source beneath alphabetic peers.
			if left.AttributionAvailable != right.AttributionAvailable {
				return left.AttributionAvailable
			}
			if left.AttributedOps != right.AttributedOps {
				return left.AttributedOps > right.AttributedOps
			}
			if left.WriteAvailable != right.WriteAvailable {
				return left.WriteAvailable
			}
			if left.WriteMiBPerSecond != right.WriteMiBPerSecond {
				return left.WriteMiBPerSecond > right.WriteMiBPerSecond
			}
		case "write":
			if left.WriteAvailable != right.WriteAvailable {
				return left.WriteAvailable
			}
			if left.WriteMiBPerSecond != right.WriteMiBPerSecond {
				return left.WriteMiBPerSecond > right.WriteMiBPerSecond
			}
		case "ops":
			if left.AttributionAvailable != right.AttributionAvailable {
				return left.AttributionAvailable
			}
			if left.AttributedOps != right.AttributedOps {
				return left.AttributedOps > right.AttributedOps
			}
		case "latency":
			if left.AttributionAvailable != right.AttributionAvailable {
				return left.AttributionAvailable
			}
			if left.LatencyP95MS != right.LatencyP95MS {
				return left.LatencyP95MS > right.LatencyP95MS
			}
		}
		return strings.ToLower(left.Name) < strings.ToLower(right.Name)
	})
}

func normalizedState(state string, available bool) string {
	state = strings.TrimSpace(state)
	if state != "" {
		return state
	}
	if available {
		return "available"
	}
	return AttributionUnavailable
}

func displayText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	const maxRunes = 128
	filtered := make([]rune, 0, len(value))
	for _, character := range value {
		if unicode.IsControl(character) {
			filtered = append(filtered, '?')
		} else {
			filtered = append(filtered, character)
		}
		if len(filtered) == maxRunes {
			break
		}
	}
	return string(filtered)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func pressureRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case statusview.PressureHigh:
		return 0
	case statusview.PressureLow:
		return 1
	case statusview.PressureIdle:
		return 2
	default:
		return 3
	}
}
