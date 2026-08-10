package ebpf

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"
)

var (
	// ErrVMBlockLatencyNotImplemented is retained for an explicitly selected
	// deferred kernel-source implementation. The normal Linux runtime uses the
	// Cilium typed-BTF source and never falls back to fabricated evidence.
	ErrVMBlockLatencyNotImplemented = errors.New("experimental_not_implemented: typed BTF kernel source is unavailable")
	// ErrVMBlockLatencyPermission is the stable operator-facing permission
	// guidance for this experimental collector.
	ErrVMBlockLatencyPermission = errors.New("permission denied loading or attaching per-VM eBPF block latency programs")
)

// VMBlockLatencyCollectOptions controls one experimental observation window.
type VMBlockLatencyCollectOptions struct {
	Duration        time.Duration
	Interval        time.Duration
	DeviceFilter    string
	ObservedAt      time.Time
	effectiveUID    func() int
	diagnosticProbe func(string, int, error) VMBlockRuntimeDiagnostics
}

// VMBlockEventSource isolates the privileged eBPF event source from the
// deterministic attribution and formatting logic.
type VMBlockEventSource interface {
	Collect(context.Context, time.Duration, func(VMBlockEvent) error) error
}

type pendingVMBlockIssue struct {
	timestampNS uint64
	cgroupID    uint64
	device      string
	operation   string
	filteredOut bool
}

type vmLatencyAccumulator struct {
	mappingIndex     int
	latency          boundedVMBlockLatencyHistogram
	deviceOperations map[vmDeviceOperationKey]*boundedVMBlockLatencyHistogram
	devices          map[string]bool
	readOps          uint64
	writeOps         uint64
	flushOps         uint64
	discardOps       uint64
	unknownOps       uint64
}

type vmDeviceOperationKey struct {
	device    string
	operation string
}

// CollectVMBlockLatencyReport returns a structured experimental status. The
// typed-BTF source measures host request latency but never fakes VM ownership.
func CollectVMBlockLatencyReport(ctx context.Context, options VMBlockLatencyCollectOptions, mappings []VMBlockCgroupMapping) VMBlockLatencyReport {
	return CollectVMBlockLatencyReportForPlatform(ctx, options, mappings, runtime.GOOS)
}

// CollectVMBlockLatencyReportForPlatform keeps Linux gating independently
// testable without requiring a non-Linux test host.
func CollectVMBlockLatencyReportForPlatform(ctx context.Context, options VMBlockLatencyCollectOptions, mappings []VMBlockCgroupMapping, platform string) VMBlockLatencyReport {
	if platform != "linux" {
		report := newVMBlockLatencyReport(options, mappings)
		report.Availability.Status = "unsupported"
		report.Availability.Error = "per-VM eBPF block latency requires Linux"
		report.UnavailableSections = append(report.UnavailableSections, VMBlockLatencyUnavailableSection{
			Name: "ebpf_attribution", Status: "unsupported", Error: report.Availability.Error,
		})
		return normalizeVMBlockLatencyReport(report)
	}
	return CollectVMBlockLatencyReportWithKernelSource(ctx, options, mappings, runtimeVMBlockKernelSource())
}

// CollectVMBlockLatencyReportWithSource is the fake-event test seam and the
// future integration point for the typed BTF eBPF source.
func CollectVMBlockLatencyReportWithSource(ctx context.Context, options VMBlockLatencyCollectOptions, mappings []VMBlockCgroupMapping, source VMBlockEventSource) VMBlockLatencyReport {
	return CollectVMBlockLatencyReportWithKernelSource(ctx, options, mappings, newEventSourceKernelAdapter(source))
}

// CollectVMBlockLatencyReportWithKernelSource runs one lifecycle-managed
// source. Product code uses the host request-correlation Cilium source; fakes are
// restricted to tests.
func CollectVMBlockLatencyReportWithKernelSource(ctx context.Context, options VMBlockLatencyCollectOptions, mappings []VMBlockCgroupMapping, source VMBlockKernelSource) VMBlockLatencyReport {
	report := newVMBlockLatencyReport(options, mappings)
	if options.Duration <= 0 || options.Interval <= 0 || options.Interval > options.Duration {
		report.Availability.Status = "invalid_options"
		report.Availability.Error = "duration and interval must be positive, and interval must not exceed duration"
		report.UnavailableSections = append(report.UnavailableSections, VMBlockLatencyUnavailableSection{
			Name: "ebpf_attribution", Status: "invalid_options", Error: report.Availability.Error,
		})
		return normalizeVMBlockLatencyReport(report)
	}
	aggregator, err := newVMBlockEventAggregator(&report, mappings, options.DeviceFilter)
	if err != nil {
		report.Availability.Status = "mapping_error"
		report.Availability.Error = err.Error()
		report.UnavailableSections = append(report.UnavailableSections, VMBlockLatencyUnavailableSection{
			Name: "cgroup_mapping", Status: "error", Error: err.Error(),
		})
		return normalizeVMBlockLatencyReport(report)
	}
	stats, preflight, err := runVMBlockKernelSource(ctx, source, options, mappings, aggregator.consume)
	report.VMAttributionPreflight = vmBlockAttributionPreflight(preflight.Capabilities)
	if report.VMAttributionPreflight.Status == "missing_fields" {
		report.UnavailableSections = append(report.UnavailableSections, VMBlockLatencyUnavailableSection{
			Name: "vm_attribution_preflight", Status: "missing_fields",
			Error: "kernel BTF ownership fields unavailable: " + strings.Join(report.VMAttributionPreflight.MissingFields, ", "),
		})
	}
	aggregator.recordKernelStats(stats)
	aggregator.finish(err == nil && stats.AttributionAvailable)
	if err != nil {
		euid := vmBlockEffectiveUID(options)
		status, message := vmBlockCollectorError(err, euid)
		report.Availability.Status = status
		report.Availability.Error = message
		report.Diagnostics = vmBlockDiagnostics(options, vmBlockErrorStage(err), euid, err)
		report.UnavailableSections = append(report.UnavailableSections, VMBlockLatencyUnavailableSection{
			Name: "ebpf_attribution", Status: status, Error: message,
		})
		if cleanup := vmBlockCleanupWarning(err); cleanup != "" {
			report.UnavailableSections = append(report.UnavailableSections, VMBlockLatencyUnavailableSection{
				Name: "ebpf_cleanup", Status: "cleanup_failed", Error: cleanup,
			})
		}
		return normalizeVMBlockLatencyReport(report)
	}
	report.Availability = VMBlockLatencyAvailability{Available: true, Status: "available"}
	if stats.AttributionAvailable {
		report.AttributionQuality = runtimeVMBlockAttributionQuality(report.AttributionSummary)
		for index := range report.VMs {
			if report.VMs[index].TotalOps > 0 {
				report.VMs[index].AttributionQuality = report.AttributionQuality
			} else {
				report.VMs[index].AttributionQuality = "no_attributed_events"
			}
		}
		if stats.CollectionMode == vmBlockVMAttributionCollectionMode {
			report.VMAttributionPreflight.Available = true
			report.VMAttributionPreflight.Status = "enabled"
			report.VMAttributionPreflight.MissingFields = []string{}
			report.VMAttributionPreflight.Caveats = vmBlockAttributionEnabledCaveats()
		}
	} else {
		report.AttributionQuality = "unavailable"
	}
	return normalizeVMBlockLatencyReport(report)
}

type vmBlockEventAggregator struct {
	report               *VMBlockLatencyReport
	mappings             []VMBlockCgroupMapping
	cgroupIndex          map[uint64]int
	issues               map[uint64]pendingVMBlockIssue
	byVM                 map[int]*vmLatencyAccumulator
	hostLatency          boundedVMBlockLatencyHistogram
	kernelHostOperations VMBlockKernelLatency
	hostDeviceOperations map[vmDeviceOperationKey]*boundedVMBlockLatencyHistogram
	filter               string
}

func newVMBlockEventAggregator(report *VMBlockLatencyReport, mappings []VMBlockCgroupMapping, deviceFilter string) (*vmBlockEventAggregator, error) {
	index, err := IndexVMCgroupMappings(mappings)
	if err != nil {
		return nil, err
	}
	return &vmBlockEventAggregator{
		report:               report,
		mappings:             mappings,
		cgroupIndex:          index,
		issues:               make(map[uint64]pendingVMBlockIssue),
		byVM:                 make(map[int]*vmLatencyAccumulator),
		hostDeviceOperations: make(map[vmDeviceOperationKey]*boundedVMBlockLatencyHistogram),
		filter:               strings.TrimSpace(deviceFilter),
	}, nil
}

func (aggregator *vmBlockEventAggregator) consume(event VMBlockEvent) error {
	switch strings.ToLower(strings.TrimSpace(event.Kind)) {
	case "issue":
		aggregator.issue(event)
	case "complete":
		aggregator.complete(event)
	default:
		aggregator.report.Unattributed.UnsupportedRequest++
	}
	return nil
}

func (aggregator *vmBlockEventAggregator) issue(event VMBlockEvent) {
	unattributed := &aggregator.report.Unattributed
	if event.UnsupportedRequest || event.RequestPointer == 0 || event.TimestampNS == 0 {
		unattributed.UnsupportedRequest++
		return
	}
	if aggregator.filter != "" && strings.TrimSpace(event.Device) != aggregator.filter {
		aggregator.issues[event.RequestPointer] = pendingVMBlockIssue{filteredOut: true}
		return
	}
	if event.MissingBio {
		unattributed.MissingBio++
		return
	}
	if event.MissingBlkcg || event.CgroupID == 0 {
		unattributed.MissingBlkcg++
		return
	}
	if event.StackedDeviceAmbiguous {
		unattributed.StackedDeviceAmbiguous++
		return
	}
	operation := normalizeBlockOperation(event.Operation)
	if operation == "" {
		unattributed.UnsupportedRequest++
		return
	}
	if _, exists := aggregator.issues[event.RequestPointer]; exists {
		if event.RequeueOrReissue {
			unattributed.RequeueOrReissue++
		} else {
			unattributed.DuplicateIssue++
		}
	}
	aggregator.issues[event.RequestPointer] = pendingVMBlockIssue{
		timestampNS: event.TimestampNS,
		cgroupID:    event.CgroupID,
		device:      strings.TrimSpace(event.Device),
		operation:   operation,
	}
}

func (aggregator *vmBlockEventAggregator) complete(event VMBlockEvent) {
	unattributed := &aggregator.report.Unattributed
	issue, ok := aggregator.issues[event.RequestPointer]
	if !ok {
		unattributed.LookupMiss++
		return
	}
	delete(aggregator.issues, event.RequestPointer)
	if issue.filteredOut {
		return
	}
	if event.TimestampNS < issue.timestampNS {
		unattributed.UnsupportedRequest++
		return
	}
	latencyNS := event.TimestampNS - issue.timestampNS
	aggregator.hostLatency.observe(latencyNS)
	mappingIndex, ok := aggregator.cgroupIndex[issue.cgroupID]
	if !ok {
		unattributed.UnmappedCgroup++
		return
	}
	accumulator := aggregator.byVM[mappingIndex]
	if accumulator == nil {
		accumulator = &vmLatencyAccumulator{
			mappingIndex: mappingIndex, devices: make(map[string]bool),
			deviceOperations: make(map[vmDeviceOperationKey]*boundedVMBlockLatencyHistogram),
		}
		aggregator.byVM[mappingIndex] = accumulator
	}
	accumulator.latency.observe(latencyNS)
	if issue.device != "" {
		accumulator.devices[issue.device] = true
	}
	device := firstNonEmpty(issue.device, "-")
	key := vmDeviceOperationKey{device: device, operation: issue.operation}
	operationHistogram := accumulator.deviceOperations[key]
	if operationHistogram == nil {
		operationHistogram = &boundedVMBlockLatencyHistogram{}
		accumulator.deviceOperations[key] = operationHistogram
	}
	operationHistogram.observe(latencyNS)
	switch issue.operation {
	case "read":
		accumulator.readOps++
	case "write":
		accumulator.writeOps++
	case "flush":
		accumulator.flushOps++
	case "discard":
		accumulator.discardOps++
	default:
		accumulator.unknownOps++
	}
}

func (aggregator *vmBlockEventAggregator) recordKernelStats(stats VMBlockKernelStats) {
	if stats.CollectionMode != "" {
		aggregator.report.CollectionMode = stats.CollectionMode
	}
	if stats.AttributionMethod != "" {
		aggregator.report.AttributionMethod = stats.AttributionMethod
	}
	aggregator.report.KernelCounters = stats.Counters
	aggregator.hostLatency.mergeKernel(stats.HostLatency)
	aggregator.kernelHostOperations = stats.HostLatency
	for _, operation := range stats.HostDeviceOperations {
		key := vmDeviceOperationKey{
			device:    fmt.Sprintf("%d:%d", operation.Major, operation.Minor),
			operation: normalizeBlockOperation(operation.Operation),
		}
		histogram := aggregator.hostDeviceOperations[key]
		if histogram == nil {
			histogram = &boundedVMBlockLatencyHistogram{}
			aggregator.hostDeviceOperations[key] = histogram
		}
		histogram.mergeKernel(operation.Latency)
	}
	for _, operation := range stats.CgroupDeviceOperations {
		aggregator.recordKernelCgroupOperation(operation)
	}
	aggregator.report.Unattributed.DroppedEvents += stats.DroppedEvents
	aggregator.report.Unattributed.RingBufferLost += stats.RingBufferLost
	aggregator.report.Unattributed.LookupMiss = saturatingAdd(aggregator.report.Unattributed.LookupMiss, stats.Counters.LookupMiss)
	aggregator.report.Unattributed.DuplicateIssue = saturatingAdd(aggregator.report.Unattributed.DuplicateIssue, stats.Counters.DuplicateIssue)
	aggregator.report.Unattributed.IncompleteAtWindowEnd = saturatingAdd(aggregator.report.Unattributed.IncompleteAtWindowEnd, stats.Counters.IncompleteAtWindowEnd)
	aggregator.report.Unattributed.MetadataUnavailable = saturatingAdd(aggregator.report.Unattributed.MetadataUnavailable, stats.Counters.MetadataUnavailable)
	aggregator.report.Unattributed.DeviceUnavailable = saturatingAdd(aggregator.report.Unattributed.DeviceUnavailable, stats.Counters.DeviceUnavailable)
	aggregator.report.Unattributed.OperationUnknown = saturatingAdd(aggregator.report.Unattributed.OperationUnknown, stats.Counters.OperationUnknown)
	aggregator.report.Unattributed.MissingBio = saturatingAdd(aggregator.report.Unattributed.MissingBio, stats.Counters.MissingBio)
	aggregator.report.Unattributed.MissingBlkcg = saturatingAdd(aggregator.report.Unattributed.MissingBlkcg, stats.Counters.MissingBlkcg)
	kernelMapFull := stats.Counters.MapFull
	if stats.MapFull > kernelMapFull {
		kernelMapFull = stats.MapFull
	}
	aggregator.report.Unattributed.MapFull = saturatingAdd(aggregator.report.Unattributed.MapFull, kernelMapFull)
}

func (aggregator *vmBlockEventAggregator) recordKernelCgroupOperation(operation VMBlockKernelCgroupDeviceOperation) {
	count := operation.Latency.Count
	if count == 0 {
		return
	}
	mappingIndex, ok := aggregator.cgroupIndex[operation.CgroupID]
	if !ok {
		aggregator.report.Unattributed.UnmappedCgroup = saturatingAdd(aggregator.report.Unattributed.UnmappedCgroup, count)
		return
	}
	accumulator := aggregator.byVM[mappingIndex]
	if accumulator == nil {
		accumulator = &vmLatencyAccumulator{
			mappingIndex: mappingIndex, devices: make(map[string]bool),
			deviceOperations: make(map[vmDeviceOperationKey]*boundedVMBlockLatencyHistogram),
		}
		aggregator.byVM[mappingIndex] = accumulator
	}
	device := fmt.Sprintf("%d:%d", operation.Major, operation.Minor)
	operationName := normalizeBlockOperation(operation.Operation)
	accumulator.latency.mergeKernel(operation.Latency)
	accumulator.devices[device] = true
	key := vmDeviceOperationKey{device: device, operation: operationName}
	histogram := accumulator.deviceOperations[key]
	if histogram == nil {
		histogram = &boundedVMBlockLatencyHistogram{}
		accumulator.deviceOperations[key] = histogram
	}
	histogram.mergeKernel(operation.Latency)
	switch operationName {
	case "read":
		accumulator.readOps = saturatingAdd(accumulator.readOps, count)
	case "write":
		accumulator.writeOps = saturatingAdd(accumulator.writeOps, count)
	case "flush":
		accumulator.flushOps = saturatingAdd(accumulator.flushOps, count)
	case "discard":
		accumulator.discardOps = saturatingAdd(accumulator.discardOps, count)
	default:
		accumulator.unknownOps = saturatingAdd(accumulator.unknownOps, count)
	}
}

func (aggregator *vmBlockEventAggregator) finish(collectionAvailable bool) {
	for _, issue := range aggregator.issues {
		if !issue.filteredOut {
			aggregator.report.Unattributed.IncompleteAtWindowEnd++
		}
	}
	for index := range aggregator.report.VMs {
		accumulator := aggregator.byVM[index]
		if accumulator == nil {
			if collectionAvailable {
				aggregator.report.VMs[index].AttributionQuality = "no_attributed_events"
			} else {
				aggregator.report.VMs[index].AttributionQuality = "unavailable"
			}
			continue
		}
		vm := &aggregator.report.VMs[index]
		vm.ReadOps = accumulator.readOps
		vm.WriteOps = accumulator.writeOps
		vm.FlushOps = accumulator.flushOps
		vm.DiscardOps = accumulator.discardOps
		vm.UnknownOps = accumulator.unknownOps
		vm.TotalOps = accumulator.latency.count
		vm.Devices = mapKeys(accumulator.devices)
		vm.LatencyMinMS, vm.LatencyAvgMS, vm.LatencyP50MS, vm.LatencyP95MS, vm.LatencyP99MS, vm.LatencyMaxMS = accumulator.latency.summary()
		vm.PercentilesApproximate = accumulator.latency.count > 0
		vm.Histogram = accumulator.latency.publicBuckets()
		vm.DeviceOperations = deviceOperationSummaries(accumulator.deviceOperations)
		if !collectionAvailable {
			vm.AttributionQuality = "unavailable_partial_collection"
		}
	}
	host := &aggregator.report.HostSummary
	var attributedOperations uint64
	for _, vm := range aggregator.report.VMs {
		host.ReadOps += vm.ReadOps
		host.WriteOps += vm.WriteOps
		host.FlushOps += vm.FlushOps
		host.DiscardOps += vm.DiscardOps
		host.UnknownOps += vm.UnknownOps
		attributedOperations = saturatingAdd(attributedOperations, vm.TotalOps)
	}
	kernelOperationTotal := aggregator.kernelHostOperations.ReadOps + aggregator.kernelHostOperations.WriteOps + aggregator.kernelHostOperations.FlushOps + aggregator.kernelHostOperations.DiscardOps + aggregator.kernelHostOperations.UnknownOps
	if kernelOperationTotal > 0 {
		host.ReadOps = aggregator.kernelHostOperations.ReadOps
		host.WriteOps = aggregator.kernelHostOperations.WriteOps
		host.FlushOps = aggregator.kernelHostOperations.FlushOps
		host.DiscardOps = aggregator.kernelHostOperations.DiscardOps
		host.UnknownOps = aggregator.kernelHostOperations.UnknownOps
	}
	if aggregator.hostLatency.count > attributedOperations {
		if kernelOperationTotal == 0 {
			host.UnknownOps = saturatingAdd(host.UnknownOps, aggregator.hostLatency.count-attributedOperations)
		}
	}
	host.TotalOps = aggregator.hostLatency.count
	host.LatencyMinMS, host.LatencyAvgMS, host.LatencyP50MS, host.LatencyP95MS, host.LatencyP99MS, host.LatencyMaxMS = aggregator.hostLatency.summary()
	host.PercentilesApproximate = aggregator.hostLatency.count > 0
	host.Histogram = aggregator.hostLatency.publicBuckets()
	host.DeviceOperations = deviceOperationSummaries(aggregator.hostDeviceOperations)
	unattributed := &aggregator.report.Unattributed
	if aggregator.report.CollectionMode == vmBlockVMAttributionCollectionMode {
		measuredUnattributed := uint64(0)
		if host.TotalOps > attributedOperations {
			measuredUnattributed = host.TotalOps - attributedOperations
		}
		unattributed.TotalUnattributedOps = saturatingAdd(measuredUnattributed, saturatingAdd(unattributed.LookupMiss, unattributed.IncompleteAtWindowEnd))
	} else {
		unattributed.TotalUnattributedOps = unattributed.MissingBio + unattributed.MissingBlkcg + unattributed.UnmappedCgroup + unattributed.LookupMiss + unattributed.UnsupportedRequest + unattributed.StackedDeviceAmbiguous + unattributed.IncompleteAtWindowEnd + unattributed.MapFull
	}
	denominator := attributedOperations + unattributed.TotalUnattributedOps
	if denominator > 0 {
		unattributed.UnattributedPercent = float64(unattributed.TotalUnattributedOps) / float64(denominator) * 100
	}
	matchedVMs := 0
	for _, vm := range aggregator.report.VMs {
		if vm.TotalOps > 0 {
			matchedVMs++
		}
	}
	aggregator.report.AttributionSummary = VMBlockAttributionSummary{
		AttributedOps: attributedOperations, UnattributedOps: unattributed.TotalUnattributedOps,
		MatchedVMCount: matchedVMs,
	}
	if denominator > 0 {
		aggregator.report.AttributionSummary.AttributedPercent = float64(attributedOperations) / float64(denominator) * 100
	}
}

func newVMBlockLatencyReport(options VMBlockLatencyCollectOptions, mappings []VMBlockCgroupMapping) VMBlockLatencyReport {
	observedAt := options.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	report := VMBlockLatencyReport{
		SchemaVersion:          vmBlockLatencySchemaVersion,
		ObservedAtUTC:          observedAt.Format(time.RFC3339Nano),
		Duration:               options.Duration.String(),
		Interval:               options.Interval.String(),
		Mode:                   "experimental",
		CollectionMode:         vmBlockHostLatencyCollectionMode,
		AttributionMethod:      vmBlockHostAttributionMethod,
		AttributionQuality:     "unavailable",
		DeviceFilter:           strings.TrimSpace(options.DeviceFilter),
		Availability:           VMBlockLatencyAvailability{Status: "pending"},
		VMAttributionPreflight: vmBlockAttributionPreflight(VMBlockBTFCapabilityReport{}),
		VMs:                    make([]VMBlockLatencyVM, 0, len(mappings)),
		Validation: VMBlockLatencyValidation{
			CgroupIOStat: []CgroupIOStatDelta{}, VirshDomstats: []VirshBlockDelta{}, QEMUPressure: []QEMUPressureSignal{},
			Caveats: []string{
				"cgroup io.stat provides bytes and operation counters, not latency",
				"virsh domstats reports virtual-disk counters and timing, not host physical-device latency histograms",
				"QEMU process accounting is pressure correlation only",
			},
		},
		UnavailableSections: []VMBlockLatencyUnavailableSection{
			{Name: "cgroup_io_stat_validation", Status: "not_collected", Error: "runtime validation sampling is deferred with the typed BTF collector"},
			{Name: "qemu_pressure_validation", Status: "not_collected", Error: "runtime validation sampling is deferred with the typed BTF collector"},
			{Name: "virsh_domstats_validation", Status: "not_collected", Error: "runtime validation sampling is deferred with the typed BTF collector"},
		},
		Caveats: []string{
			"experimental collection; it does not prove exact VM latency or customer impact",
			"typed-BTF request correlation attributes only complete blkcg cgroup IDs that exactly match validated libvirt VM cgroup IDs",
			"opaque request identities are used only as bounded in-kernel correlation keys and are never emitted in report output",
			"host request-correlation programs use CO-RE to read request operation flags, block-device identity, and the bio/blkcg/cgroup ownership identity path",
			"request merging, requeues, flush requests, missing bio or blkcg ownership, and stacked devices can reduce attribution quality",
			"kernel BTF layout and privileged eBPF tracepoint access are required",
			"unattributed events must be considered before using per-VM comparisons",
			"requests incomplete at the observation-window boundary are censored requests, not necessarily errors",
			"p50, p95, and p99 latency values are approximate fixed-bucket estimates; min, max, count, and average use exact observed event values",
			"dropped-event, ring-buffer-loss, and map-full counters describe instrumentation loss and are not treated as exact completed request counts",
		},
	}
	for _, mapping := range mappings {
		mappingCaveats := []string{"latency is attributed only when the blkcg kernfs cgroup ID exactly matches this validated libvirt cgroup mapping"}
		if mapping.MappingQuality != "cgroup_v2_inode_tree" {
			mappingCaveats = append(mappingCaveats, "cgroup mapping is unavailable or partial: "+mapping.MappingQuality)
			report.UnavailableSections = append(report.UnavailableSections, VMBlockLatencyUnavailableSection{
				Name: "cgroup_mapping:" + mapping.Name, Status: mappingAvailabilityStatus(mapping.MappingQuality), Error: "cgroup mapping quality: " + mapping.MappingQuality,
			})
		}
		report.VMs = append(report.VMs, VMBlockLatencyVM{
			Name: mapping.Name, Tenant: mapping.Tenant, Role: mapping.Role, QEMUPID: mapping.QEMUPID,
			CgroupPath: mapping.PrimaryPath, CgroupID: mapping.PrimaryID, Disk: mapping.Disk,
			Devices: []string{}, Histogram: emptyVMBlockLatencyBuckets(), DeviceOperations: []VMBlockLatencyDeviceOperation{},
			MappingQuality: mapping.MappingQuality, AttributionQuality: "unavailable",
			Caveats: mappingCaveats,
		})
	}
	return report
}

func mappingAvailabilityStatus(quality string) string {
	switch quality {
	case "cgroup_v2_inode_partial":
		return "partial"
	default:
		return "unavailable"
	}
}

func vmBlockCollectorError(err error, euid int) (string, string) {
	var verifierError *VMBlockVerifierError
	var capabilityError *VMBlockCapabilityError
	message := boundVMBlockDiagnostic(err.Error(), maxVMBlockVerifierLogBytes)
	stageError := primaryVMBlockStageError(err)
	switch {
	case errors.Is(err, ErrVMBlockLatencyNotImplemented):
		return "experimental_not_implemented", message
	case errors.As(err, &verifierError):
		return VMBlockCapabilityVerifierRejected, message
	case isPermissionError(err):
		return "permission_denied", permissionDeniedMessage(euid, err)
	case errors.Is(err, ErrVMBlockObjectUnavailable):
		return "object_unavailable", message
	case errors.Is(err, ErrVMBlockObjectInvalid):
		return "object_invalid", message
	case errors.Is(err, ErrVMBlockBTFMissing):
		return VMBlockCapabilityBTFMissing, message
	case errors.Is(err, ErrVMBlockUnsupportedEndianness):
		return "unsupported_endianness", message
	case errors.Is(err, ErrVMBlockUnsupportedKernel):
		return "unsupported_kernel", message
	case errors.As(err, &capabilityError):
		return firstNonEmpty(capabilityError.Status, VMBlockCapabilityResolutionError), message
	case stageError != nil:
		return firstNonEmpty(stageError.Status, "error"), message
	default:
		return "error", boundVMBlockDiagnostic(fmt.Sprintf("per-VM eBPF block latency unavailable: %v", err), maxVMBlockVerifierLogBytes)
	}
}

func vmBlockEffectiveUID(options VMBlockLatencyCollectOptions) int {
	if options.effectiveUID != nil {
		return options.effectiveUID()
	}
	return defaultVMBlockDiagnosticConfig().GetEUID()
}

func vmBlockDiagnostics(options VMBlockLatencyCollectOptions, stage string, euid int, err error) VMBlockRuntimeDiagnostics {
	if options.diagnosticProbe != nil {
		diagnostics := options.diagnosticProbe(stage, euid, err)
		diagnostics.Stage = firstNonEmpty(strings.TrimSpace(diagnostics.Stage), firstNonEmpty(stage, "unknown"))
		diagnostics.EUID = euid
		diagnostics.RawError = boundedError(err)
		applyVMBlockMapLayoutDiagnostics(&diagnostics, err)
		return diagnostics
	}
	config := defaultVMBlockDiagnosticConfig()
	config.GetEUID = func() int { return euid }
	return collectVMBlockRuntimeDiagnostics(config, stage, err)
}

func vmBlockErrorStage(err error) string {
	if stage := primaryVMBlockStageError(err); stage != nil {
		return firstNonEmpty(strings.TrimSpace(stage.Stage), "unknown")
	}
	var verifierError *VMBlockVerifierError
	if errors.As(err, &verifierError) {
		return "object_load"
	}
	var capabilityError *VMBlockCapabilityError
	if errors.As(err, &capabilityError) {
		return "preflight"
	}
	if isPermissionError(err) {
		return "preflight"
	}
	return "unknown"
}

func primaryVMBlockStageError(err error) *VMBlockKernelStageError {
	stages := vmBlockStageErrors(err)
	for _, stage := range stages {
		if stage.Status != "cleanup_failed" {
			return stage
		}
	}
	if len(stages) > 0 {
		return stages[0]
	}
	return nil
}

func vmBlockStageErrors(err error) []*VMBlockKernelStageError {
	var stages []*VMBlockKernelStageError
	var visit func(error)
	visit = func(current error) {
		if current == nil {
			return
		}
		if stage, ok := current.(*VMBlockKernelStageError); ok {
			stages = append(stages, stage)
			return
		}
		if joined, ok := current.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				visit(child)
			}
			return
		}
		if wrapped, ok := current.(interface{ Unwrap() error }); ok {
			visit(wrapped.Unwrap())
		}
	}
	visit(err)
	return stages
}

func vmBlockCleanupWarning(err error) string {
	values := make([]string, 0)
	for _, stage := range vmBlockStageErrors(err) {
		if stage.Status == "cleanup_failed" {
			values = append(values, stage.Error())
		}
	}
	values = sortedUniqueStrings(values)
	if len(values) == 0 {
		return ""
	}
	return boundVMBlockDiagnostic(strings.Join(values, "; "), maxVMBlockVerifierLogBytes)
}

func normalizeBlockOperation(operation string) string {
	operation = strings.ToLower(strings.TrimSpace(operation))
	switch operation {
	case "read", "r":
		return "read"
	case "write", "w":
		return "write"
	case "flush", "f":
		return "flush"
	case "discard", "d":
		return "discard"
	default:
		return "unknown"
	}
}

func deviceOperationSummaries(values map[vmDeviceOperationKey]*boundedVMBlockLatencyHistogram) []VMBlockLatencyDeviceOperation {
	keys := make([]vmDeviceOperationKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].device != keys[j].device {
			return keys[i].device < keys[j].device
		}
		return blockOperationOrder(keys[i].operation) < blockOperationOrder(keys[j].operation)
	})
	result := make([]VMBlockLatencyDeviceOperation, 0, len(keys))
	for _, key := range keys {
		result = append(result, operationSummary(key.device, key.operation, *values[key]))
	}
	return result
}

func blockOperationOrder(operation string) int {
	switch operation {
	case "read":
		return 0
	case "write":
		return 1
	case "flush":
		return 2
	case "discard":
		return 3
	default:
		return 4
	}
}

func emptyVMBlockLatencyBuckets() []VMBlockLatencyHistogramBucket {
	return (boundedVMBlockLatencyHistogram{}).publicBuckets()
}

func mapKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func runtimeVMBlockAttributionQuality(summary VMBlockAttributionSummary) string {
	if summary.AttributedOps == 0 || summary.MatchedVMCount == 0 {
		return "unavailable"
	}
	denominator := summary.AttributedOps + summary.UnattributedOps
	if denominator == 0 {
		return "unavailable"
	}
	unattributedPercent := float64(summary.UnattributedOps) / float64(denominator) * 100
	if unattributedPercent <= 5 {
		return "available"
	}
	if unattributedPercent <= 25 {
		return "degraded"
	}
	return "unavailable"
}
