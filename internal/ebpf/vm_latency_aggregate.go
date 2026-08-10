package ebpf

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

var (
	// ErrVMBlockLatencyNotImplemented is returned by the system source until a
	// BTF-aware typed tracepoint loader is implemented and verifier-tested.
	ErrVMBlockLatencyNotImplemented = errors.New("experimental_not_implemented: typed BTF request-pointer and bio/blkcg eBPF attach is not implemented")
	// ErrVMBlockLatencyPermission is the stable operator-facing permission
	// guidance for this experimental collector.
	ErrVMBlockLatencyPermission = errors.New("permission denied loading or attaching per-VM eBPF block latency programs; try running with sudo")
)

// VMBlockLatencyCollectOptions controls one experimental observation window.
type VMBlockLatencyCollectOptions struct {
	Duration     time.Duration
	Interval     time.Duration
	DeviceFilter string
	ObservedAt   time.Time
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
	unknownOps       uint64
}

type vmDeviceOperationKey struct {
	device    string
	operation string
}

// CollectVMBlockLatencyReport returns a structured experimental status. Until
// the typed BTF loader is complete it never fakes successful attribution.
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
	return CollectVMBlockLatencyReportWithKernelSource(ctx, options, mappings, experimentalVMBlockKernelSource{})
}

// CollectVMBlockLatencyReportWithSource is the fake-event test seam and the
// future integration point for the typed BTF eBPF source.
func CollectVMBlockLatencyReportWithSource(ctx context.Context, options VMBlockLatencyCollectOptions, mappings []VMBlockCgroupMapping, source VMBlockEventSource) VMBlockLatencyReport {
	return CollectVMBlockLatencyReportWithKernelSource(ctx, options, mappings, newEventSourceKernelAdapter(source))
}

// CollectVMBlockLatencyReportWithKernelSource runs one lifecycle-managed
// source. Product code uses the explicitly unavailable experimental source;
// fake sources are used only by tests until a real loader is implemented.
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
	stats, err := runVMBlockKernelSource(ctx, source, options, mappings, aggregator.consume)
	aggregator.recordKernelStats(stats)
	aggregator.finish(err == nil)
	if err != nil {
		status, message := vmBlockCollectorError(err)
		report.Availability.Status = status
		report.Availability.Error = message
		report.UnavailableSections = append(report.UnavailableSections, VMBlockLatencyUnavailableSection{
			Name: "ebpf_attribution", Status: status, Error: message,
		})
		return normalizeVMBlockLatencyReport(report)
	}
	report.Availability = VMBlockLatencyAvailability{Available: true, Status: "available"}
	report.AttributionQuality = attributionQuality(report.Unattributed, report.HostSummary.TotalOps)
	return normalizeVMBlockLatencyReport(report)
}

type vmBlockEventAggregator struct {
	report      *VMBlockLatencyReport
	mappings    []VMBlockCgroupMapping
	cgroupIndex map[uint64]int
	issues      map[uint64]pendingVMBlockIssue
	byVM        map[int]*vmLatencyAccumulator
	hostLatency boundedVMBlockLatencyHistogram
	filter      string
}

func newVMBlockEventAggregator(report *VMBlockLatencyReport, mappings []VMBlockCgroupMapping, deviceFilter string) (*vmBlockEventAggregator, error) {
	index, err := IndexVMCgroupMappings(mappings)
	if err != nil {
		return nil, err
	}
	return &vmBlockEventAggregator{
		report:      report,
		mappings:    mappings,
		cgroupIndex: index,
		issues:      make(map[uint64]pendingVMBlockIssue),
		byVM:        make(map[int]*vmLatencyAccumulator),
		filter:      strings.TrimSpace(deviceFilter),
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
	latencyNS := event.TimestampNS - issue.timestampNS
	accumulator.latency.observe(latencyNS)
	aggregator.hostLatency.observe(latencyNS)
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
	default:
		accumulator.unknownOps++
	}
}

func (aggregator *vmBlockEventAggregator) recordKernelStats(stats VMBlockKernelStats) {
	aggregator.report.Unattributed.DroppedEvents += stats.DroppedEvents
	aggregator.report.Unattributed.RingBufferLost += stats.RingBufferLost
	aggregator.report.Unattributed.MapFull += stats.MapFull
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
		vm.UnknownOps = accumulator.unknownOps
		vm.TotalOps = accumulator.latency.count
		vm.Devices = mapKeys(accumulator.devices)
		vm.LatencyMinMS, vm.LatencyAvgMS, vm.LatencyP50MS, vm.LatencyP95MS, vm.LatencyP99MS, vm.LatencyMaxMS = accumulator.latency.summary()
		vm.PercentilesApproximate = accumulator.latency.count > 0
		vm.Histogram = accumulator.latency.publicBuckets()
		vm.DeviceOperations = deviceOperationSummaries(accumulator.deviceOperations)
		if collectionAvailable {
			vm.AttributionQuality = "experimental_blkcg_correlated"
		} else {
			vm.AttributionQuality = "unavailable_partial_collection"
		}
	}
	host := &aggregator.report.HostSummary
	for _, vm := range aggregator.report.VMs {
		host.ReadOps += vm.ReadOps
		host.WriteOps += vm.WriteOps
		host.FlushOps += vm.FlushOps
		host.UnknownOps += vm.UnknownOps
	}
	host.TotalOps = aggregator.hostLatency.count
	host.LatencyMinMS, host.LatencyAvgMS, host.LatencyP50MS, host.LatencyP95MS, host.LatencyP99MS, host.LatencyMaxMS = aggregator.hostLatency.summary()
	host.PercentilesApproximate = aggregator.hostLatency.count > 0
	host.Histogram = aggregator.hostLatency.publicBuckets()
	unattributed := &aggregator.report.Unattributed
	unattributed.TotalUnattributedOps = unattributed.MissingBio + unattributed.MissingBlkcg + unattributed.UnmappedCgroup + unattributed.LookupMiss + unattributed.UnsupportedRequest + unattributed.StackedDeviceAmbiguous + unattributed.IncompleteAtWindowEnd
	denominator := host.TotalOps + unattributed.TotalUnattributedOps
	if denominator > 0 {
		unattributed.UnattributedPercent = float64(unattributed.TotalUnattributedOps) / float64(denominator) * 100
	}
}

func newVMBlockLatencyReport(options VMBlockLatencyCollectOptions, mappings []VMBlockCgroupMapping) VMBlockLatencyReport {
	observedAt := options.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	report := VMBlockLatencyReport{
		SchemaVersion:      vmBlockLatencySchemaVersion,
		ObservedAtUTC:      observedAt.Format(time.RFC3339Nano),
		Duration:           options.Duration.String(),
		Interval:           options.Interval.String(),
		Mode:               "experimental",
		AttributionMethod:  "request_pointer_correlated+bio_blkcg+cgroup_inode_vm_map",
		AttributionQuality: "unavailable",
		DeviceFilter:       strings.TrimSpace(options.DeviceFilter),
		Availability:       VMBlockLatencyAvailability{Status: "pending"},
		VMs:                make([]VMBlockLatencyVM, 0, len(mappings)),
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
			"experimental attribution; it does not prove exact VM latency or customer impact",
			"request merging, requeues, flush requests, missing bio or blkcg ownership, and stacked devices can reduce attribution quality",
			"kernel BTF layout and privileged eBPF tracepoint access are required",
			"unattributed events must be considered before using per-VM comparisons",
			"requests incomplete at the observation-window boundary are censored requests, not necessarily errors",
			"p50, p95, and p99 latency values are approximate fixed-bucket estimates; min, max, count, and average use exact observed event values",
			"dropped-event, ring-buffer-loss, and map-full counters describe instrumentation loss and are not treated as exact completed request counts",
		},
	}
	for _, mapping := range mappings {
		mappingCaveats := []string{"blkcg ownership is correlated to a userspace libvirt cgroup inode mapping"}
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

func vmBlockCollectorError(err error) (string, string) {
	var verifierError *VMBlockVerifierError
	var capabilityError *VMBlockCapabilityError
	switch {
	case errors.Is(err, ErrVMBlockLatencyNotImplemented):
		return "experimental_not_implemented", ErrVMBlockLatencyNotImplemented.Error()
	case errors.Is(err, ErrVMBlockLatencyPermission), errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return "permission_denied", ErrVMBlockLatencyPermission.Error()
	case errors.Is(err, ErrVMBlockUnsupportedKernel):
		return "unsupported_kernel", err.Error()
	case errors.As(err, &verifierError):
		return VMBlockCapabilityVerifierRejected, verifierError.Error()
	case errors.As(err, &capabilityError):
		return firstNonEmpty(capabilityError.Status, VMBlockCapabilityResolutionError), capabilityError.Error()
	default:
		return "error", fmt.Sprintf("per-VM eBPF block latency unavailable: %v", err)
	}
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
	default:
		return 3
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

func attributionQuality(unattributed VMBlockLatencyUnattributed, attributed uint64) string {
	if attributed == 0 {
		return "no_attributed_events"
	}
	if unattributed.TotalUnattributedOps > 0 || unattributed.DroppedEvents > 0 || unattributed.RingBufferLost > 0 || unattributed.MapFull > 0 {
		return "experimental_partial"
	}
	return "experimental_blkcg_correlated"
}
