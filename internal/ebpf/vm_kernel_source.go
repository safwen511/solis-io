package ebpf

import (
	"context"
	"errors"
	"strings"
	"time"
)

const maxVMBlockVerifierLogBytes = 4096

var (
	// ErrVMBlockUnsupportedKernel identifies a kernel that cannot support the
	// future typed-BTF collector.
	ErrVMBlockUnsupportedKernel = errors.New("unsupported kernel for typed-BTF per-VM block latency")
)

// VMBlockKernelPreflight is the loader's non-attaching capability result.
type VMBlockKernelPreflight struct {
	Available    bool                       `json:"available"`
	Status       string                     `json:"status"`
	Error        string                     `json:"error"`
	Capabilities VMBlockBTFCapabilityReport `json:"capabilities"`
}

// VMBlockKernelStats contains bounded loss counters reported by a kernel
// source. These are instrumentation-quality signals, not fabricated I/O ops.
type VMBlockKernelStats struct {
	CollectionMode       string                         `json:"collection_mode"`
	AttributionMethod    string                         `json:"attribution_method"`
	AttributionAvailable bool                           `json:"attribution_available"`
	Counters             VMBlockKernelCounters          `json:"counters"`
	HostLatency          VMBlockKernelLatency           `json:"host_latency"`
	HostDeviceOperations []VMBlockKernelDeviceOperation `json:"host_device_operations"`
	DroppedEvents        uint64                         `json:"dropped_events"`
	RingBufferLost       uint64                         `json:"ring_buffer_lost"`
	MapFull              uint64                         `json:"map_full"`
}

// VMBlockKernelLatency is a bounded host-level aggregate read from kernel
// maps. It contains exact count/total/min/max values and fixed histogram
// buckets, but no request keys or per-VM ownership.
type VMBlockKernelLatency struct {
	Count      uint64                                   `json:"count"`
	TotalNS    uint64                                   `json:"total_ns"`
	MinNS      uint64                                   `json:"min_ns"`
	MaxNS      uint64                                   `json:"max_ns"`
	Buckets    [len(vmBlockLatencyBucketUpperNS)]uint64 `json:"buckets"`
	ReadOps    uint64                                   `json:"read_ops"`
	WriteOps   uint64                                   `json:"write_ops"`
	FlushOps   uint64                                   `json:"flush_ops"`
	DiscardOps uint64                                   `json:"discard_ops"`
	UnknownOps uint64                                   `json:"unknown_ops"`
}

// VMBlockKernelDeviceOperation is one sanitized kernel-map aggregate. Device
// identity is major:minor; it contains no request or kernel addresses.
type VMBlockKernelDeviceOperation struct {
	Major     uint32               `json:"major"`
	Minor     uint32               `json:"minor"`
	Operation string               `json:"operation"`
	Latency   VMBlockKernelLatency `json:"latency"`
}

// VMBlockKernelSource is the lifecycle boundary for the future privileged
// loader. Prepare must not attach; Start performs attachment on a prepared
// session so callers can always Close a partially started session.
type VMBlockKernelSource interface {
	Preflight(context.Context) (VMBlockKernelPreflight, error)
	Prepare(context.Context, VMBlockLatencyCollectOptions, []VMBlockCgroupMapping) (VMBlockKernelSession, error)
}

// VMBlockKernelSession is one prepared collection lifecycle. Implementations
// must make Stop and Close idempotent and release partial attachments/maps.
type VMBlockKernelSession interface {
	Start(context.Context) error
	Collect(context.Context, time.Duration, func(VMBlockEvent) error) error
	Stats() VMBlockKernelStats
	Stop() error
	Close() error
}

// VMBlockVerifierError preserves a bounded verifier log for a future loader.
// The bound prevents untrusted kernel diagnostics from expanding output
// without limit.
type VMBlockVerifierError struct {
	Operation string
	Log       string
	Err       error
}

func NewVMBlockVerifierError(operation, verifierLog string, err error) *VMBlockVerifierError {
	return &VMBlockVerifierError{
		Operation: strings.TrimSpace(operation),
		Log:       boundVMBlockDiagnostic(verifierLog, maxVMBlockVerifierLogBytes),
		Err:       err,
	}
}

func (err *VMBlockVerifierError) Error() string {
	if err == nil {
		return ""
	}
	message := "eBPF verifier rejected per-VM block latency program"
	if err.Operation != "" {
		message += " during " + err.Operation
	}
	if err.Err != nil {
		message += ": " + err.Err.Error()
	}
	if err.Log != "" {
		message += "; verifier log: " + err.Log
	}
	return message
}

func (err *VMBlockVerifierError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func boundVMBlockDiagnostic(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if maximum <= 0 || len(value) <= maximum {
		return value
	}
	const suffix = "... (truncated)"
	if maximum <= len(suffix) {
		return suffix[:maximum]
	}
	return value[:maximum-len(suffix)] + suffix
}

// experimentalVMBlockKernelSource represents the still-unimplemented bio/blkcg
// VM-attribution stage. The product host request-correlation source uses Cilium
// and reports object_unavailable until a matching authentic ELF is embedded;
// this source remains useful for explicit deferred-feature tests.
type experimentalVMBlockKernelSource struct{}

func (experimentalVMBlockKernelSource) Preflight(context.Context) (VMBlockKernelPreflight, error) {
	return VMBlockKernelPreflight{
		Available: false,
		Status:    "experimental_not_implemented",
		Error:     ErrVMBlockLatencyNotImplemented.Error(),
	}, ErrVMBlockLatencyNotImplemented
}

func (experimentalVMBlockKernelSource) Prepare(context.Context, VMBlockLatencyCollectOptions, []VMBlockCgroupMapping) (VMBlockKernelSession, error) {
	return nil, ErrVMBlockLatencyNotImplemented
}

// eventSourceKernelAdapter retains the original event-source test seam while
// routing it through the lifecycle contract. Product collection never creates
// this adapter.
type eventSourceKernelAdapter struct {
	source VMBlockEventSource
}

func newEventSourceKernelAdapter(source VMBlockEventSource) VMBlockKernelSource {
	return eventSourceKernelAdapter{source: source}
}

func (source eventSourceKernelAdapter) Preflight(context.Context) (VMBlockKernelPreflight, error) {
	if source.source == nil {
		return VMBlockKernelPreflight{}, ErrVMBlockLatencyNotImplemented
	}
	return VMBlockKernelPreflight{Available: true, Status: "available"}, nil
}

func (source eventSourceKernelAdapter) Prepare(context.Context, VMBlockLatencyCollectOptions, []VMBlockCgroupMapping) (VMBlockKernelSession, error) {
	if source.source == nil {
		return nil, ErrVMBlockLatencyNotImplemented
	}
	return &eventSourceKernelSession{source: source.source}, nil
}

type eventSourceKernelSession struct {
	source  VMBlockEventSource
	started bool
}

func (session *eventSourceKernelSession) Start(context.Context) error {
	session.started = true
	return nil
}

func (session *eventSourceKernelSession) Collect(ctx context.Context, duration time.Duration, consume func(VMBlockEvent) error) error {
	if !session.started {
		return errors.New("per-VM eBPF test event session is not started")
	}
	return session.source.Collect(ctx, duration, consume)
}

func (*eventSourceKernelSession) Stats() VMBlockKernelStats {
	return VMBlockKernelStats{
		CollectionMode:       "test_event_stream",
		AttributionMethod:    "request_correlated+bio_blkcg+cgroup_inode_vm_map",
		AttributionAvailable: true,
	}
}
func (*eventSourceKernelSession) Stop() error  { return nil }
func (*eventSourceKernelSession) Close() error { return nil }

func runVMBlockKernelSource(
	ctx context.Context,
	source VMBlockKernelSource,
	options VMBlockLatencyCollectOptions,
	mappings []VMBlockCgroupMapping,
	consume func(VMBlockEvent) error,
) (stats VMBlockKernelStats, preflight VMBlockKernelPreflight, err error) {
	if source == nil {
		source = experimentalVMBlockKernelSource{}
	}
	preflight, err = source.Preflight(ctx)
	if err != nil {
		return VMBlockKernelStats{}, preflight, err
	}
	if !preflight.Available {
		status := firstNonEmpty(preflight.Status, "unavailable")
		message := firstNonEmpty(preflight.Error, "typed-BTF per-VM block latency preflight is unavailable")
		return VMBlockKernelStats{}, preflight, &VMBlockCapabilityError{Status: status, Name: message}
	}
	session, err := source.Prepare(ctx, options, mappings)
	if err != nil {
		return VMBlockKernelStats{}, preflight, err
	}
	if session == nil {
		return VMBlockKernelStats{}, preflight, errors.New("per-VM eBPF kernel source returned a nil session")
	}
	defer func() {
		closeErr := classifyVMBlockCleanupError("close per-VM eBPF collection", session.Close())
		if closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if err = session.Start(ctx); err != nil {
		return VMBlockKernelStats{}, preflight, classifyVMBlockLifecycleError("start_failed", "start per-VM eBPF collection", err)
	}
	collectErr := classifyVMBlockLifecycleError("collection_failed", "collect per-VM eBPF events", session.Collect(ctx, options.Duration, consume))
	stopErr := classifyVMBlockCleanupError("stop per-VM eBPF collection", session.Stop())
	stats = session.Stats()
	return stats, preflight, errors.Join(collectErr, stopErr)
}

func classifyVMBlockLifecycleError(status, operation string, err error) error {
	if err == nil {
		return nil
	}
	// A source-provided stage error is already more precise than the generic
	// lifecycle wrapper, including cleanup failures produced while freezing
	// the observation window before map reads.
	if len(vmBlockStageErrors(err)) > 0 {
		return err
	}
	if errors.Is(err, context.Canceled) {
		status = "cancelled"
		operation = "per-VM eBPF collection cancelled"
	} else if errors.Is(err, context.DeadlineExceeded) {
		status = "deadline_exceeded"
		operation = "per-VM eBPF collection deadline exceeded"
	}
	return &VMBlockKernelStageError{Status: status, Stage: "collection", Operation: operation, Err: err}
}

func classifyVMBlockCleanupError(operation string, err error) error {
	if err == nil {
		return nil
	}
	for _, stage := range vmBlockStageErrors(err) {
		if stage.Status == "cleanup_failed" {
			return err
		}
	}
	return &VMBlockKernelStageError{Status: "cleanup_failed", Stage: "cleanup", Operation: operation, Err: err}
}
