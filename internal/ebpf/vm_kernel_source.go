package ebpf

import (
	"context"
	"errors"
	"fmt"
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
	DroppedEvents  uint64 `json:"dropped_events"`
	RingBufferLost uint64 `json:"ring_buffer_lost"`
	MapFull        uint64 `json:"map_full"`
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

// experimentalVMBlockKernelSource is the only product source until a real,
// verifier-tested typed-BTF loader exists. It cannot emit events or claim
// successful collection.
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

func (*eventSourceKernelSession) Stats() VMBlockKernelStats { return VMBlockKernelStats{} }
func (*eventSourceKernelSession) Stop() error               { return nil }
func (*eventSourceKernelSession) Close() error              { return nil }

func runVMBlockKernelSource(
	ctx context.Context,
	source VMBlockKernelSource,
	options VMBlockLatencyCollectOptions,
	mappings []VMBlockCgroupMapping,
	consume func(VMBlockEvent) error,
) (stats VMBlockKernelStats, err error) {
	if source == nil {
		source = experimentalVMBlockKernelSource{}
	}
	preflight, err := source.Preflight(ctx)
	if err != nil {
		return VMBlockKernelStats{}, err
	}
	if !preflight.Available {
		status := firstNonEmpty(preflight.Status, "unavailable")
		message := firstNonEmpty(preflight.Error, "typed-BTF per-VM block latency preflight is unavailable")
		return VMBlockKernelStats{}, &VMBlockCapabilityError{Status: status, Name: message}
	}
	session, err := source.Prepare(ctx, options, mappings)
	if err != nil {
		return VMBlockKernelStats{}, err
	}
	if session == nil {
		return VMBlockKernelStats{}, errors.New("per-VM eBPF kernel source returned a nil session")
	}
	defer func() {
		closeErr := session.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close per-VM eBPF collection: %w", closeErr)
		}
	}()
	if err = session.Start(ctx); err != nil {
		return VMBlockKernelStats{}, err
	}
	collectErr := session.Collect(ctx, options.Duration, consume)
	stopErr := session.Stop()
	stats = session.Stats()
	if collectErr != nil {
		return stats, collectErr
	}
	if stopErr != nil {
		return stats, fmt.Errorf("stop per-VM eBPF collection: %w", stopErr)
	}
	return stats, nil
}
