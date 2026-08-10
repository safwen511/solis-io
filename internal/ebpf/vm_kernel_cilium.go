package ebpf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

var (
	ErrVMBlockBTFMissing            = errors.New("kernel BTF required for typed-BTF VM block count collection is unavailable")
	ErrVMBlockObjectInvalid         = errors.New("embedded typed-BTF VM block count object is invalid")
	ErrVMBlockUnsupportedEndianness = errors.New("embedded typed-BTF VM block count object supports little-endian Linux only")
)

const vmBlockCountCollectionMode = "typed_btf_count_only"

// VMBlockKernelStageError gives stable status to loader/attach/cleanup errors.
type VMBlockKernelStageError struct {
	Status    string
	Stage     string
	Operation string
	Err       error
}

func (err *VMBlockKernelStageError) Error() string {
	if err == nil {
		return ""
	}
	message := firstNonEmpty(err.Operation, "typed-BTF VM block count collection")
	if err.Err != nil {
		message += ": " + err.Err.Error()
	}
	return message
}

func (err *VMBlockKernelStageError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func vmBlockStageStatus(err error, fallback string) string {
	var stageError *VMBlockKernelStageError
	if errors.As(err, &stageError) {
		return firstNonEmpty(stageError.Status, fallback)
	}
	return fallback
}

type vmBlockCountObjectLoader interface {
	Load([]byte) (vmBlockCountResources, error)
}

type vmBlockCountResources interface {
	AttachIssue() (io.Closer, error)
	AttachComplete() (io.Closer, error)
	ReadCounters() (VMBlockKernelCounters, error)
	Close() error
}

type ciliumVMBlockKernelSource struct {
	platform       string
	architecture   string
	probeBTF       func() error
	objectProvider func() ([]byte, error)
	loader         vmBlockCountObjectLoader
}

func newCiliumVMBlockKernelSource() VMBlockKernelSource {
	return &ciliumVMBlockKernelSource{
		platform:       runtime.GOOS,
		architecture:   runtime.GOARCH,
		probeBTF:       probeVMBlockTypedTracepoints,
		objectProvider: embeddedVMBlockObject,
		loader:         ciliumVMBlockObjectLoader{},
	}
}

func (source *ciliumVMBlockKernelSource) Preflight(context.Context) (VMBlockKernelPreflight, error) {
	if source == nil || source.platform != "linux" {
		return VMBlockKernelPreflight{Status: VMBlockCapabilityUnsupportedKernel, Error: ErrVMBlockUnsupportedKernel.Error()}, ErrVMBlockUnsupportedKernel
	}
	if !supportsBPFELArchitecture(source.architecture) {
		err := fmt.Errorf("%w: GOARCH %s", ErrVMBlockUnsupportedEndianness, firstNonEmpty(source.architecture, "unknown"))
		return VMBlockKernelPreflight{Status: "unsupported_endianness", Error: err.Error()}, err
	}
	if source.objectProvider == nil {
		return VMBlockKernelPreflight{Status: "object_unavailable", Error: ErrVMBlockObjectUnavailable.Error()}, ErrVMBlockObjectUnavailable
	}
	if _, err := source.objectProvider(); err != nil {
		classified := classifyVMBlockObjectProviderError("preflight", "read embedded typed-BTF object", err)
		return VMBlockKernelPreflight{Status: vmBlockStageStatus(classified, "object_invalid"), Error: classified.Error()}, classified
	}
	if source.probeBTF == nil {
		return VMBlockKernelPreflight{Status: VMBlockCapabilityBTFMissing, Error: ErrVMBlockBTFMissing.Error()}, ErrVMBlockBTFMissing
	}
	if err := source.probeBTF(); err != nil {
		status := classifyVMBlockPreflightStatus(err)
		if primaryVMBlockStageError(err) == nil {
			err = &VMBlockKernelStageError{Status: status, Stage: "preflight", Operation: "typed-BTF preflight", Err: err}
		}
		return VMBlockKernelPreflight{Status: status, Error: err.Error()}, err
	}
	return VMBlockKernelPreflight{Available: true, Status: "available"}, nil
}

func (source *ciliumVMBlockKernelSource) Prepare(_ context.Context, _ VMBlockLatencyCollectOptions, _ []VMBlockCgroupMapping) (VMBlockKernelSession, error) {
	if source == nil || source.objectProvider == nil {
		return nil, &VMBlockKernelStageError{Status: "object_unavailable", Stage: "object_load", Operation: "prepare typed-BTF count-only collector", Err: ErrVMBlockObjectUnavailable}
	}
	if source.loader == nil {
		return nil, &VMBlockKernelStageError{Status: "object_load_failed", Stage: "object_load", Operation: "prepare typed-BTF count-only collector", Err: errors.New("object loader is unavailable")}
	}
	object, err := source.objectProvider()
	if err != nil {
		return nil, classifyVMBlockObjectProviderError("object_load", "read embedded typed-BTF object", err)
	}
	resources, err := source.loader.Load(object)
	if err != nil {
		return nil, classifyVMBlockLoadError(err)
	}
	if resources == nil {
		return nil, &VMBlockKernelStageError{Status: "object_load_failed", Stage: "object_load", Operation: "load embedded typed-BTF object", Err: errors.New("loader returned nil resources")}
	}
	return &ciliumVMBlockKernelSession{resources: resources}, nil
}

func supportsBPFELArchitecture(architecture string) bool {
	switch strings.TrimSpace(architecture) {
	case "386", "amd64", "arm", "arm64", "loong64", "mipsle", "mips64le", "ppc64le", "riscv64":
		return true
	default:
		return false
	}
}

func classifyVMBlockObjectProviderError(stage, operation string, err error) error {
	if errors.Is(err, ErrVMBlockObjectUnavailable) || errors.Is(err, fs.ErrNotExist) {
		return &VMBlockKernelStageError{Status: "object_unavailable", Stage: stage, Operation: operation, Err: err}
	}
	return &VMBlockKernelStageError{Status: "object_invalid", Stage: stage, Operation: operation, Err: err}
}

func classifyVMBlockPreflightStatus(err error) string {
	switch {
	case errors.Is(err, ErrVMBlockBTFMissing):
		return VMBlockCapabilityBTFMissing
	case errors.Is(err, ErrVMBlockUnsupportedKernel):
		return VMBlockCapabilityUnsupportedKernel
	case errors.Is(err, os.ErrPermission):
		return VMBlockCapabilityPermissionDenied
	default:
		var stageError *VMBlockKernelStageError
		if errors.As(err, &stageError) && stageError.Status != "" {
			return stageError.Status
		}
		return VMBlockCapabilityResolutionError
	}
}

func probeVMBlockTypedTracepoints() error {
	_, err := inspectVMBlockTypedTracepoints()
	return err
}

func inspectVMBlockTypedTracepoints() ([]vmBlockTypedTracepointPrototype, error) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrVMBlockBTFMissing
		}
		return nil, fmt.Errorf("read kernel BTF: %w", err)
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("load kernel BTF: %w", err)
	}
	return resolveVMBlockTypedTracepoints(spec)
}

type vmBlockBTFTypeFinder interface {
	TypeByName(string, any) error
}

type vmBlockTypedTracepointPrototype struct {
	Name              string
	KernelParameters  []string
	ProgramParameters []string
}

type vmBlockTypedTracepointExpectation struct {
	typedefName       string
	tracepointName    string
	programParameters []string
}

var vmBlockTypedTracepointExpectations = []vmBlockTypedTracepointExpectation{
	{
		typedefName:       "btf_trace_block_rq_issue",
		tracepointName:    "block_rq_issue",
		programParameters: []string{"struct request *"},
	},
	{
		typedefName:       "btf_trace_block_rq_complete",
		tracepointName:    "block_rq_complete",
		programParameters: []string{"struct request *", "blk_status_t", "unsigned int"},
	},
}

func resolveVMBlockTypedTracepoints(spec vmBlockBTFTypeFinder) ([]vmBlockTypedTracepointPrototype, error) {
	if spec == nil {
		return nil, &VMBlockKernelStageError{
			Status: VMBlockCapabilityResolutionError, Stage: "preflight", Operation: "resolve typed block tracepoints", Err: errors.New("kernel BTF type finder is unavailable"),
		}
	}

	// Cilium resolves tp_btf AttachTraceRawTp targets by prefixing AttachTo
	// with btf_trace_. Kernel BTF publishes these targets as typedefs of
	// function pointers, not as BTF functions. The typedef's leading void
	// pointer is kernel trace callback data and is not an argument exposed to
	// a tp_btf BPF program. The effective program parameters begin after it.
	prototypes := make([]vmBlockTypedTracepointPrototype, 0, len(vmBlockTypedTracepointExpectations))
	for _, expectation := range vmBlockTypedTracepointExpectations {
		var tracepoint *btf.Typedef
		if err := spec.TypeByName(expectation.typedefName, &tracepoint); err != nil {
			return nil, &VMBlockKernelStageError{
				Status: "typed_tracepoint_missing", Stage: "preflight", Operation: "resolve typed tracepoint " + expectation.tracepointName, Err: err,
			}
		}
		prototype, err := describeVMBlockTypedTracepoint(tracepoint, expectation)
		if err != nil {
			return nil, &VMBlockKernelStageError{
				Status: "btf_incompatible", Stage: "preflight", Operation: "validate typed tracepoint " + expectation.tracepointName, Err: err,
			}
		}
		prototypes = append(prototypes, prototype)
	}
	return prototypes, nil
}

func describeVMBlockTypedTracepoint(tracepoint *btf.Typedef, expectation vmBlockTypedTracepointExpectation) (vmBlockTypedTracepointPrototype, error) {
	if tracepoint == nil {
		return vmBlockTypedTracepointPrototype{}, errors.New("kernel BTF typedef is nil")
	}
	pointer, ok := btf.UnderlyingType(tracepoint).(*btf.Pointer)
	if !ok || pointer == nil {
		return vmBlockTypedTracepointPrototype{}, fmt.Errorf("%s is not a function-pointer typedef", expectation.typedefName)
	}
	function, ok := btf.UnderlyingType(pointer.Target).(*btf.FuncProto)
	if !ok || function == nil {
		return vmBlockTypedTracepointPrototype{}, fmt.Errorf("%s does not reference a function prototype", expectation.typedefName)
	}

	kernelParameters := make([]string, 0, len(function.Params))
	for _, parameter := range function.Params {
		kernelParameters = append(kernelParameters, formatVMBlockBTFType(parameter.Type))
	}
	if len(kernelParameters) == 0 || kernelParameters[0] != "void *" {
		return vmBlockTypedTracepointPrototype{}, fmt.Errorf("%s leading trace callback parameter is %q, want void *", expectation.typedefName, firstVMBlockParameter(kernelParameters))
	}
	programParameters := append([]string(nil), kernelParameters[1:]...)
	if !equalVMBlockParameters(programParameters, expectation.programParameters) {
		return vmBlockTypedTracepointPrototype{}, fmt.Errorf("%s program parameters are %v, want %v", expectation.typedefName, programParameters, expectation.programParameters)
	}
	return vmBlockTypedTracepointPrototype{
		Name:              expectation.tracepointName,
		KernelParameters:  append([]string(nil), kernelParameters...),
		ProgramParameters: programParameters,
	}, nil
}

func formatVMBlockBTFType(value btf.Type) string {
	value = btf.QualifiedType(value)
	switch typed := value.(type) {
	case *btf.Void:
		return "void"
	case *btf.Pointer:
		return strings.TrimSpace(formatVMBlockBTFType(typed.Target)) + " *"
	case *btf.Typedef:
		return firstNonEmpty(strings.TrimSpace(typed.Name), formatVMBlockBTFType(typed.Type))
	case *btf.Struct:
		return strings.TrimSpace("struct " + typed.Name)
	case *btf.Union:
		return strings.TrimSpace("union " + typed.Name)
	case *btf.Enum:
		return strings.TrimSpace("enum " + typed.Name)
	case *btf.Int:
		return strings.TrimSpace(typed.Name)
	default:
		return fmt.Sprintf("%T", value)
	}
}

func equalVMBlockParameters(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func firstVMBlockParameter(parameters []string) string {
	if len(parameters) == 0 {
		return "-"
	}
	return parameters[0]
}

type ciliumVMBlockKernelSession struct {
	resources    vmBlockCountResources
	issueLink    io.Closer
	completeLink io.Closer
	stats        VMBlockKernelStats
	stopOnce     sync.Once
	stopErr      error
	closeOnce    sync.Once
	closeErr     error
}

func (session *ciliumVMBlockKernelSession) Start(context.Context) error {
	issueLink, err := session.resources.AttachIssue()
	if err != nil {
		return classifyVMBlockAttachError("issue_attach", "attach block_rq_issue typed-BTF program", err)
	}
	if issueLink == nil {
		return &VMBlockKernelStageError{Status: "attach_failed", Stage: "issue_attach", Operation: "attach block_rq_issue typed-BTF program", Err: errors.New("attach returned a nil link")}
	}
	session.issueLink = issueLink
	completeLink, err := session.resources.AttachComplete()
	if err != nil {
		cleanupErr := closeVMBlockLink(&session.issueLink)
		attachErr := classifyVMBlockAttachError("complete_attach", "attach block_rq_complete typed-BTF program", err)
		if cleanupErr != nil {
			return errors.Join(attachErr, &VMBlockKernelStageError{Status: "cleanup_failed", Stage: "cleanup", Operation: "detach block_rq_issue after partial attach", Err: cleanupErr})
		}
		return attachErr
	}
	if completeLink == nil {
		cleanupErr := closeVMBlockLink(&session.issueLink)
		attachErr := &VMBlockKernelStageError{Status: "attach_failed", Stage: "complete_attach", Operation: "attach block_rq_complete typed-BTF program", Err: errors.New("attach returned a nil link")}
		if cleanupErr != nil {
			return errors.Join(attachErr, &VMBlockKernelStageError{Status: "cleanup_failed", Stage: "cleanup", Operation: "detach block_rq_issue after partial attach", Err: cleanupErr})
		}
		return attachErr
	}
	session.completeLink = completeLink
	return nil
}

func (session *ciliumVMBlockKernelSession) Collect(ctx context.Context, duration time.Duration, _ func(VMBlockEvent) error) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	counters, err := session.resources.ReadCounters()
	if err != nil {
		if isPermissionError(err) {
			return &VMBlockKernelStageError{Status: "permission_denied", Stage: "map_read", Operation: "read typed-BTF count-only counters", Err: err}
		}
		return &VMBlockKernelStageError{Status: "counter_read_failed", Stage: "map_read", Operation: "read typed-BTF count-only counters", Err: err}
	}
	session.stats = VMBlockKernelStats{
		CollectionMode:       vmBlockCountCollectionMode,
		AttributionMethod:    "none_count_only",
		AttributionAvailable: false,
		Counters:             counters,
	}
	return nil
}

func (session *ciliumVMBlockKernelSession) Stats() VMBlockKernelStats { return session.stats }

func (session *ciliumVMBlockKernelSession) Stop() error {
	session.stopOnce.Do(func() {
		session.stopErr = errors.Join(closeVMBlockLink(&session.completeLink), closeVMBlockLink(&session.issueLink))
		if session.stopErr != nil {
			session.stopErr = &VMBlockKernelStageError{Status: "cleanup_failed", Stage: "cleanup", Operation: "detach typed-BTF count-only links", Err: session.stopErr}
		}
	})
	return session.stopErr
}

func (session *ciliumVMBlockKernelSession) Close() error {
	session.closeOnce.Do(func() {
		stopErr := session.Stop()
		resourceErr := session.resources.Close()
		session.closeErr = errors.Join(stopErr, resourceErr)
		if session.closeErr != nil {
			session.closeErr = &VMBlockKernelStageError{Status: "cleanup_failed", Stage: "cleanup", Operation: "close typed-BTF count-only resources", Err: session.closeErr}
		}
	})
	return session.closeErr
}

func closeVMBlockLink(target *io.Closer) error {
	if target == nil || *target == nil {
		return nil
	}
	link := *target
	*target = nil
	return link.Close()
}

func classifyVMBlockAttachError(stage, operation string, err error) error {
	if isPermissionError(err) {
		return &VMBlockKernelStageError{Status: "permission_denied", Stage: stage, Operation: operation, Err: err}
	}
	if errors.Is(err, os.ErrNotExist) {
		return &VMBlockKernelStageError{Status: "typed_tracepoint_missing", Stage: stage, Operation: operation, Err: err}
	}
	return &VMBlockKernelStageError{Status: "attach_failed", Stage: stage, Operation: operation, Err: err}
}

func classifyVMBlockLoadError(err error) error {
	var verifierError *VMBlockVerifierError
	if errors.As(err, &verifierError) {
		return verifierError
	}
	if isPermissionError(err) {
		return &VMBlockKernelStageError{Status: "permission_denied", Stage: "object_load", Operation: "load embedded typed-BTF object", Err: err}
	}
	if errors.Is(err, ErrVMBlockObjectInvalid) {
		return &VMBlockKernelStageError{Status: "object_invalid", Stage: "object_load", Operation: "load embedded typed-BTF object", Err: err}
	}
	if errors.Is(err, btf.ErrNotFound) {
		return &VMBlockKernelStageError{Status: "btf_incompatible", Stage: "object_load", Operation: "relocate embedded typed-BTF object", Err: err}
	}
	return &VMBlockKernelStageError{Status: "object_load_failed", Stage: "object_load", Operation: "load embedded typed-BTF object", Err: err}
}

type ciliumVMBlockObjectLoader struct{}

type ciliumVMBlockObjects struct {
	OnIssue    *ciliumebpf.Program `ebpf:"on_block_rq_issue"`
	OnComplete *ciliumebpf.Program `ebpf:"on_block_rq_complete"`
	Counters   *ciliumebpf.Map     `ebpf:"counters"`
}

func (ciliumVMBlockObjectLoader) Load(object []byte) (vmBlockCountResources, error) {
	spec, err := ciliumebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("%w: parse embedded eBPF ELF: %v", ErrVMBlockObjectInvalid, err)
	}
	objects := &ciliumVMBlockObjects{}
	err = spec.LoadAndAssign(objects, &ciliumebpf.CollectionOptions{
		Programs: ciliumebpf.ProgramOptions{LogSizeStart: 64 * 1024},
	})
	if err != nil {
		var verifierError *ciliumebpf.VerifierError
		if errors.As(err, &verifierError) {
			return nil, NewVMBlockVerifierError("load typed-BTF count-only object", fmt.Sprintf("%+v", verifierError), err)
		}
		return nil, err
	}
	return objects, nil
}

func (objects *ciliumVMBlockObjects) AttachIssue() (io.Closer, error) {
	return link.AttachTracing(link.TracingOptions{Program: objects.OnIssue})
}

func (objects *ciliumVMBlockObjects) AttachComplete() (io.Closer, error) {
	return link.AttachTracing(link.TracingOptions{Program: objects.OnComplete})
}

func (objects *ciliumVMBlockObjects) ReadCounters() (VMBlockKernelCounters, error) {
	var perCPU []vmBlockCountValues
	key := uint32(0)
	if err := objects.Counters.Lookup(&key, &perCPU); err != nil {
		return VMBlockKernelCounters{}, err
	}
	var counters VMBlockKernelCounters
	for _, value := range perCPU {
		counters.IssueSeen = saturatingAdd(counters.IssueSeen, value.IssueSeen)
		counters.CompleteSeen = saturatingAdd(counters.CompleteSeen, value.CompleteSeen)
		counters.NullRequest = saturatingAdd(counters.NullRequest, value.NullRequest)
	}
	return counters, nil
}

func (objects *ciliumVMBlockObjects) Close() error {
	return errors.Join(closeCiliumProgram(objects.OnIssue), closeCiliumProgram(objects.OnComplete), closeCiliumMap(objects.Counters))
}

type vmBlockCountValues struct {
	IssueSeen    uint64
	CompleteSeen uint64
	NullRequest  uint64
}

func closeCiliumProgram(program *ciliumebpf.Program) error {
	if program == nil {
		return nil
	}
	return program.Close()
}

func closeCiliumMap(blockMap *ciliumebpf.Map) error {
	if blockMap == nil {
		return nil
	}
	return blockMap.Close()
}

func saturatingAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}
