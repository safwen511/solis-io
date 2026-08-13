package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

var (
	ErrVMBlockBTFMissing            = errors.New("kernel BTF required for typed-BTF host request-latency collection is unavailable")
	ErrVMBlockObjectInvalid         = errors.New("embedded typed-BTF host request-latency object is invalid")
	ErrVMBlockUnsupportedEndianness = errors.New("embedded typed-BTF host request-latency object supports little-endian Linux only")
)

const vmBlockHostLatencyCollectionMode = "typed_btf_request_correlation_host_only"
const vmBlockHostAttributionMethod = "host_request_correlation_no_vm_attribution"
const vmBlockVMAttributionCollectionMode = "typed_btf_vm_attributed_latency"
const vmBlockVMAttributionMethod = "blkcg_cgroup_id_to_libvirt_vm"

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
	message := firstNonEmpty(err.Operation, "typed-BTF host request-latency collection")
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
	ReadStats() (VMBlockKernelStats, error)
	Close() error
}

type ciliumVMBlockKernelSource struct {
	platform        string
	architecture    string
	probeBTF        func() error
	capabilityProbe func() (VMBlockBTFCapabilityReport, error)
	objectProvider  func() ([]byte, error)
	loader          vmBlockCountObjectLoader
}

func newCiliumVMBlockKernelSource() VMBlockKernelSource {
	return &ciliumVMBlockKernelSource{
		platform:        runtime.GOOS,
		architecture:    runtime.GOARCH,
		probeBTF:        probeVMBlockTypedTracepoints,
		capabilityProbe: inspectKernelVMBlockBTFCapabilities,
		objectProvider:  embeddedVMBlockObject,
		loader:          ciliumVMBlockObjectLoader{},
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
	if source.capabilityProbe == nil {
		err := errors.New("request metadata BTF capability probe is unavailable")
		return VMBlockKernelPreflight{Status: VMBlockCapabilityResolutionError, Error: err.Error()}, err
	}
	capabilities, err := source.capabilityProbe()
	if err != nil {
		classified := &VMBlockKernelStageError{Status: VMBlockCapabilityResolutionError, Stage: "preflight", Operation: "inspect request metadata and VM ownership BTF fields", Err: err}
		return VMBlockKernelPreflight{Status: VMBlockCapabilityResolutionError, Error: classified.Error(), Capabilities: capabilities}, classified
	}
	if missing := missingVMBlockCapabilities(capabilities, vmBlockMetadataRequirements); len(missing) > 0 {
		err := fmt.Errorf("required request metadata BTF fields are unavailable: %s", strings.Join(missing, ", "))
		classified := &VMBlockKernelStageError{Status: "request_metadata_unsupported", Stage: "preflight", Operation: "inspect request metadata BTF fields", Err: err}
		return VMBlockKernelPreflight{Status: "request_metadata_unsupported", Error: classified.Error(), Capabilities: capabilities}, classified
	}
	if missing := missingVMBlockCapabilities(capabilities, vmBlockOwnershipRequirements); len(missing) > 0 {
		err := fmt.Errorf("required VM ownership BTF fields are unavailable: %s", strings.Join(missing, ", "))
		classified := &VMBlockKernelStageError{Status: "vm_attribution_unsupported", Stage: "preflight", Operation: "inspect blkcg cgroup ownership BTF fields", Err: err}
		return VMBlockKernelPreflight{Status: "vm_attribution_unsupported", Error: classified.Error(), Capabilities: capabilities}, classified
	}
	return VMBlockKernelPreflight{Available: true, Status: "available", Capabilities: capabilities}, nil
}

func (source *ciliumVMBlockKernelSource) Prepare(_ context.Context, options VMBlockLatencyCollectOptions, _ []VMBlockCgroupMapping) (VMBlockKernelSession, error) {
	if strings.TrimSpace(options.DeviceFilter) != "" {
		return nil, &VMBlockKernelStageError{
			Status: "device_filter_unsupported", Stage: "preflight", Operation: "prepare typed-BTF host request-latency collector",
			Err: errors.New("device filtering is not enabled until major:minor selector resolution and filter semantics are validated; device metadata is report-only"),
		}
	}
	if source == nil || source.objectProvider == nil {
		return nil, &VMBlockKernelStageError{Status: "object_unavailable", Stage: "object_load", Operation: "prepare typed-BTF host request-latency collector", Err: ErrVMBlockObjectUnavailable}
	}
	if source.loader == nil {
		return nil, &VMBlockKernelStageError{Status: "object_load_failed", Stage: "object_load", Operation: "prepare typed-BTF host request-latency collector", Err: errors.New("object loader is unavailable")}
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
	// Freeze the observation window before reading maps. This makes the number
	// of request entries left in request_starts a conservative end-of-window
	// censored-request count instead of racing active hooks.
	if err := session.Stop(); err != nil {
		return err
	}
	stats, err := session.resources.ReadStats()
	if err != nil {
		stats.CollectionMode = vmBlockHostLatencyCollectionMode
		stats.AttributionMethod = vmBlockHostAttributionMethod
		session.stats = stats
		var layoutError *VMBlockMapLayoutError
		if errors.As(err, &layoutError) {
			return &VMBlockKernelStageError{Status: "map_layout_mismatch", Stage: "map_read", Operation: "read typed-BTF request-latency maps", Err: err}
		}
		if isPermissionError(err) {
			return &VMBlockKernelStageError{Status: "permission_denied", Stage: "map_read", Operation: "read typed-BTF request-latency maps", Err: err}
		}
		return &VMBlockKernelStageError{Status: "map_read_failed", Stage: "map_read", Operation: "read typed-BTF request-latency maps", Err: err}
	}
	stats.CollectionMode = vmBlockVMAttributionCollectionMode
	stats.AttributionMethod = vmBlockVMAttributionMethod
	stats.AttributionAvailable = true
	session.stats = stats
	return nil
}

func (session *ciliumVMBlockKernelSession) Stats() VMBlockKernelStats { return session.stats }

func (session *ciliumVMBlockKernelSession) Stop() error {
	session.stopOnce.Do(func() {
		// Stop new issues first, then allow the completion hook to remain until
		// its link is closed. This minimizes artificial pending entries at the
		// observation boundary.
		session.stopErr = errors.Join(closeVMBlockLink(&session.issueLink), closeVMBlockLink(&session.completeLink))
		if session.stopErr != nil {
			session.stopErr = &VMBlockKernelStageError{Status: "cleanup_failed", Stage: "cleanup", Operation: "detach typed-BTF request-correlation links", Err: session.stopErr}
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
			session.closeErr = &VMBlockKernelStageError{Status: "cleanup_failed", Stage: "cleanup", Operation: "close typed-BTF request-correlation resources", Err: session.closeErr}
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

const (
	vmBlockRequestStartsMapName         = "request_starts"
	vmBlockDeviceOperationMapName       = "device_operation_stats"
	vmBlockCgroupDeviceOperationMapName = "cgroup_device_operation_stats"
)

// VMBlockMapLayoutError identifies an ELF/Go key- or value-layout mismatch
// before map iteration. It contains sizes and a map name only, never map
// contents.
type VMBlockMapLayoutError struct {
	MapName        string
	Component      string
	SizeFromObject uint32
	GoSize         int
}

func (err *VMBlockMapLayoutError) Error() string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf(
		"map layout mismatch for %s: object %s size %d, Go %s size %d",
		firstNonEmpty(strings.TrimSpace(err.MapName), "unknown"),
		firstNonEmpty(strings.TrimSpace(err.Component), "data"), err.SizeFromObject,
		firstNonEmpty(strings.TrimSpace(err.Component), "data"), err.GoSize,
	)
}

type ciliumVMBlockObjects struct {
	OnIssue                    *ciliumebpf.Program `ebpf:"on_block_rq_issue"`
	OnComplete                 *ciliumebpf.Program `ebpf:"on_block_rq_complete"`
	Counters                   *ciliumebpf.Map     `ebpf:"counters"`
	RequestStarts              *ciliumebpf.Map     `ebpf:"request_starts"`
	LatencyStats               *ciliumebpf.Map     `ebpf:"latency_stats"`
	DeviceOperationStats       *ciliumebpf.Map     `ebpf:"device_operation_stats"`
	CgroupDeviceOperationStats *ciliumebpf.Map     `ebpf:"cgroup_device_operation_stats"`
}

func (ciliumVMBlockObjectLoader) Load(object []byte) (vmBlockCountResources, error) {
	spec, err := ciliumebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("%w: parse embedded eBPF ELF: %v", ErrVMBlockObjectInvalid, err)
	}
	if err := validateVMBlockCollectionSpec(spec); err != nil {
		return nil, err
	}
	objects := &ciliumVMBlockObjects{}
	err = spec.LoadAndAssign(objects, &ciliumebpf.CollectionOptions{
		Programs: ciliumebpf.ProgramOptions{LogSizeStart: 64 * 1024},
	})
	if err != nil {
		var verifierError *ciliumebpf.VerifierError
		if errors.As(err, &verifierError) {
			return nil, NewVMBlockVerifierError("load typed-BTF host request-latency object", fmt.Sprintf("%+v", verifierError), err)
		}
		return nil, err
	}
	return objects, nil
}

func validateVMBlockCollectionSpec(spec *ciliumebpf.CollectionSpec) error {
	if spec == nil {
		return fmt.Errorf("%w: embedded eBPF collection spec is nil", ErrVMBlockObjectInvalid)
	}
	for _, name := range []string{"on_block_rq_issue", "on_block_rq_complete"} {
		if _, available := spec.Programs[name]; !available {
			return fmt.Errorf("%w: embedded eBPF object is stale or incompatible; missing program %s", ErrVMBlockObjectInvalid, name)
		}
	}
	for _, name := range []string{
		"counters", vmBlockRequestStartsMapName, "latency_stats", "device_operation_stats", "cgroup_device_operation_stats",
	} {
		if _, available := spec.Maps[name]; !available {
			return fmt.Errorf("%w: embedded eBPF object is stale or incompatible; missing map %s", ErrVMBlockObjectInvalid, name)
		}
	}
	if err := validateVMBlockMapKeyLayout(
		vmBlockRequestStartsMapName, spec.Maps[vmBlockRequestStartsMapName].KeySize, uint64(0),
	); err != nil {
		return fmt.Errorf("%w: %w", ErrVMBlockObjectInvalid, err)
	}
	if err := validateVMBlockMapValueLayout(
		vmBlockRequestStartsMapName, spec.Maps[vmBlockRequestStartsMapName].ValueSize, vmBlockIssueValue{},
	); err != nil {
		return fmt.Errorf("%w: %w", ErrVMBlockObjectInvalid, err)
	}
	if err := validateVMBlockMapKeyLayout(
		vmBlockDeviceOperationMapName, spec.Maps[vmBlockDeviceOperationMapName].KeySize, vmBlockDeviceOperationKey{},
	); err != nil {
		return fmt.Errorf("%w: %w", ErrVMBlockObjectInvalid, err)
	}
	if err := validateVMBlockMapKeyLayout(
		vmBlockCgroupDeviceOperationMapName, spec.Maps[vmBlockCgroupDeviceOperationMapName].KeySize, vmBlockCgroupDeviceOperationKey{},
	); err != nil {
		return fmt.Errorf("%w: %w", ErrVMBlockObjectInvalid, err)
	}
	return nil
}

func validateVMBlockMapKeyLayout(mapName string, objectKeySize uint32, key any) error {
	goKeySize := binary.Size(key)
	if goKeySize < 0 || uint32(goKeySize) != objectKeySize {
		return &VMBlockMapLayoutError{
			MapName: strings.TrimSpace(mapName), Component: "key", SizeFromObject: objectKeySize, GoSize: goKeySize,
		}
	}
	return nil
}

func validateVMBlockMapValueLayout(mapName string, objectValueSize uint32, value any) error {
	goValueSize := binary.Size(value)
	if goValueSize < 0 || uint32(goValueSize) != objectValueSize {
		return &VMBlockMapLayoutError{
			MapName: strings.TrimSpace(mapName), Component: "value", SizeFromObject: objectValueSize, GoSize: goValueSize,
		}
	}
	return nil
}

func (objects *ciliumVMBlockObjects) AttachIssue() (io.Closer, error) {
	return link.AttachTracing(link.TracingOptions{Program: objects.OnIssue})
}

func (objects *ciliumVMBlockObjects) AttachComplete() (io.Closer, error) {
	return link.AttachTracing(link.TracingOptions{Program: objects.OnComplete})
}

func (objects *ciliumVMBlockObjects) ReadStats() (VMBlockKernelStats, error) {
	var perCPU []vmBlockCountValues
	key := uint32(0)
	if err := objects.Counters.Lookup(&key, &perCPU); err != nil {
		return VMBlockKernelStats{}, fmt.Errorf("read request-correlation counters: %w", err)
	}
	var counters VMBlockKernelCounters
	for _, value := range perCPU {
		counters.IssueSeen = saturatingAdd(counters.IssueSeen, value.IssueSeen)
		counters.CompleteSeen = saturatingAdd(counters.CompleteSeen, value.CompleteSeen)
		counters.NullRequest = saturatingAdd(counters.NullRequest, value.NullRequest)
		counters.DuplicateIssue = saturatingAdd(counters.DuplicateIssue, value.DuplicateIssue)
		counters.LookupMiss = saturatingAdd(counters.LookupMiss, value.LookupMiss)
		counters.MapFull = saturatingAdd(counters.MapFull, value.MapFull)
		counters.CompletedLatencyEvents = saturatingAdd(counters.CompletedLatencyEvents, value.CompletedLatencyEvents)
		counters.MetadataUnavailable = saturatingAdd(counters.MetadataUnavailable, value.MetadataUnavailable)
		counters.DeviceUnavailable = saturatingAdd(counters.DeviceUnavailable, value.DeviceUnavailable)
		counters.OperationUnknown = saturatingAdd(counters.OperationUnknown, value.OperationUnknown)
		counters.MissingBio = saturatingAdd(counters.MissingBio, value.MissingBio)
		counters.MissingBlkcg = saturatingAdd(counters.MissingBlkcg, value.MissingBlkcg)
	}

	var perCPULatency []vmBlockLatencyValues
	if err := objects.LatencyStats.Lookup(&key, &perCPULatency); err != nil {
		return VMBlockKernelStats{}, fmt.Errorf("read request-latency histogram: %w", err)
	}
	latency := mergeVMBlockPerCPULatency(perCPULatency)
	partial := VMBlockKernelStats{Counters: counters, HostLatency: latency}
	deviceOperations, err := objects.readDeviceOperations()
	if err != nil {
		return partial, err
	}
	partial.HostDeviceOperations = deviceOperations
	cgroupDeviceOperations, err := objects.readCgroupDeviceOperations()
	if err != nil {
		return partial, err
	}
	partial.CgroupDeviceOperations = cgroupDeviceOperations

	if err := validateVMBlockMapKeyLayout(vmBlockRequestStartsMapName, objects.RequestStarts.KeySize(), uint64(0)); err != nil {
		return partial, err
	}
	if err := validateVMBlockMapValueLayout(vmBlockRequestStartsMapName, objects.RequestStarts.ValueSize(), vmBlockIssueValue{}); err != nil {
		return partial, err
	}
	var requestKey uint64
	var issueValue vmBlockIssueValue
	iterator := objects.RequestStarts.Iterate()
	for iterator.Next(&requestKey, &issueValue) {
		counters.IncompleteAtWindowEnd = saturatingAdd(counters.IncompleteAtWindowEnd, 1)
	}
	if err := iterator.Err(); err != nil {
		return partial, fmt.Errorf("count incomplete request correlations: %w", err)
	}
	partial.Counters = counters
	return partial, nil
}

func (objects *ciliumVMBlockObjects) readDeviceOperations() ([]VMBlockKernelDeviceOperation, error) {
	if err := validateVMBlockMapKeyLayout(vmBlockDeviceOperationMapName, objects.DeviceOperationStats.KeySize(), vmBlockDeviceOperationKey{}); err != nil {
		return nil, err
	}
	result := make([]VMBlockKernelDeviceOperation, 0)
	iterator := objects.DeviceOperationStats.Iterate()
	var key vmBlockDeviceOperationKey
	var perCPU []vmBlockLatencyValues
	for iterator.Next(&key, &perCPU) {
		result = append(result, VMBlockKernelDeviceOperation{
			Major: key.Major, Minor: key.Minor, Operation: vmBlockOperationName(key.Operation),
			Latency: mergeVMBlockPerCPULatency(perCPU),
		})
		perCPU = nil
	}
	if err := iterator.Err(); err != nil {
		return nil, fmt.Errorf("read device-operation latency aggregates: %w", err)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Major != result[right].Major {
			return result[left].Major < result[right].Major
		}
		if result[left].Minor != result[right].Minor {
			return result[left].Minor < result[right].Minor
		}
		return blockOperationOrder(result[left].Operation) < blockOperationOrder(result[right].Operation)
	})
	return result, nil
}

func (objects *ciliumVMBlockObjects) readCgroupDeviceOperations() ([]VMBlockKernelCgroupDeviceOperation, error) {
	if err := validateVMBlockMapKeyLayout(vmBlockCgroupDeviceOperationMapName, objects.CgroupDeviceOperationStats.KeySize(), vmBlockCgroupDeviceOperationKey{}); err != nil {
		return nil, err
	}
	result := make([]VMBlockKernelCgroupDeviceOperation, 0)
	iterator := objects.CgroupDeviceOperationStats.Iterate()
	var key vmBlockCgroupDeviceOperationKey
	var perCPU []vmBlockLatencyValues
	for iterator.Next(&key, &perCPU) {
		result = append(result, VMBlockKernelCgroupDeviceOperation{
			CgroupID: key.CgroupID, Major: key.Major, Minor: key.Minor,
			Operation: vmBlockOperationName(key.Operation), Latency: mergeVMBlockPerCPULatency(perCPU),
		})
		perCPU = nil
	}
	if err := iterator.Err(); err != nil {
		return nil, fmt.Errorf("read cgroup-device-operation latency aggregates: %w", err)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].CgroupID != result[right].CgroupID {
			return result[left].CgroupID < result[right].CgroupID
		}
		if result[left].Major != result[right].Major {
			return result[left].Major < result[right].Major
		}
		if result[left].Minor != result[right].Minor {
			return result[left].Minor < result[right].Minor
		}
		return blockOperationOrder(result[left].Operation) < blockOperationOrder(result[right].Operation)
	})
	return result, nil
}

func (objects *ciliumVMBlockObjects) Close() error {
	return errors.Join(
		closeCiliumProgram(objects.OnIssue),
		closeCiliumProgram(objects.OnComplete),
		closeCiliumMap(objects.Counters),
		closeCiliumMap(objects.RequestStarts),
		closeCiliumMap(objects.LatencyStats),
		closeCiliumMap(objects.DeviceOperationStats),
		closeCiliumMap(objects.CgroupDeviceOperationStats),
	)
}

type vmBlockCountValues struct {
	IssueSeen              uint64
	CompleteSeen           uint64
	NullRequest            uint64
	DuplicateIssue         uint64
	LookupMiss             uint64
	MapFull                uint64
	CompletedLatencyEvents uint64
	MetadataUnavailable    uint64
	DeviceUnavailable      uint64
	OperationUnknown       uint64
	MissingBio             uint64
	MissingBlkcg           uint64
}

type vmBlockLatencyValues struct {
	Count      uint64
	TotalNS    uint64
	MinNS      uint64
	MaxNS      uint64
	Buckets    [len(vmBlockLatencyBucketUpperNS)]uint64
	ReadOps    uint64
	WriteOps   uint64
	FlushOps   uint64
	DiscardOps uint64
	UnknownOps uint64
}

type vmBlockIssueValue struct {
	TimestampNS        uint64
	CgroupID           uint64
	Major              uint32
	Minor              uint32
	Operation          uint8
	DeviceAvailable    uint8
	OwnershipAvailable uint8
	Reserved           uint8
	Padding            uint32
}

type vmBlockCgroupDeviceOperationKey struct {
	CgroupID  uint64
	Major     uint32
	Minor     uint32
	Operation uint32
	Padding   uint32
}

type vmBlockDeviceOperationKey struct {
	Major     uint32
	Minor     uint32
	Operation uint32
}

func mergeVMBlockPerCPULatency(values []vmBlockLatencyValues) VMBlockKernelLatency {
	var result VMBlockKernelLatency
	for _, value := range values {
		if value.Count > 0 && (result.Count == 0 || value.MinNS < result.MinNS) {
			result.MinNS = value.MinNS
		}
		if value.MaxNS > result.MaxNS {
			result.MaxNS = value.MaxNS
		}
		result.Count = saturatingAdd(result.Count, value.Count)
		result.TotalNS = saturatingAdd(result.TotalNS, value.TotalNS)
		for index, count := range value.Buckets {
			result.Buckets[index] = saturatingAdd(result.Buckets[index], count)
		}
		result.ReadOps = saturatingAdd(result.ReadOps, value.ReadOps)
		result.WriteOps = saturatingAdd(result.WriteOps, value.WriteOps)
		result.FlushOps = saturatingAdd(result.FlushOps, value.FlushOps)
		result.DiscardOps = saturatingAdd(result.DiscardOps, value.DiscardOps)
		result.UnknownOps = saturatingAdd(result.UnknownOps, value.UnknownOps)
	}
	return result
}

func vmBlockOperationName(operation uint32) string {
	switch operation {
	case 0:
		return "read"
	case 1:
		return "write"
	case 2:
		return "flush"
	case 3:
		return "discard"
	default:
		return "unknown"
	}
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
