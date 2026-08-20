package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	bpfMapTypeLRUHash      = 9
	bpfMapTypePerCPUArray  = 6
	bpfProgTracepoint      = 5
	bpfFuncMapUpdateElem   = 2
	bpfFuncMapDeleteElem   = 3
	bpfFuncKTimeGetNS      = 5
	latencyStartEntries    = 65536
	latencyBucketCount     = 10
	latencyStatsValueSize  = (3 + latencyBucketCount) * 8
	perfTypeTracepoint     = 2
	perfAttrSizeVersion0   = 64
	perfFlagFDCloseOnExec  = 1 << 3
	perfEventIOCEnable     = 0x2400
	perfEventIOCDisable    = 0x2401
	perfEventIOCSetBPF     = 0x40042408
	defaultCPUOnlinePath   = "/sys/devices/system/cpu/online"
	defaultCPUPossiblePath = "/sys/devices/system/cpu/possible"
)

var (
	latencyBucketUpperNS = []uint64{
		10_000,
		50_000,
		100_000,
		500_000,
		1_000_000,
		5_000_000,
		10_000_000,
		50_000_000,
		100_000_000,
	}
	latencyBucketLabels = []string{
		"< 10 us",
		"10-49 us",
		"50-99 us",
		"100-499 us",
		"500-999 us",
		"1-4.999 ms",
		"5-9.999 ms",
		"10-49.999 ms",
		"50-99.999 ms",
		"100 ms+",
	}
	errBPFLatencyPermission = errors.New("permission denied loading or attaching eBPF block latency programs; try running with sudo")
)

// BlockLatencyResult contains a host-wide block request latency summary.
type BlockLatencyResult struct {
	Duration          time.Duration
	CompletedRequests uint64
	TotalLatencyNS    uint64
	MaxLatencyNS      uint64
	Histogram         [latencyBucketCount]uint64
}

type tracepointKeyFields struct {
	dev    TracepointField
	sector TracepointField
}

type instructionFixup struct {
	index int
	label string
}

type instructionBuilder struct {
	instructions []bpfInstruction
	labels       map[string]int
	fixups       []instructionFixup
}

type perfAttachment struct {
	fd  int
	ops perfEventOperations
}

type perfEventOperations struct {
	open  func(eventID uint64, cpu int) (int, error)
	ioctl func(fd int, request, argument uintptr) error
	close func(fd int) error
}

var systemPerfEventOperations = perfEventOperations{
	open:  openTracepointPerfEvent,
	ioctl: perfEventIOCTL,
	close: syscall.Close,
}

// MeasureBlockLatency temporarily attaches issue and completion tracepoint
// programs, then returns a host-wide latency histogram. Tracepoint payloads are
// used only for the dev+sector correlation key and are never sent to userspace.
func MeasureBlockLatency(duration time.Duration) (BlockLatencyResult, error) {
	if duration <= 0 {
		return BlockLatencyResult{}, errors.New("block latency duration must be positive")
	}
	formats, err := LoadBlockFormats()
	if err != nil {
		return BlockLatencyResult{}, err
	}
	issueFormat, err := findTracepointFormat(formats, "block_rq_issue")
	if err != nil {
		return BlockLatencyResult{}, err
	}
	completeFormat, err := findTracepointFormat(formats, "block_rq_complete")
	if err != nil {
		return BlockLatencyResult{}, err
	}
	issueFields, err := keyFields(issueFormat)
	if err != nil {
		return BlockLatencyResult{}, err
	}
	completeFields, err := keyFields(completeFormat)
	if err != nil {
		return BlockLatencyResult{}, err
	}

	onlineCPUs, possibleCPUCount, err := hostCPUConfiguration(defaultCPUOnlinePath, defaultCPUPossiblePath)
	if err != nil {
		return BlockLatencyResult{}, err
	}
	startMapFD, err := createBPFMap(bpfMapTypeLRUHash, 16, 8, latencyStartEntries, "solis_lat_start")
	if err != nil {
		return BlockLatencyResult{}, latencyOperationError("create issue timestamp map", "block_rq_issue", err, "")
	}
	defer syscall.Close(startMapFD)
	statsMapFD, err := createBPFMap(bpfMapTypePerCPUArray, 4, latencyStatsValueSize, 1, "solis_lat_stat")
	if err != nil {
		return BlockLatencyResult{}, latencyOperationError("create latency statistics map", "block_rq_complete", err, "")
	}
	defer syscall.Close(statsMapFD)

	issueInstructions, err := issueLatencyProgram(startMapFD, issueFields)
	if err != nil {
		return BlockLatencyResult{}, err
	}
	completeInstructions, err := completeLatencyProgram(startMapFD, statsMapFD, completeFields)
	if err != nil {
		return BlockLatencyResult{}, err
	}
	issueProgramFD, verifierLog, err := loadTracepointProgram(issueInstructions, "solis_lat_issue")
	if err != nil {
		return BlockLatencyResult{}, latencyOperationError("load latency program", "block_rq_issue", err, verifierLog)
	}
	defer syscall.Close(issueProgramFD)
	completeProgramFD, verifierLog, err := loadTracepointProgram(completeInstructions, "solis_lat_done")
	if err != nil {
		return BlockLatencyResult{}, latencyOperationError("load latency program", "block_rq_complete", err, verifierLog)
	}
	defer syscall.Close(completeProgramFD)

	// BPF_PROG_TYPE_TRACEPOINT registration is tracepoint-wide. One perf event
	// FD observes all CPUs; attaching the same program to additional per-CPU
	// FDs is rejected by the kernel with EEXIST.
	attachmentCPU := onlineCPUs[0]
	issueAttachment, err := attachTracepointProgram(issueFormat.ID, issueProgramFD, attachmentCPU)
	if err != nil {
		return BlockLatencyResult{}, latencyOperationError("attach latency program", "block_rq_issue", err, "")
	}
	defer issueAttachment.close()
	completeAttachment, err := attachTracepointProgram(completeFormat.ID, completeProgramFD, attachmentCPU)
	if err != nil {
		return BlockLatencyResult{}, latencyOperationError("attach latency program", "block_rq_complete", err, "")
	}
	defer completeAttachment.close()

	if err := completeAttachment.enable(); err != nil {
		return BlockLatencyResult{}, latencyOperationError("enable latency program", "block_rq_complete", err, "")
	}
	if err := issueAttachment.enable(); err != nil {
		return BlockLatencyResult{}, latencyOperationError("enable latency program", "block_rq_issue", err, "")
	}

	timer := time.NewTimer(duration)
	<-timer.C
	issueAttachment.close()
	completeAttachment.close()

	data, err := lookupPerCPUValue(statsMapFD, 0, latencyStatsValueSize, possibleCPUCount)
	if err != nil {
		return BlockLatencyResult{}, fmt.Errorf("read latency statistics: %w", err)
	}
	result, err := aggregateLatencyStats(duration, data, possibleCPUCount)
	if err != nil {
		return BlockLatencyResult{}, err
	}
	return result, nil
}

// findTracepointFormat finds tracepoint format in the available data.
func findTracepointFormat(formats []TracepointFormat, name string) (TracepointFormat, error) {
	for _, format := range formats {
		if format.Name == name || format.Name == "block:"+name {
			return format, nil
		}
	}
	return TracepointFormat{}, fmt.Errorf("tracepoint format block:%s is missing", name)
}

// keyFields builds key fields and returns an error when validation or source access fails.
func keyFields(format TracepointFormat) (tracepointKeyFields, error) {
	var fields tracepointKeyFields
	var haveDev, haveSector bool
	for _, field := range format.Fields {
		switch field.Name {
		case "dev":
			fields.dev = field
			haveDev = true
		case "sector":
			fields.sector = field
			haveSector = true
		}
	}
	if !haveDev || !haveSector {
		return tracepointKeyFields{}, fmt.Errorf("tracepoint block:%s does not expose both dev and sector fields", format.Name)
	}
	for _, field := range []TracepointField{fields.dev, fields.sector} {
		if field.Size != 1 && field.Size != 2 && field.Size != 4 && field.Size != 8 {
			return tracepointKeyFields{}, fmt.Errorf("tracepoint block:%s field %s has unsupported size %d", format.Name, field.Name, field.Size)
		}
		if field.Offset > 32767 {
			return tracepointKeyFields{}, fmt.Errorf("tracepoint block:%s field %s offset %d is too large", format.Name, field.Name, field.Offset)
		}
	}
	return fields, nil
}

// issueLatencyProgram builds the verifier-bounded instruction stream for request issue timestamps.
func issueLatencyProgram(startMapFD int, fields tracepointKeyFields) ([]bpfInstruction, error) {
	builder := newInstructionBuilder()
	builder.emit(0xbf, 6, 1, 0, 0)
	if err := builder.loadContextKey(fields); err != nil {
		return nil, err
	}
	builder.emit(0x85, 0, 0, 0, bpfFuncKTimeGetNS)
	builder.emit(0x7b, 10, 0, -24, 0)
	builder.loadMap(1, startMapFD)
	builder.emit(0xbf, 2, 10, 0, 0)
	builder.emit(0x07, 2, 0, 0, -16)
	builder.emit(0xbf, 3, 10, 0, 0)
	builder.emit(0x07, 3, 0, 0, -24)
	builder.emit(0xb7, 4, 0, 0, 0)
	builder.emit(0x85, 0, 0, 0, bpfFuncMapUpdateElem)
	builder.emit(0xb7, 0, 0, 0, 0)
	builder.emit(0x95, 0, 0, 0, 0)
	return builder.finalize()
}

// completeLatencyProgram builds complete latency program and returns an error when validation or
// source access fails.
func completeLatencyProgram(startMapFD, statsMapFD int, fields tracepointKeyFields) ([]bpfInstruction, error) {
	builder := newInstructionBuilder()
	builder.emit(0xbf, 6, 1, 0, 0)
	if err := builder.loadContextKey(fields); err != nil {
		return nil, err
	}
	builder.loadMap(1, startMapFD)
	builder.emit(0xbf, 2, 10, 0, 0)
	builder.emit(0x07, 2, 0, 0, -16)
	builder.emit(0x85, 0, 0, 0, bpfFuncMapLookupElem)
	builder.jump(0x15, 0, 0, 0, "exit")
	builder.emit(0x79, 7, 0, 0, 0)
	builder.emit(0x85, 0, 0, 0, bpfFuncKTimeGetNS)
	builder.emit(0x1f, 0, 7, 0, 0)
	builder.emit(0xbf, 7, 0, 0, 0)
	builder.loadMap(1, startMapFD)
	builder.emit(0xbf, 2, 10, 0, 0)
	builder.emit(0x07, 2, 0, 0, -16)
	builder.emit(0x85, 0, 0, 0, bpfFuncMapDeleteElem)
	builder.emit(0x62, 10, 0, -20, 0)
	builder.loadMap(1, statsMapFD)
	builder.emit(0xbf, 2, 10, 0, 0)
	builder.emit(0x07, 2, 0, 0, -20)
	builder.emit(0x85, 0, 0, 0, bpfFuncMapLookupElem)
	builder.jump(0x15, 0, 0, 0, "exit")
	builder.emit(0xbf, 8, 0, 0, 0)

	builder.emit(0x79, 1, 8, 0, 0)
	builder.emit(0x07, 1, 0, 0, 1)
	builder.emit(0x7b, 8, 1, 0, 0)
	builder.emit(0x79, 1, 8, 8, 0)
	builder.emit(0x0f, 1, 7, 0, 0)
	builder.emit(0x7b, 8, 1, 8, 0)
	builder.emit(0x79, 1, 8, 16, 0)
	builder.jump(0xbd, 7, 1, 0, "histogram")
	builder.emit(0x7b, 8, 7, 16, 0)

	builder.label("histogram")
	for index, upperNS := range latencyBucketUpperNS {
		builder.jump(0xa5, 7, 0, int32(upperNS), fmt.Sprintf("bucket_%d", index))
	}
	builder.jump(0x05, 0, 0, 0, fmt.Sprintf("bucket_%d", latencyBucketCount-1))
	for index := 0; index < latencyBucketCount; index++ {
		builder.label(fmt.Sprintf("bucket_%d", index))
		offset := int16(24 + index*8)
		builder.emit(0x79, 1, 8, offset, 0)
		builder.emit(0x07, 1, 0, 0, 1)
		builder.emit(0x7b, 8, 1, offset, 0)
		builder.jump(0x05, 0, 0, 0, "exit")
	}

	builder.label("exit")
	builder.emit(0xb7, 0, 0, 0, 0)
	builder.emit(0x95, 0, 0, 0, 0)
	return builder.finalize()
}

// newInstructionBuilder constructs instruction builder wired to the package's production
// dependencies.
func newInstructionBuilder() *instructionBuilder {
	return &instructionBuilder{labels: make(map[string]int)}
}

// emit performs emit as part of the package workflow.
func (builder *instructionBuilder) emit(code, destination, source uint8, offset int16, immediate int32) {
	builder.instructions = append(builder.instructions, bpfInstruction{
		Code: code,
		Regs: register(destination, source),
		Off:  offset,
		Imm:  immediate,
	})
}

// loadMap emits a verifier-safe map lookup instruction sequence for the selected register.
func (builder *instructionBuilder) loadMap(destination uint8, mapFD int) {
	builder.emit(0x18, destination, bpfPseudoMapFD, 0, int32(mapFD))
	builder.emit(0, 0, 0, 0, 0)
}

// loadContextKey emits the architecture-specific tracepoint context load for the request identity.
func (builder *instructionBuilder) loadContextKey(fields tracepointKeyFields) error {
	for _, field := range []struct {
		value       TracepointField
		stackOffset int16
	}{
		{fields.dev, -16},
		{fields.sector, -8},
	} {
		code, err := contextLoadCode(field.value.Size)
		if err != nil {
			return err
		}
		builder.emit(code, 2, 6, int16(field.value.Offset), 0)
		builder.emit(0x7b, 10, 2, field.stackOffset, 0)
	}
	return nil
}

// contextLoadCode builds context load code and returns an error when validation or source access
// fails.
func contextLoadCode(size uint64) (uint8, error) {
	switch size {
	case 1:
		return 0x71, nil
	case 2:
		return 0x69, nil
	case 4:
		return 0x61, nil
	case 8:
		return 0x79, nil
	default:
		return 0, fmt.Errorf("unsupported tracepoint field size %d", size)
	}
}

// jump performs jump as part of the package workflow.
func (builder *instructionBuilder) jump(code, destination, source uint8, immediate int32, label string) {
	builder.fixups = append(builder.fixups, instructionFixup{index: len(builder.instructions), label: label})
	builder.emit(code, destination, source, 0, immediate)
}

// label performs label as part of the package workflow.
func (builder *instructionBuilder) label(name string) {
	builder.labels[name] = len(builder.instructions)
}

// finalize builds finalize and returns an error when validation or source access fails.
func (builder *instructionBuilder) finalize() ([]bpfInstruction, error) {
	for _, fixup := range builder.fixups {
		target, ok := builder.labels[fixup.label]
		if !ok {
			return nil, fmt.Errorf("eBPF instruction label %q is missing", fixup.label)
		}
		offset := target - fixup.index - 1
		if offset < -32768 || offset > 32767 {
			return nil, fmt.Errorf("eBPF jump to %q is out of range", fixup.label)
		}
		builder.instructions[fixup.index].Off = int16(offset)
	}
	return builder.instructions, nil
}

// createBPFMap creates BPF map while preserving the package's security invariants.
func createBPFMap(mapType, keySize, valueSize, maxEntries uint32, name string) (int, error) {
	attr := bpfMapCreateAttr{
		MapType:    mapType,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
	}
	copy(attr.MapName[:], name)
	return bpfCall(bpfMapCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
}

// loadTracepointProgram loads one classic tracepoint program and retains bounded verifier diagnostics.
func loadTracepointProgram(instructions []bpfInstruction, name string) (int, string, error) {
	license := []byte("GPL\x00")
	logBuffer := make([]byte, 256*1024)
	attr := bpfProgramLoadAttr{
		ProgramType:      bpfProgTracepoint,
		InstructionCount: uint32(len(instructions)),
		Instructions:     uint64(uintptr(unsafe.Pointer(&instructions[0]))),
		License:          uint64(uintptr(unsafe.Pointer(&license[0]))),
		LogLevel:         1,
		LogSize:          uint32(len(logBuffer)),
		LogBuffer:        uint64(uintptr(unsafe.Pointer(&logBuffer[0]))),
	}
	copy(attr.ProgramName[:], name)
	fd, err := bpfCall(bpfProgLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(instructions)
	runtime.KeepAlive(license)
	runtime.KeepAlive(logBuffer)
	return fd, strings.TrimRight(string(logBuffer), "\x00"), err
}

// attachTracepointProgram attaches tracepoint program and returns an owned handle for cleanup.
func attachTracepointProgram(eventID uint64, programFD, cpu int) (*perfAttachment, error) {
	return attachTracepointProgramWithOperations(eventID, programFD, cpu, systemPerfEventOperations)
}

// attachTracepointProgramWithOperations attaches tracepoint program with operations and returns an
// owned handle for cleanup.
func attachTracepointProgramWithOperations(eventID uint64, programFD, cpu int, operations perfEventOperations) (*perfAttachment, error) {
	fd, err := operations.open(eventID, cpu)
	if err != nil {
		return nil, fmt.Errorf("open perf event on CPU %d: %w", cpu, err)
	}
	attachment := &perfAttachment{fd: fd, ops: operations}
	if err := operations.ioctl(fd, perfEventIOCSetBPF, uintptr(programFD)); err != nil {
		_ = operations.close(fd)
		attachment.fd = -1
		return nil, fmt.Errorf("associate eBPF program on CPU %d: %w", cpu, err)
	}
	return attachment, nil
}

// openTracepointPerfEvent opens tracepoint perf event after validating its source.
func openTracepointPerfEvent(eventID uint64, cpu int) (int, error) {
	attr := make([]byte, perfAttrSizeVersion0)
	binary.NativeEndian.PutUint32(attr[0:4], perfTypeTracepoint)
	binary.NativeEndian.PutUint32(attr[4:8], perfAttrSizeVersion0)
	binary.NativeEndian.PutUint64(attr[8:16], eventID)
	binary.NativeEndian.PutUint64(attr[16:24], 1)
	binary.NativeEndian.PutUint64(attr[40:48], 1)
	binary.NativeEndian.PutUint32(attr[48:52], 1)
	result, _, errno := syscall.Syscall6(
		syscall.SYS_PERF_EVENT_OPEN,
		uintptr(unsafe.Pointer(&attr[0])),
		^uintptr(0),
		uintptr(cpu),
		^uintptr(0),
		perfFlagFDCloseOnExec,
		0,
	)
	runtime.KeepAlive(attr)
	if errno != 0 {
		return -1, errno
	}
	return int(result), nil
}

// perfEventIOCTL completes perf event ioctl and returns any failure to its caller.
func perfEventIOCTL(fd int, request, argument uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, argument)
	if errno != 0 {
		return errno
	}
	return nil
}

// enable completes enable and returns any failure to its caller.
func (attachment *perfAttachment) enable() error {
	if attachment == nil || attachment.fd < 0 {
		return errors.New("tracepoint perf event is closed")
	}
	return attachment.ops.ioctl(attachment.fd, perfEventIOCEnable, 0)
}

// close releases the underlying descriptor and preserves cleanup errors.
func (attachment *perfAttachment) close() {
	if attachment == nil || attachment.fd < 0 {
		return
	}
	_ = attachment.ops.ioctl(attachment.fd, perfEventIOCDisable, 0)
	_ = attachment.ops.close(attachment.fd)
	attachment.fd = -1
}

// hostCPUConfiguration builds host cpu configuration and returns an error when validation or source
// access fails.
func hostCPUConfiguration(onlinePath, possiblePath string) ([]int, int, error) {
	onlineData, err := os.ReadFile(onlinePath)
	if err != nil {
		return nil, 0, fmt.Errorf("read online CPU list: %w", err)
	}
	possibleData, err := os.ReadFile(possiblePath)
	if err != nil {
		return nil, 0, fmt.Errorf("read possible CPU list: %w", err)
	}
	online, err := parseCPUList(string(onlineData))
	if err != nil {
		return nil, 0, fmt.Errorf("parse online CPU list: %w", err)
	}
	possible, err := parseCPUList(string(possibleData))
	if err != nil {
		return nil, 0, fmt.Errorf("parse possible CPU list: %w", err)
	}
	if len(online) == 0 || len(possible) == 0 {
		return nil, 0, errors.New("host CPU list is empty")
	}
	return online, possible[len(possible)-1] + 1, nil
}

// parseCPUList parses and validates cpu list.
func parseCPUList(input string) ([]int, error) {
	seen := make(map[int]bool)
	for _, part := range strings.Split(strings.TrimSpace(input), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		startText, endText, ranged := strings.Cut(part, "-")
		start, err := strconv.Atoi(startText)
		if err != nil || start < 0 {
			return nil, fmt.Errorf("invalid CPU range %q", part)
		}
		end := start
		if ranged {
			end, err = strconv.Atoi(endText)
			if err != nil || end < start {
				return nil, fmt.Errorf("invalid CPU range %q", part)
			}
		}
		for cpu := start; cpu <= end; cpu++ {
			seen[cpu] = true
		}
	}
	cpus := make([]int, 0, len(seen))
	for cpu := range seen {
		cpus = append(cpus, cpu)
	}
	sort.Ints(cpus)
	return cpus, nil
}

// lookupPerCPUValue looks up per cpu value without inventing a missing value.
func lookupPerCPUValue(mapFD int, key uint32, valueSize, cpuCount int) ([]byte, error) {
	stride := (valueSize + 7) &^ 7
	value := make([]byte, stride*cpuCount)
	attr := bpfMapElementAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(uintptr(unsafe.Pointer(&key))),
		Value: uint64(uintptr(unsafe.Pointer(&value[0]))),
	}
	_, err := bpfCall(bpfMapLookupElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(&key)
	runtime.KeepAlive(value)
	return value, err
}

// aggregateLatencyStats aggregates latency stats into its bounded summary.
func aggregateLatencyStats(duration time.Duration, data []byte, cpuCount int) (BlockLatencyResult, error) {
	stride := (latencyStatsValueSize + 7) &^ 7
	if cpuCount <= 0 || len(data) < stride*cpuCount {
		return BlockLatencyResult{}, errors.New("invalid per-CPU latency statistics buffer")
	}
	result := BlockLatencyResult{Duration: duration}
	for cpu := 0; cpu < cpuCount; cpu++ {
		value := data[cpu*stride : cpu*stride+latencyStatsValueSize]
		result.CompletedRequests += binary.NativeEndian.Uint64(value[0:8])
		result.TotalLatencyNS += binary.NativeEndian.Uint64(value[8:16])
		maxLatency := binary.NativeEndian.Uint64(value[16:24])
		if maxLatency > result.MaxLatencyNS {
			result.MaxLatencyNS = maxLatency
		}
		for bucket := 0; bucket < latencyBucketCount; bucket++ {
			offset := 24 + bucket*8
			result.Histogram[bucket] += binary.NativeEndian.Uint64(value[offset : offset+8])
		}
	}
	return result, nil
}

// latencyOperationError completes latency operation error and returns any failure to its caller.
func latencyOperationError(operation, tracepoint string, err error, verifierLog string) error {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return errBPFLatencyPermission
	}
	message := fmt.Sprintf("%s for block:%s: %v", operation, tracepoint, err)
	if strings.TrimSpace(verifierLog) != "" {
		message += "; verifier log: " + strings.TrimSpace(verifierLog)
	}
	return errors.New(message)
}
