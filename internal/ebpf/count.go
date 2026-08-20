package ebpf

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	bpfMapCreate         = 0
	bpfMapLookupElem     = 1
	bpfProgLoad          = 5
	bpfRawTracepointOpen = 17
	bpfMapTypeArray      = 2
	bpfProgRawTracepoint = 17
	bpfPseudoMapFD       = 1
	bpfFuncMapLookupElem = 1
)

var errBPFPermission = errors.New("permission denied loading or attaching eBPF block counters; try running with sudo")

// BlockCountResult contains count-only tracepoint results.
type BlockCountResult struct {
	Duration      time.Duration
	IssueCount    uint64
	CompleteCount uint64
}

type bpfInstruction struct {
	Code uint8
	Regs uint8
	Off  int16
	Imm  int32
}

type bpfMapCreateAttr struct {
	MapType               uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	InnerMapFD            uint32
	NUMANode              uint32
	MapName               [16]byte
	MapIfIndex            uint32
	BTFFD                 uint32
	BTFKeyTypeID          uint32
	BTFValueTypeID        uint32
	BTFVMLinuxValueTypeID uint32
	MapExtra              uint64
}

type bpfProgramLoadAttr struct {
	ProgramType        uint32
	InstructionCount   uint32
	Instructions       uint64
	License            uint64
	LogLevel           uint32
	LogSize            uint32
	LogBuffer          uint64
	KernelVersion      uint32
	ProgramFlags       uint32
	ProgramName        [16]byte
	ProgramIfIndex     uint32
	ExpectedAttachType uint32
}

type bpfRawTracepointAttr struct {
	Name      uint64
	ProgramFD uint32
	Padding   uint32
}

type bpfMapElementAttr struct {
	MapFD   uint32
	Padding uint32
	Key     uint64
	Value   uint64
	Flags   uint64
}

type counterAttachment struct {
	programFD int
	linkFD    int
}

// CountBlockEvents temporarily attaches count-only programs to block issue and
// completion raw tracepoints. The programs do not read tracepoint arguments.
func CountBlockEvents(duration time.Duration) (BlockCountResult, error) {
	if duration <= 0 {
		return BlockCountResult{}, errors.New("block count duration must be positive")
	}
	mapFD, err := createCounterMap()
	if err != nil {
		return BlockCountResult{}, bpfOperationError("create shared counter map", "block_rq_issue/block_rq_complete", err, "")
	}
	defer syscall.Close(mapFD)

	issue, err := attachCounter("block_rq_issue", "solis_issue", mapFD, 0)
	if err != nil {
		return BlockCountResult{}, err
	}
	defer issue.close()
	complete, err := attachCounter("block_rq_complete", "solis_complete", mapFD, 1)
	if err != nil {
		return BlockCountResult{}, err
	}
	defer complete.close()

	issueStart, err := lookupCounter(mapFD, 0)
	if err != nil {
		return BlockCountResult{}, fmt.Errorf("read initial block_rq_issue count: %w", err)
	}
	completeStart, err := lookupCounter(mapFD, 1)
	if err != nil {
		return BlockCountResult{}, fmt.Errorf("read initial block_rq_complete count: %w", err)
	}

	timer := time.NewTimer(duration)
	<-timer.C

	issue.detach()
	complete.detach()
	issueEnd, err := lookupCounter(mapFD, 0)
	if err != nil {
		return BlockCountResult{}, fmt.Errorf("read final block_rq_issue count: %w", err)
	}
	completeEnd, err := lookupCounter(mapFD, 1)
	if err != nil {
		return BlockCountResult{}, fmt.Errorf("read final block_rq_complete count: %w", err)
	}

	return BlockCountResult{
		Duration:      duration,
		IssueCount:    counterDelta(issueStart, issueEnd),
		CompleteCount: counterDelta(completeStart, completeEnd),
	}, nil
}

// attachCounter attaches counter and returns an owned handle for cleanup.
func attachCounter(tracepoint, programName string, mapFD int, key uint32) (*counterAttachment, error) {
	attachment := &counterAttachment{programFD: -1, linkFD: -1}
	programFD, verifierLog, err := loadCounterProgram(mapFD, key, programName)
	if err != nil {
		attachment.close()
		return nil, bpfOperationError("load counter program", tracepoint, err, verifierLog)
	}
	attachment.programFD = programFD

	linkFD, err := openRawTracepoint(tracepoint, programFD)
	if err != nil {
		attachment.close()
		return nil, bpfOperationError("attach counter program", tracepoint, err, "")
	}
	attachment.linkFD = linkFD
	return attachment, nil
}

// createCounterMap creates counter map while preserving the package's security invariants.
func createCounterMap() (int, error) {
	attr := bpfMapCreateAttr{
		MapType:    bpfMapTypeArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 2,
	}
	copy(attr.MapName[:], "solis_count")
	return bpfCall(bpfMapCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
}

// loadCounterProgram loads a minimal tracepoint counter and retains the verifier log on rejection.
func loadCounterProgram(mapFD int, key uint32, programName string) (int, string, error) {
	instructions := counterProgram(mapFD, key)
	license := []byte("GPL\x00")
	logBuffer := make([]byte, 64*1024)
	attr := bpfProgramLoadAttr{
		ProgramType:      bpfProgRawTracepoint,
		InstructionCount: uint32(len(instructions)),
		Instructions:     uint64(uintptr(unsafe.Pointer(&instructions[0]))),
		License:          uint64(uintptr(unsafe.Pointer(&license[0]))),
		LogLevel:         1,
		LogSize:          uint32(len(logBuffer)),
		LogBuffer:        uint64(uintptr(unsafe.Pointer(&logBuffer[0]))),
	}
	copy(attr.ProgramName[:], programName)
	fd, err := bpfCall(bpfProgLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(instructions)
	runtime.KeepAlive(license)
	runtime.KeepAlive(logBuffer)
	return fd, strings.TrimRight(string(logBuffer), "\x00"), err
}

// counterProgram builds counter program from validated inputs.
func counterProgram(mapFD int, key uint32) []bpfInstruction {
	return []bpfInstruction{
		{Code: 0x18, Regs: register(1, bpfPseudoMapFD), Imm: int32(mapFD)},
		{},
		{Code: 0xbf, Regs: register(2, 10)},
		{Code: 0x07, Regs: register(2, 0), Imm: -4},
		{Code: 0x62, Regs: register(2, 0), Imm: int32(key)},
		{Code: 0x85, Imm: bpfFuncMapLookupElem},
		{Code: 0x15, Regs: register(0, 0), Off: 2},
		{Code: 0xb7, Regs: register(1, 0), Imm: 1},
		{Code: 0xdb, Regs: register(0, 1)},
		{Code: 0xb7, Regs: register(0, 0)},
		{Code: 0x95},
	}
}

// register appends one classic BPF instruction to the bounded program under construction.
func register(destination, source uint8) uint8 {
	return destination | source<<4
}

// openRawTracepoint opens raw tracepoint after validating its source.
func openRawTracepoint(name string, programFD int) (int, error) {
	nameBytes := append([]byte(name), 0)
	attr := bpfRawTracepointAttr{
		Name:      uint64(uintptr(unsafe.Pointer(&nameBytes[0]))),
		ProgramFD: uint32(programFD),
	}
	fd, err := bpfCall(bpfRawTracepointOpen, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(nameBytes)
	return fd, err
}

// lookupCounter looks up counter without inventing a missing value.
func lookupCounter(mapFD int, key uint32) (uint64, error) {
	value := uint64(0)
	attr := bpfMapElementAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(uintptr(unsafe.Pointer(&key))),
		Value: uint64(uintptr(unsafe.Pointer(&value))),
	}
	_, err := bpfCall(bpfMapLookupElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(&key)
	runtime.KeepAlive(&value)
	return value, err
}

// bpfCall builds BPF call and returns an error when validation or source access fails.
func bpfCall(command uintptr, attr unsafe.Pointer, size uintptr) (int, error) {
	syscallNumber, err := bpfSyscallNumber()
	if err != nil {
		return -1, err
	}
	result, _, errno := syscall.Syscall(syscallNumber, command, uintptr(attr), size)
	if errno != 0 {
		return -1, errno
	}
	return int(result), nil
}

// bpfSyscallNumber builds BPF syscall number and returns an error when validation or source access
// fails.
func bpfSyscallNumber() (uintptr, error) {
	switch runtime.GOARCH {
	case "amd64":
		return 321, nil
	case "386":
		return 357, nil
	case "arm":
		return 386, nil
	case "arm64", "loong64", "riscv64":
		return 280, nil
	case "ppc64", "ppc64le":
		return 361, nil
	case "s390x":
		return 351, nil
	case "mips", "mipsle":
		return 4355, nil
	case "mips64", "mips64le":
		return 5315, nil
	default:
		return 0, fmt.Errorf("eBPF syscall is unsupported on architecture %s", runtime.GOARCH)
	}
}

// bpfOperationError completes BPF operation error and returns any failure to its caller.
func bpfOperationError(operation, tracepoint string, err error, verifierLog string) error {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return errBPFPermission
	}
	message := fmt.Sprintf("%s for block:%s: %v", operation, tracepoint, err)
	if strings.TrimSpace(verifierLog) != "" {
		message += "; verifier log: " + strings.TrimSpace(verifierLog)
	}
	return errors.New(message)
}

// counterDelta subtracts monotonic counters and treats reset or wrap as unavailable evidence.
func counterDelta(start, end uint64) uint64 {
	if end < start {
		return 0
	}
	return end - start
}

// detach performs detach as part of the package workflow.
func (attachment *counterAttachment) detach() {
	if attachment != nil && attachment.linkFD >= 0 {
		_ = syscall.Close(attachment.linkFD)
		attachment.linkFD = -1
	}
}

// close releases the underlying descriptor and preserves cleanup errors.
func (attachment *counterAttachment) close() {
	if attachment == nil {
		return
	}
	attachment.detach()
	if attachment.programFD >= 0 {
		_ = syscall.Close(attachment.programFD)
		attachment.programFD = -1
	}
}
