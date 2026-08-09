package ebpf

import (
	"bytes"
	"encoding/binary"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTracepointAttachmentsUseOneDistinctFDPerTracepoint(t *testing.T) {
	nextFD := 100
	setPrograms := make(map[int][]uintptr)
	closed := make(map[int]int)
	operations := perfEventOperations{
		open: func(_ uint64, _ int) (int, error) {
			fd := nextFD
			nextFD++
			return fd, nil
		},
		ioctl: func(fd int, request, argument uintptr) error {
			if request == perfEventIOCSetBPF {
				setPrograms[fd] = append(setPrograms[fd], argument)
			}
			return nil
		},
		close: func(fd int) error {
			closed[fd]++
			return nil
		},
	}

	issue, err := attachTracepointProgramWithOperations(111, 21, 0, operations)
	if err != nil {
		t.Fatal(err)
	}
	defer issue.close()
	complete, err := attachTracepointProgramWithOperations(112, 22, 0, operations)
	if err != nil {
		t.Fatal(err)
	}
	defer complete.close()

	if issue.fd == complete.fd {
		t.Fatalf("issue and complete share perf event FD %d", issue.fd)
	}
	if len(setPrograms[issue.fd]) != 1 || setPrograms[issue.fd][0] != 21 {
		t.Fatalf("issue FD program assignments = %v", setPrograms[issue.fd])
	}
	if len(setPrograms[complete.fd]) != 1 || setPrograms[complete.fd][0] != 22 {
		t.Fatalf("complete FD program assignments = %v", setPrograms[complete.fd])
	}

	issueFD, completeFD := issue.fd, complete.fd
	issue.close()
	issue.close()
	complete.close()
	complete.close()
	if closed[issueFD] != 1 || closed[completeFD] != 1 {
		t.Fatalf("close counts = %v, want one close per FD", closed)
	}
}

func TestTracepointAttachClosesFDWhenSetProgramFails(t *testing.T) {
	closed := 0
	operations := perfEventOperations{
		open: func(_ uint64, _ int) (int, error) { return 55, nil },
		ioctl: func(_ int, _ uintptr, _ uintptr) error {
			return syscall.EEXIST
		},
		close: func(fd int) error {
			if fd != 55 {
				t.Fatalf("closed FD = %d, want 55", fd)
			}
			closed++
			return nil
		},
	}
	attachment, err := attachTracepointProgramWithOperations(111, 21, 0, operations)
	if err == nil || !strings.Contains(err.Error(), "file exists") {
		t.Fatalf("attach error = %v", err)
	}
	if attachment != nil || closed != 1 {
		t.Fatalf("attachment = %#v, closed = %d", attachment, closed)
	}
}

func TestLatencyProgramsUseConfiguredDevAndSectorOffsets(t *testing.T) {
	fields := tracepointKeyFields{
		dev:    TracepointField{Name: "dev", Offset: 8, Size: 4},
		sector: TracepointField{Name: "sector", Offset: 16, Size: 8},
	}
	issue, err := issueLatencyProgram(7, fields)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := completeLatencyProgram(7, 8, fields)
	if err != nil {
		t.Fatal(err)
	}
	for name, instructions := range map[string][]bpfInstruction{"issue": issue, "complete": complete} {
		if instructions[1].Code != 0x61 || instructions[1].Off != 8 {
			t.Errorf("%s dev load = %#v", name, instructions[1])
		}
		if instructions[3].Code != 0x79 || instructions[3].Off != 16 {
			t.Errorf("%s sector load = %#v", name, instructions[3])
		}
		for _, instruction := range instructions {
			if instruction.Code == 0x85 && instruction.Imm != bpfFuncMapLookupElem && instruction.Imm != bpfFuncMapUpdateElem && instruction.Imm != bpfFuncMapDeleteElem && instruction.Imm != bpfFuncKTimeGetNS {
				t.Errorf("%s program uses unexpected helper %d", name, instruction.Imm)
			}
		}
	}
}

func TestKeyFieldsRequiresDevAndSector(t *testing.T) {
	_, err := keyFields(TracepointFormat{
		Name:   "block_rq_issue",
		Fields: []TracepointField{{Name: "dev", Offset: 8, Size: 4}},
	})
	if err == nil || !strings.Contains(err.Error(), "does not expose both dev and sector") {
		t.Fatalf("keyFields() error = %v", err)
	}
}

func TestParseCPUList(t *testing.T) {
	cpus, err := parseCPUList("0-2,4,6-7\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{0, 1, 2, 4, 6, 7}
	if len(cpus) != len(want) {
		t.Fatalf("CPUs = %v, want %v", cpus, want)
	}
	for index := range want {
		if cpus[index] != want[index] {
			t.Fatalf("CPUs = %v, want %v", cpus, want)
		}
	}
}

func TestAggregateLatencyStats(t *testing.T) {
	stride := (latencyStatsValueSize + 7) &^ 7
	data := make([]byte, stride*2)
	putLatencyStats := func(cpu int, count, total, max uint64, buckets map[int]uint64) {
		value := data[cpu*stride:]
		binary.NativeEndian.PutUint64(value[0:8], count)
		binary.NativeEndian.PutUint64(value[8:16], total)
		binary.NativeEndian.PutUint64(value[16:24], max)
		for bucket, count := range buckets {
			offset := 24 + bucket*8
			binary.NativeEndian.PutUint64(value[offset:offset+8], count)
		}
	}
	putLatencyStats(0, 2, 150_000, 100_000, map[int]uint64{2: 2})
	putLatencyStats(1, 1, 150_000, 150_000, map[int]uint64{3: 1})

	result, err := aggregateLatencyStats(10*time.Second, data, 2)
	if err != nil {
		t.Fatal(err)
	}
	if result.CompletedRequests != 3 || result.TotalLatencyNS != 300_000 || result.MaxLatencyNS != 150_000 {
		t.Fatalf("result = %#v", result)
	}
	if result.Histogram[2] != 2 || result.Histogram[3] != 1 {
		t.Fatalf("histogram = %v", result.Histogram)
	}
}

func TestWriteBlockLatency(t *testing.T) {
	result := BlockLatencyResult{
		Duration:          10 * time.Second,
		CompletedRequests: 3,
		TotalLatencyNS:    300_000,
		MaxLatencyNS:      150_000,
	}
	result.Histogram[2] = 2
	result.Histogram[3] = 1
	var output bytes.Buffer
	if err := WriteBlockLatency(&output, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Solis eBPF Block Latency",
		"Duration:                 10s",
		"Total completed requests:  3",
		"Average latency:           100.00 us",
		"Max latency:               150.00 us",
		"50-99 us",
		"66.67%",
		"100 ms+",
		"no payloads or process memory inspected",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "VM-aware context") {
		t.Fatalf("host-wide output unexpectedly contains VM-aware context:\n%s", output.String())
	}
}

func TestLatencyHistogramStructuredValues(t *testing.T) {
	result := BlockLatencyResult{CompletedRequests: 4, TotalLatencyNS: 200_000}
	result.Histogram[0] = 1
	result.Histogram[1] = 3
	buckets := LatencyHistogram(result)
	if len(buckets) != 10 {
		t.Fatalf("bucket count = %d, want 10", len(buckets))
	}
	if buckets[0].Range != "< 10 us" || buckets[0].Requests != 1 || buckets[0].Percent != 25 {
		t.Fatalf("first bucket = %#v", buckets[0])
	}
	if buckets[1].Range != "10-49 us" || buckets[1].Requests != 3 || buckets[1].Percent != 75 {
		t.Fatalf("second bucket = %#v", buckets[1])
	}
	if got := AverageLatencyMicroseconds(result); got != 50 {
		t.Fatalf("average latency = %v us, want 50", got)
	}
}

func TestLatencyOperationErrorIncludesVerifierAndPermissionGuidance(t *testing.T) {
	verifierError := latencyOperationError("load latency program", "block_rq_complete", syscall.EINVAL, "invalid access to context")
	for _, want := range []string{"load latency program", "block:block_rq_complete", "verifier log", "invalid access to context"} {
		if !strings.Contains(verifierError.Error(), want) {
			t.Errorf("verifier error missing %q: %v", want, verifierError)
		}
	}
	permissionError := latencyOperationError("load latency program", "block_rq_issue", syscall.EPERM, "")
	if permissionError.Error() != "permission denied loading or attaching eBPF block latency programs; try running with sudo" {
		t.Fatalf("permission error = %q", permissionError)
	}
}
