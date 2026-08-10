package ebpf

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeVMBlockKernelSource struct {
	preflight    VMBlockKernelPreflight
	preflightErr error
	prepareErr   error
	session      *fakeVMBlockKernelSession
}

func (source *fakeVMBlockKernelSource) Preflight(context.Context) (VMBlockKernelPreflight, error) {
	return source.preflight, source.preflightErr
}

func (source *fakeVMBlockKernelSource) Prepare(context.Context, VMBlockLatencyCollectOptions, []VMBlockCgroupMapping) (VMBlockKernelSession, error) {
	if source.prepareErr != nil {
		return nil, source.prepareErr
	}
	return source.session, nil
}

type fakeVMBlockKernelSession struct {
	events     []VMBlockEvent
	stats      VMBlockKernelStats
	startErr   error
	collectErr error
	stopErr    error
	closeErr   error
	started    bool
	stopped    bool
	closed     bool
}

func (session *fakeVMBlockKernelSession) Start(context.Context) error {
	session.started = true
	return session.startErr
}

func (session *fakeVMBlockKernelSession) Collect(_ context.Context, _ time.Duration, consume func(VMBlockEvent) error) error {
	for _, event := range session.events {
		if err := consume(event); err != nil {
			return err
		}
	}
	return session.collectErr
}

func (session *fakeVMBlockKernelSession) Stats() VMBlockKernelStats { return session.stats }
func (session *fakeVMBlockKernelSession) Stop() error {
	session.stopped = true
	return session.stopErr
}
func (session *fakeVMBlockKernelSession) Close() error {
	session.closed = true
	return session.closeErr
}

func availableFakeKernelSource(session *fakeVMBlockKernelSession) *fakeVMBlockKernelSource {
	if session.stats.CollectionMode == "" {
		session.stats.CollectionMode = "test_event_stream"
		session.stats.AttributionMethod = "request_correlated+bio_blkcg+cgroup_inode_vm_map"
		session.stats.AttributionAvailable = true
	}
	return &fakeVMBlockKernelSource{
		preflight: VMBlockKernelPreflight{Available: true, Status: "available"},
		session:   session,
	}
}

func TestExperimentalVMBlockKernelSourceIsHonestlyUnavailable(t *testing.T) {
	options := VMBlockLatencyCollectOptions{Duration: time.Second, Interval: time.Second}
	report := CollectVMBlockLatencyReportWithKernelSource(context.Background(), options, nil, experimentalVMBlockKernelSource{})
	if report.Availability.Available || report.Availability.Status != "experimental_not_implemented" {
		t.Fatalf("availability = %#v", report.Availability)
	}
	if report.HostSummary.TotalOps != 0 || report.AttributionQuality != "unavailable" || privacyCollected(report) {
		t.Fatalf("deferred source fabricated evidence: %#v", report)
	}
	if !hasUnavailableSection(report.UnavailableSections, "ebpf_attribution", "experimental_not_implemented") {
		t.Fatalf("unavailable section missing: %#v", report.UnavailableSections)
	}
}

func TestVMBlockKernelSourceLifecycleAndLossCounters(t *testing.T) {
	session := &fakeVMBlockKernelSession{
		events: []VMBlockEvent{
			{Kind: "issue", RequestPointer: 1, TimestampNS: 1, CgroupID: 11, Device: "dm-0", Operation: "write"},
			{Kind: "complete", RequestPointer: 1, TimestampNS: 2_000_001},
		},
		stats: VMBlockKernelStats{DroppedEvents: 3, RingBufferLost: 2, MapFull: 1},
	}
	report := CollectVMBlockLatencyReportWithKernelSource(
		context.Background(),
		VMBlockLatencyCollectOptions{Duration: time.Second, Interval: time.Second},
		[]VMBlockCgroupMapping{{Name: "a-web", CgroupIDs: []uint64{11}, MappingQuality: "cgroup_v2_inode_tree"}},
		availableFakeKernelSource(session),
	)
	if !session.started || !session.stopped || !session.closed {
		t.Fatalf("lifecycle = started:%v stopped:%v closed:%v", session.started, session.stopped, session.closed)
	}
	if report.HostSummary.TotalOps != 1 || report.Unattributed.DroppedEvents != 3 || report.Unattributed.RingBufferLost != 2 || report.Unattributed.MapFull != 1 {
		t.Fatalf("report = %#v", report)
	}
	if report.AttributionQuality != "unavailable" {
		t.Fatalf("quality = %q", report.AttributionQuality)
	}
}

func TestVMBlockKernelSourcePartialStartFailureCleansUp(t *testing.T) {
	session := &fakeVMBlockKernelSession{startErr: errors.New("attach complete tracepoint failed")}
	report := CollectVMBlockLatencyReportWithKernelSource(
		context.Background(),
		VMBlockLatencyCollectOptions{Duration: time.Second, Interval: time.Second},
		nil,
		availableFakeKernelSource(session),
	)
	if !session.started || session.stopped || !session.closed {
		t.Fatalf("partial-start lifecycle = started:%v stopped:%v closed:%v", session.started, session.stopped, session.closed)
	}
	if report.Availability.Available || report.Availability.Status != "start_failed" {
		t.Fatalf("availability = %#v", report.Availability)
	}
}

func TestVMBlockKernelSourceCleanupOnCollectError(t *testing.T) {
	session := &fakeVMBlockKernelSession{collectErr: errors.New("event stream failed")}
	report := CollectVMBlockLatencyReportWithKernelSource(
		context.Background(),
		VMBlockLatencyCollectOptions{Duration: time.Second, Interval: time.Second},
		nil,
		availableFakeKernelSource(session),
	)
	if !session.stopped || !session.closed {
		t.Fatalf("cleanup = stopped:%v closed:%v", session.stopped, session.closed)
	}
	if report.Availability.Available || report.Availability.Status != "collection_failed" {
		t.Fatalf("availability = %#v", report.Availability)
	}
}

func TestVMBlockKernelSourcePrimaryErrorsPrecedeCleanupWarnings(t *testing.T) {
	tests := []struct {
		name       string
		startErr   error
		collectErr error
		wantStatus string
		wantText   string
	}{
		{name: "context cancellation", collectErr: context.Canceled, wantStatus: "cancelled", wantText: "context canceled"},
		{name: "collection failure", collectErr: errors.New("event stream failed"), wantStatus: "collection_failed", wantText: "event stream failed"},
		{name: "attach failure", startErr: &VMBlockKernelStageError{Status: "attach_failed", Operation: "attach issue", Err: errors.New("attach denied")}, wantStatus: "attach_failed", wantText: "attach denied"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := &fakeVMBlockKernelSession{
				startErr: test.startErr, collectErr: test.collectErr,
				closeErr: errors.New("resource cleanup failed"),
			}
			report := CollectVMBlockLatencyReportWithKernelSource(
				context.Background(),
				VMBlockLatencyCollectOptions{Duration: time.Second, Interval: time.Second},
				nil,
				availableFakeKernelSource(session),
			)
			if report.Availability.Available || report.Availability.Status != test.wantStatus {
				t.Fatalf("availability = %#v", report.Availability)
			}
			if !strings.Contains(report.Availability.Error, test.wantText) || !strings.Contains(report.Availability.Error, "resource cleanup failed") {
				t.Fatalf("primary and cleanup errors were not preserved: %#v", report.Availability)
			}
			if !hasUnavailableSection(report.UnavailableSections, "ebpf_cleanup", "cleanup_failed") {
				t.Fatalf("cleanup unavailable section missing: %#v", report.UnavailableSections)
			}
			var rendered strings.Builder
			if err := WriteVMBlockLatencyJSON(&rendered, report); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(rendered.String(), test.wantStatus) || !strings.Contains(rendered.String(), "cleanup_failed") {
				t.Fatalf("rendered JSON lost primary or cleanup status: %s", rendered.String())
			}
		})
	}
}

func TestVMBlockKernelSourceStructuredErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status string
		text   string
	}{
		{name: "permission", err: ErrVMBlockLatencyPermission, status: "permission_denied", text: "try running with sudo"},
		{name: "unsupported", err: ErrVMBlockUnsupportedKernel, status: "unsupported_kernel", text: "unsupported kernel"},
		{name: "verifier", err: NewVMBlockVerifierError("load issue", strings.Repeat("x", maxVMBlockVerifierLogBytes+100), errors.New("EINVAL")), status: VMBlockCapabilityVerifierRejected, text: "verifier log"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &fakeVMBlockKernelSource{preflightErr: test.err}
			report := CollectVMBlockLatencyReportWithKernelSource(context.Background(), VMBlockLatencyCollectOptions{
				Duration: time.Second, Interval: time.Second, effectiveUID: func() int { return 1000 },
			}, nil, source)
			if report.Availability.Status != test.status || !strings.Contains(report.Availability.Error, test.text) {
				t.Fatalf("availability = %#v", report.Availability)
			}
		})
	}
	verifier := NewVMBlockVerifierError("load", strings.Repeat("x", maxVMBlockVerifierLogBytes+100), errors.New("EINVAL"))
	if len(verifier.Log) != maxVMBlockVerifierLogBytes || !strings.HasSuffix(verifier.Log, "... (truncated)") {
		t.Fatalf("verifier log was not bounded clearly: length=%d", len(verifier.Log))
	}
}

func TestVMBlockKernelSourceFakeErrorEvents(t *testing.T) {
	tests := []struct {
		name   string
		events []VMBlockEvent
		check  func(VMBlockLatencyUnattributed) uint64
	}{
		{name: "duplicate issue", events: []VMBlockEvent{{Kind: "issue", RequestPointer: 1, TimestampNS: 1, CgroupID: 11, Operation: "write"}, {Kind: "issue", RequestPointer: 1, TimestampNS: 2, CgroupID: 11, Operation: "write"}}, check: func(value VMBlockLatencyUnattributed) uint64 { return value.DuplicateIssue }},
		{name: "lookup miss", events: []VMBlockEvent{{Kind: "complete", RequestPointer: 99, TimestampNS: 2}}, check: func(value VMBlockLatencyUnattributed) uint64 { return value.LookupMiss }},
		{name: "missing bio", events: []VMBlockEvent{{Kind: "issue", RequestPointer: 1, TimestampNS: 1, MissingBio: true}}, check: func(value VMBlockLatencyUnattributed) uint64 { return value.MissingBio }},
		{name: "missing blkcg", events: []VMBlockEvent{{Kind: "issue", RequestPointer: 1, TimestampNS: 1, MissingBlkcg: true}}, check: func(value VMBlockLatencyUnattributed) uint64 { return value.MissingBlkcg }},
		{name: "unmapped cgroup", events: []VMBlockEvent{{Kind: "issue", RequestPointer: 1, TimestampNS: 1, CgroupID: 99, Operation: "write"}, {Kind: "complete", RequestPointer: 1, TimestampNS: 2}}, check: func(value VMBlockLatencyUnattributed) uint64 { return value.UnmappedCgroup }},
		{name: "unsupported request", events: []VMBlockEvent{{Kind: "issue", RequestPointer: 1, TimestampNS: 1, UnsupportedRequest: true}}, check: func(value VMBlockLatencyUnattributed) uint64 { return value.UnsupportedRequest }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := &fakeVMBlockKernelSession{events: test.events}
			report := CollectVMBlockLatencyReportWithKernelSource(
				context.Background(), VMBlockLatencyCollectOptions{Duration: time.Second, Interval: time.Second},
				[]VMBlockCgroupMapping{{Name: "a-web", CgroupIDs: []uint64{11}, MappingQuality: "cgroup_v2_inode_tree"}}, availableFakeKernelSource(session),
			)
			if test.check(report.Unattributed) == 0 {
				t.Fatalf("counter missing: %#v", report.Unattributed)
			}
		})
	}
}
