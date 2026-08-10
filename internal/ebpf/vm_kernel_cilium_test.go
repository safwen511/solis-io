package ebpf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
)

type fakeVMBlockObjectLoader struct {
	resources vmBlockCountResources
	err       error
	loaded    bool
}

func (loader *fakeVMBlockObjectLoader) Load(object []byte) (vmBlockCountResources, error) {
	loader.loaded = len(object) > 0
	return loader.resources, loader.err
}

type fakeVMBlockCountResources struct {
	issueLink        *fakeVMBlockLink
	completeLink     *fakeVMBlockLink
	issueErr         error
	completeErr      error
	counters         VMBlockKernelCounters
	counterErr       error
	closeErr         error
	closed           bool
	attachIssueCalls int
	attachDoneCalls  int
}

func (resources *fakeVMBlockCountResources) AttachIssue() (io.Closer, error) {
	resources.attachIssueCalls++
	if resources.issueErr != nil {
		return nil, resources.issueErr
	}
	if resources.issueLink == nil {
		resources.issueLink = &fakeVMBlockLink{}
	}
	return resources.issueLink, nil
}

func (resources *fakeVMBlockCountResources) AttachComplete() (io.Closer, error) {
	resources.attachDoneCalls++
	if resources.completeErr != nil {
		return nil, resources.completeErr
	}
	if resources.completeLink == nil {
		resources.completeLink = &fakeVMBlockLink{}
	}
	return resources.completeLink, nil
}

func (resources *fakeVMBlockCountResources) ReadCounters() (VMBlockKernelCounters, error) {
	return resources.counters, resources.counterErr
}

func (resources *fakeVMBlockCountResources) Close() error {
	resources.closed = true
	return resources.closeErr
}

type fakeVMBlockLink struct {
	closed bool
	err    error
}

type fakeVMBlockBTFTypeFinder struct {
	missing map[string]error
	lookups []string
	types   []any
}

func (finder *fakeVMBlockBTFTypeFinder) TypeByName(name string, target any) error {
	finder.lookups = append(finder.lookups, name)
	finder.types = append(finder.types, target)
	if err := finder.missing[name]; err != nil {
		return err
	}
	return nil
}

func (link *fakeVMBlockLink) Close() error {
	link.closed = true
	return link.err
}

func fakeCiliumVMBlockSource(resources vmBlockCountResources) (*ciliumVMBlockKernelSource, *fakeVMBlockObjectLoader) {
	loader := &fakeVMBlockObjectLoader{resources: resources}
	return &ciliumVMBlockKernelSource{
		platform:       "linux",
		architecture:   "amd64",
		probeBTF:       func() error { return nil },
		objectProvider: func() ([]byte, error) { return []byte("authentic-object-fixture-boundary"), nil },
		loader:         loader,
	}, loader
}

func TestCiliumVMBlockUnsupportedEndianness(t *testing.T) {
	source, _ := fakeCiliumVMBlockSource(&fakeVMBlockCountResources{})
	source.architecture = "s390x"
	report := collectCountOnlyTestReport(source, nil)
	if report.Availability.Available || report.Availability.Status != "unsupported_endianness" {
		t.Fatalf("availability = %#v", report.Availability)
	}
	if !strings.Contains(report.Availability.Error, "little-endian") || report.KernelCounters != (VMBlockKernelCounters{}) {
		t.Fatalf("unsupported-endianness report = %#v", report)
	}
}

func TestCiliumVMBlockGeneratedObjectUnavailable(t *testing.T) {
	source := &ciliumVMBlockKernelSource{
		platform:       "linux",
		architecture:   "amd64",
		probeBTF:       func() error { return nil },
		objectProvider: func() ([]byte, error) { return nil, ErrVMBlockObjectUnavailable },
		loader:         &fakeVMBlockObjectLoader{},
	}
	report := collectCountOnlyTestReport(source, []VMBlockCgroupMapping{{
		Name: "a-web", MappingQuality: "cgroup_v2_inode_tree", CgroupIDs: []uint64{11},
	}})
	if report.Availability.Available || report.Availability.Status != "object_unavailable" || report.HostSummary.TotalOps != 0 {
		t.Fatalf("report = %#v", report)
	}
	if report.KernelCounters != (VMBlockKernelCounters{}) || privacyCollected(report) {
		t.Fatalf("unavailable source fabricated counters/privacy: %#v", report)
	}
	if len(report.VMs) != 1 || report.VMs[0].TotalOps != 0 || report.VMs[0].LatencyAvgMS != 0 || report.VMs[0].AttributionQuality != "unavailable" {
		t.Fatalf("unavailable source fabricated VM attribution: %#v", report.VMs)
	}
}

func TestCiliumVMBlockBTFMissing(t *testing.T) {
	source, _ := fakeCiliumVMBlockSource(&fakeVMBlockCountResources{})
	source.probeBTF = func() error { return ErrVMBlockBTFMissing }
	report := collectCountOnlyTestReport(source, nil)
	if report.Availability.Status != VMBlockCapabilityBTFMissing || !strings.Contains(report.Availability.Error, "BTF") {
		t.Fatalf("availability = %#v", report.Availability)
	}
}

func TestResolveVMBlockTypedTracepointsUsesKernelTypedefNames(t *testing.T) {
	finder := &fakeVMBlockBTFTypeFinder{}
	if err := resolveVMBlockTypedTracepoints(finder); err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"btf_trace_block_rq_issue", "btf_trace_block_rq_complete"}
	if fmt.Sprint(finder.lookups) != fmt.Sprint(wantNames) {
		t.Fatalf("lookups = %v, want %v", finder.lookups, wantNames)
	}
	for _, target := range finder.types {
		if _, ok := target.(**btf.Typedef); !ok {
			t.Fatalf("BTF target type = %T, want **btf.Typedef", target)
		}
	}
}

func TestResolveVMBlockTypedTracepointsMissingIsStructured(t *testing.T) {
	finder := &fakeVMBlockBTFTypeFinder{missing: map[string]error{
		"btf_trace_block_rq_complete": btf.ErrNotFound,
	}}
	err := resolveVMBlockTypedTracepoints(finder)
	if vmBlockStageStatus(err, "") != "typed_tracepoint_missing" || !strings.Contains(err.Error(), "block_rq_complete") {
		t.Fatalf("error = %v", err)
	}
}

func TestCiliumVMBlockPermissionAndVerifierErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status string
	}{
		{name: "permission", err: os.ErrPermission, status: "permission_denied"},
		{name: "verifier", err: NewVMBlockVerifierError("load", strings.Repeat("v", maxVMBlockVerifierLogBytes+500), errors.New("rejected")), status: VMBlockCapabilityVerifierRejected},
		{name: "BTF incompatible", err: fmt.Errorf("CO-RE relocation: %w", btf.ErrNotFound), status: "btf_incompatible"},
		{name: "generic load failure", err: errors.New("load collection failed"), status: "object_load_failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, loader := fakeCiliumVMBlockSource(nil)
			loader.err = test.err
			report := collectCountOnlyTestReport(source, nil)
			if report.Availability.Status != test.status || report.Availability.Available {
				t.Fatalf("availability = %#v", report.Availability)
			}
			if test.status == VMBlockCapabilityVerifierRejected && len(report.Availability.Error) > maxVMBlockVerifierLogBytes+256 {
				t.Fatalf("verifier output is not bounded: %d bytes", len(report.Availability.Error))
			}
		})
	}
}

func TestCiliumVMBlockInvalidObjectBytes(t *testing.T) {
	source := &ciliumVMBlockKernelSource{
		platform:       "linux",
		architecture:   "amd64",
		probeBTF:       func() error { return nil },
		objectProvider: func() ([]byte, error) { return []byte("not-an-elf-object"), nil },
		loader:         ciliumVMBlockObjectLoader{},
	}
	report := collectCountOnlyTestReport(source, nil)
	if report.Availability.Available || report.Availability.Status != "object_invalid" {
		t.Fatalf("availability = %#v", report.Availability)
	}
	if !strings.Contains(report.Availability.Error, "parse embedded eBPF ELF") || report.HostSummary.TotalOps != 0 {
		t.Fatalf("invalid object report = %#v", report)
	}
}

func TestCiliumVMBlockAttachFailuresCleanUp(t *testing.T) {
	t.Run("issue attach", func(t *testing.T) {
		resources := &fakeVMBlockCountResources{issueErr: errors.New("issue attach failed")}
		source, _ := fakeCiliumVMBlockSource(resources)
		report := collectCountOnlyTestReport(source, nil)
		if report.Availability.Status != "attach_failed" || !resources.closed || resources.attachDoneCalls != 0 {
			t.Fatalf("report=%#v resources=%#v", report.Availability, resources)
		}
	})

	t.Run("complete attach", func(t *testing.T) {
		issueLink := &fakeVMBlockLink{}
		resources := &fakeVMBlockCountResources{issueLink: issueLink, completeErr: errors.New("complete attach failed")}
		source, _ := fakeCiliumVMBlockSource(resources)
		report := collectCountOnlyTestReport(source, nil)
		if report.Availability.Status != "attach_failed" || !issueLink.closed || !resources.closed {
			t.Fatalf("report=%#v issue=%#v resources=%#v", report.Availability, issueLink, resources)
		}
	})

	t.Run("issue attach and resource cleanup fail", func(t *testing.T) {
		resources := &fakeVMBlockCountResources{
			issueErr: errors.New("issue attach failed"),
			closeErr: errors.New("resource close failed"),
		}
		source, _ := fakeCiliumVMBlockSource(resources)
		report := collectCountOnlyTestReport(source, nil)
		if report.Availability.Status != "attach_failed" || !resources.closed {
			t.Fatalf("report=%#v resources=%#v", report.Availability, resources)
		}
		if !hasUnavailableSection(report.UnavailableSections, "ebpf_cleanup", "cleanup_failed") || !strings.Contains(report.Availability.Error, "resource close failed") {
			t.Fatalf("cleanup failure was not preserved: %#v", report)
		}
	})

	t.Run("complete attach and issue link cleanup fail", func(t *testing.T) {
		issueLink := &fakeVMBlockLink{err: errors.New("issue link close failed")}
		resources := &fakeVMBlockCountResources{issueLink: issueLink, completeErr: errors.New("complete attach failed")}
		source, _ := fakeCiliumVMBlockSource(resources)
		report := collectCountOnlyTestReport(source, nil)
		if report.Availability.Status != "attach_failed" || !issueLink.closed || !resources.closed {
			t.Fatalf("report=%#v issue=%#v resources=%#v", report.Availability, issueLink, resources)
		}
		if !hasUnavailableSection(report.UnavailableSections, "ebpf_cleanup", "cleanup_failed") || !strings.Contains(report.Availability.Error, "issue link close failed") {
			t.Fatalf("partial cleanup failure was not preserved: %#v", report)
		}
	})
}

func TestCiliumVMBlockCleanupFailuresAreStructured(t *testing.T) {
	tests := []struct {
		name      string
		resources *fakeVMBlockCountResources
		status    string
		message   string
	}{
		{
			name: "link close failure",
			resources: &fakeVMBlockCountResources{
				completeLink: &fakeVMBlockLink{err: errors.New("complete link close failed")},
			},
			status: "cleanup_failed", message: "complete link close failed",
		},
		{
			name:      "resource close failure",
			resources: &fakeVMBlockCountResources{closeErr: errors.New("resource close failed")},
			status:    "cleanup_failed", message: "resource close failed",
		},
		{
			name: "collection and cleanup failure",
			resources: &fakeVMBlockCountResources{
				counterErr:   errors.New("counter read failed"),
				completeLink: &fakeVMBlockLink{err: errors.New("complete link close failed")},
			},
			status: "counter_read_failed", message: "complete link close failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, _ := fakeCiliumVMBlockSource(test.resources)
			report := collectCountOnlyTestReport(source, nil)
			if report.Availability.Available || report.Availability.Status != test.status {
				t.Fatalf("availability = %#v", report.Availability)
			}
			if !test.resources.closed || !hasUnavailableSection(report.UnavailableSections, "ebpf_cleanup", "cleanup_failed") {
				t.Fatalf("cleanup lifecycle/report = resources:%#v report:%#v", test.resources, report)
			}
			if !strings.Contains(report.Availability.Error, test.message) {
				t.Fatalf("cleanup detail missing from availability: %#v", report.Availability)
			}
		})
	}
}

func TestCiliumVMBlockCleanupDiagnosticsAreBounded(t *testing.T) {
	resources := &fakeVMBlockCountResources{closeErr: errors.New(strings.Repeat("cleanup-log", maxVMBlockVerifierLogBytes))}
	source, _ := fakeCiliumVMBlockSource(resources)
	report := collectCountOnlyTestReport(source, nil)
	if report.Availability.Status != "cleanup_failed" || len(report.Availability.Error) > maxVMBlockVerifierLogBytes {
		t.Fatalf("availability cleanup diagnostic is not bounded: %#v", report.Availability)
	}
	for _, section := range report.UnavailableSections {
		if section.Name == "ebpf_cleanup" && len(section.Error) > maxVMBlockVerifierLogBytes {
			t.Fatalf("cleanup section diagnostic is not bounded: %d", len(section.Error))
		}
	}
}

func TestCiliumVMBlockSuccessfulCountOnlyCollection(t *testing.T) {
	resources := &fakeVMBlockCountResources{
		counters: VMBlockKernelCounters{IssueSeen: 41, CompleteSeen: 39, NullRequest: 0},
	}
	source, loader := fakeCiliumVMBlockSource(resources)
	mappings := []VMBlockCgroupMapping{{Name: "a-web", MappingQuality: "cgroup_v2_inode_tree", CgroupIDs: []uint64{11}}}
	report := collectCountOnlyTestReport(source, mappings)
	if !loader.loaded || !resources.closed || resources.issueLink == nil || !resources.issueLink.closed || resources.completeLink == nil || !resources.completeLink.closed {
		t.Fatalf("loader/resources lifecycle incomplete: loader=%#v resources=%#v", loader, resources)
	}
	if !report.Availability.Available || report.CollectionMode != vmBlockCountCollectionMode || report.AttributionMethod != "none_count_only" || report.AttributionQuality != "unavailable" {
		t.Fatalf("report mode = %#v", report)
	}
	if report.KernelCounters != resources.counters || report.HostSummary.TotalOps != 0 || len(report.VMs) != 1 || report.VMs[0].TotalOps != 0 || report.VMs[0].LatencyAvgMS != 0 || report.VMs[0].AttributionQuality != "unavailable" {
		t.Fatalf("count-only report fabricated attribution: %#v", report)
	}
	if privacyCollected(report) {
		t.Fatalf("privacy flags = %#v", report.Privacy)
	}

	var first, second bytes.Buffer
	if err := WriteVMBlockLatencyJSON(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := WriteVMBlockLatencyJSON(&second, report); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("count-only JSON is not deterministic")
	}
	if strings.Contains(first.String(), "request_pointer") || strings.Contains(first.String(), "request_pointer_value") {
		t.Fatalf("raw request pointer field leaked into JSON: %s", first.String())
	}
	var decoded VMBlockLatencyReport
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.KernelCounters.IssueSeen != 41 || decoded.KernelCounters.CompleteSeen != 39 || decoded.HostSummary.TotalOps != 0 {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func collectCountOnlyTestReport(source VMBlockKernelSource, mappings []VMBlockCgroupMapping) VMBlockLatencyReport {
	return CollectVMBlockLatencyReportWithKernelSource(
		context.Background(),
		VMBlockLatencyCollectOptions{Duration: time.Nanosecond, Interval: time.Nanosecond, ObservedAt: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)},
		mappings,
		source,
	)
}
