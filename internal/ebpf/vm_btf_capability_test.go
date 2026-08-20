package ebpf

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeVMBlockBTFCapabilityResolver struct {
	results map[string]VMBlockBTFCapability
	errors  map[string]error
}

// Resolve resolves source identities from validated inputs and reports unsupported layouts.
func (resolver fakeVMBlockBTFCapabilityResolver) Resolve(_ context.Context, requirement VMBlockBTFCapabilityRequirement) (VMBlockBTFCapability, error) {
	if err := resolver.errors[requirement.Name]; err != nil {
		return VMBlockBTFCapability{}, err
	}
	if result, ok := resolver.results[requirement.Name]; ok {
		return result, nil
	}
	return VMBlockBTFCapability{Available: true, Status: VMBlockCapabilityAvailable}, nil
}

// TestResolveVMBlockBTFCapabilitiesFailures verifies resolve vm block btf capabilities failures.
func TestResolveVMBlockBTFCapabilitiesFailures(t *testing.T) {
	tests := []struct {
		name         string
		requirement  string
		status       string
		err          error
		reportStatus string
		reportAvail  bool
		optional     bool
	}{
		{name: "BTF missing", requirement: "vmlinux", status: VMBlockCapabilityBTFMissing, err: errors.New("BTF file is absent"), reportStatus: VMBlockCapabilityBTFMissing},
		{name: "tracepoint missing", requirement: "block_rq_issue(void *, struct request *)", status: VMBlockCapabilityTracepointMissing, err: errors.New("typed tracepoint is absent"), reportStatus: VMBlockCapabilityTracepointMissing},
		{name: "required member missing", requirement: "request.bio", status: VMBlockCapabilityRequiredMemberMissing, err: errors.New("member is absent"), reportStatus: VMBlockCapabilityRequiredMemberMissing},
		{name: "optional member missing", requirement: "request.biotail", status: VMBlockCapabilityOptionalMemberMissing, err: errors.New("member is absent"), reportStatus: "partial", reportAvail: true, optional: true},
		{name: "incompatible prototype", requirement: "block_rq_complete(void *, struct request *, blk_status_t, unsigned int)", status: VMBlockCapabilityIncompatiblePrototype, err: errors.New("prototype differs"), reportStatus: VMBlockCapabilityIncompatiblePrototype},
		{name: "unsupported kernel", requirement: "vmlinux", status: VMBlockCapabilityUnsupportedKernel, err: ErrVMBlockUnsupportedKernel, reportStatus: VMBlockCapabilityUnsupportedKernel},
		{name: "permission denied", requirement: "vmlinux", status: VMBlockCapabilityPermissionDenied, err: ErrVMBlockLatencyPermission, reportStatus: VMBlockCapabilityPermissionDenied},
		{name: "verifier placeholder", requirement: "request.bio", status: VMBlockCapabilityVerifierRejected, err: NewVMBlockVerifierError("preflight placeholder", "invalid field access", errors.New("rejected")), reportStatus: VMBlockCapabilityVerifierRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := fakeVMBlockBTFCapabilityResolver{errors: map[string]error{
				test.requirement: &VMBlockCapabilityError{Status: test.status, Name: test.requirement, Err: test.err},
			}}
			report := ResolveVMBlockBTFCapabilities(context.Background(), resolver)
			if report.Available != test.reportAvail || report.Status != test.reportStatus {
				t.Fatalf("report = %#v", report)
			}
			if !hasUnavailableSection(report.UnavailableSections, "btf:"+test.requirement, test.status) {
				t.Fatalf("missing unavailable section: %#v", report.UnavailableSections)
			}
			if test.optional && !report.Available {
				t.Fatal("optional member made report unavailable")
			}
		})
	}
}

// TestResolveVMBlockBTFCapabilitiesDeterministicSections verifies resolve vm block btf capabilities
// deterministic sections.
func TestResolveVMBlockBTFCapabilitiesDeterministicSections(t *testing.T) {
	resolver := fakeVMBlockBTFCapabilityResolver{errors: map[string]error{
		"request.biotail": &VMBlockCapabilityError{Status: VMBlockCapabilityOptionalMemberMissing, Name: "request.biotail"},
		"request.bio":     &VMBlockCapabilityError{Status: VMBlockCapabilityRequiredMemberMissing, Name: "request.bio"},
		"bio.bi_bdev":     &VMBlockCapabilityError{Status: VMBlockCapabilityOptionalMemberMissing, Name: "bio.bi_bdev"},
	}}
	first := ResolveVMBlockBTFCapabilities(context.Background(), resolver)
	second := ResolveVMBlockBTFCapabilities(context.Background(), resolver)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("reports differ:\n%#v\n%#v", first, second)
	}
	for index := 1; index < len(first.UnavailableSections); index++ {
		if first.UnavailableSections[index-1].Name > first.UnavailableSections[index].Name {
			t.Fatalf("unavailable sections are not sorted: %#v", first.UnavailableSections)
		}
	}
}

// TestRequiredVMBlockBTFCapabilitiesAreSymbolicAndComplete verifies required vm block btf
// capabilities are symbolic and complete.
func TestRequiredVMBlockBTFCapabilitiesAreSymbolicAndComplete(t *testing.T) {
	requirements := RequiredVMBlockBTFCapabilities()
	want := []string{
		"block_rq_issue(void *, struct request *)",
		"block_rq_complete(void *, struct request *, blk_status_t, unsigned int)",
		"request.bio", "request.biotail", "request.part", "request.cmd_flags",
		"bio.bi_bdev", "bio.bi_opf", "bio.bi_blkg", "blkcg_gq.blkcg",
		"blkcg.css.cgroup", "cgroup.kn", "kernfs_node.id", "block_device.bd_dev",
		"request_queue.disk", "gendisk.major", "gendisk.first_minor", "req_op",
	}
	for _, name := range want {
		found := false
		for _, requirement := range requirements {
			if requirement.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing capability requirement %q", name)
		}
	}
}
