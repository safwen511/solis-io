package ebpf

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// VMBlockBTFCapabilityKind identifies one capability needed by the future
// typed-BTF request-pointer collector.
type VMBlockBTFCapabilityKind string

const (
	VMBlockCapabilityBTF             VMBlockBTFCapabilityKind = "btf"
	VMBlockCapabilityTypedTracepoint VMBlockBTFCapabilityKind = "typed_tracepoint"
	VMBlockCapabilityStructMember    VMBlockBTFCapabilityKind = "struct_member"
	VMBlockCapabilityEnum            VMBlockBTFCapabilityKind = "enum"
)

const (
	VMBlockCapabilityAvailable             = "available"
	VMBlockCapabilityBTFMissing            = "btf_missing"
	VMBlockCapabilityTracepointMissing     = "tracepoint_missing"
	VMBlockCapabilityRequiredMemberMissing = "required_member_missing"
	VMBlockCapabilityOptionalMemberMissing = "optional_member_missing"
	VMBlockCapabilityIncompatiblePrototype = "incompatible_prototype"
	VMBlockCapabilityUnsupportedKernel     = "unsupported_kernel"
	VMBlockCapabilityPermissionDenied      = "permission_denied"
	VMBlockCapabilityVerifierRejected      = "verifier_rejected"
	VMBlockCapabilityResolutionError       = "error"
)

// VMBlockBTFCapabilityRequirement is a symbolic BTF requirement. It never
// contains or relies on a hard-coded kernel field offset.
type VMBlockBTFCapabilityRequirement struct {
	Name     string
	Kind     VMBlockBTFCapabilityKind
	Required bool
}

// VMBlockBTFCapability is one resolver result suitable for deterministic JSON
// diagnostics once a real resolver is added.
type VMBlockBTFCapability struct {
	Name      string                   `json:"name"`
	Kind      VMBlockBTFCapabilityKind `json:"kind"`
	Required  bool                     `json:"required"`
	Available bool                     `json:"available"`
	Status    string                   `json:"status"`
	Error     string                   `json:"error"`
}

// VMBlockBTFCapabilityReport summarizes typed-BTF feasibility without loading
// or attaching a program.
type VMBlockBTFCapabilityReport struct {
	Available           bool                               `json:"available"`
	Status              string                             `json:"status"`
	Capabilities        []VMBlockBTFCapability             `json:"capabilities"`
	UnavailableSections []VMBlockLatencyUnavailableSection `json:"unavailable_sections"`
}

// VMBlockBTFCapabilityResolver is the future boundary around kernel BTF type,
// prototype, member, and enum resolution. Implementations must resolve names
// from BTF and must not hard-code field offsets.
type VMBlockBTFCapabilityResolver interface {
	Resolve(context.Context, VMBlockBTFCapabilityRequirement) (VMBlockBTFCapability, error)
}

// VMBlockCapabilityError is a structured preflight failure. It is also used
// by tests to model kernels and permissions without touching the real host.
type VMBlockCapabilityError struct {
	Status string
	Name   string
	Err    error
}

// Error returns the human-readable error description.
func (err *VMBlockCapabilityError) Error() string {
	if err == nil {
		return ""
	}
	if err.Err != nil {
		return fmt.Sprintf("%s: %v", err.Name, err.Err)
	}
	return err.Name
}

// Unwrap exposes the underlying error for standard error-chain inspection.
func (err *VMBlockCapabilityError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

// RequiredVMBlockBTFCapabilities returns the fixed symbolic requirements for
// the intended request -> bio -> blkcg -> cgroup attribution path. Optional
// device/operation fields can be absent without invalidating ownership
// attribution, but the report remains partial.
func RequiredVMBlockBTFCapabilities() []VMBlockBTFCapabilityRequirement {
	requirements := []VMBlockBTFCapabilityRequirement{
		{Name: "vmlinux", Kind: VMBlockCapabilityBTF, Required: true},
		{Name: "block_rq_issue(void *, struct request *)", Kind: VMBlockCapabilityTypedTracepoint, Required: true},
		{Name: "block_rq_complete(void *, struct request *, blk_status_t, unsigned int)", Kind: VMBlockCapabilityTypedTracepoint, Required: true},
		{Name: "request.bio", Kind: VMBlockCapabilityStructMember, Required: true},
		{Name: "request.biotail", Kind: VMBlockCapabilityStructMember, Required: false},
		{Name: "request.part", Kind: VMBlockCapabilityStructMember, Required: false},
		{Name: "request.cmd_flags", Kind: VMBlockCapabilityStructMember, Required: false},
		{Name: "bio.bi_bdev", Kind: VMBlockCapabilityStructMember, Required: false},
		{Name: "bio.bi_opf", Kind: VMBlockCapabilityStructMember, Required: false},
		{Name: "bio.bi_blkg", Kind: VMBlockCapabilityStructMember, Required: true},
		{Name: "blkcg_gq.blkcg", Kind: VMBlockCapabilityStructMember, Required: true},
		{Name: "blkcg.css.cgroup", Kind: VMBlockCapabilityStructMember, Required: true},
		{Name: "cgroup.kn", Kind: VMBlockCapabilityStructMember, Required: true},
		{Name: "kernfs_node.id", Kind: VMBlockCapabilityStructMember, Required: true},
		{Name: "block_device.bd_dev", Kind: VMBlockCapabilityStructMember, Required: false},
		{Name: "request_queue.disk", Kind: VMBlockCapabilityStructMember, Required: false},
		{Name: "gendisk.major", Kind: VMBlockCapabilityStructMember, Required: false},
		{Name: "gendisk.first_minor", Kind: VMBlockCapabilityStructMember, Required: false},
		{Name: "req_op", Kind: VMBlockCapabilityEnum, Required: false},
	}
	return append([]VMBlockBTFCapabilityRequirement(nil), requirements...)
}

// ResolveVMBlockBTFCapabilities evaluates every symbolic requirement. A
// missing optional member produces a partial report; any required capability
// failure makes collection unavailable.
func ResolveVMBlockBTFCapabilities(ctx context.Context, resolver VMBlockBTFCapabilityResolver) VMBlockBTFCapabilityReport {
	report := VMBlockBTFCapabilityReport{
		Available:           true,
		Status:              VMBlockCapabilityAvailable,
		Capabilities:        []VMBlockBTFCapability{},
		UnavailableSections: []VMBlockLatencyUnavailableSection{},
	}
	if resolver == nil {
		report.Available = false
		report.Status = VMBlockCapabilityResolutionError
		report.UnavailableSections = append(report.UnavailableSections, VMBlockLatencyUnavailableSection{
			Name: "btf_capability_resolver", Status: VMBlockCapabilityResolutionError, Error: "BTF capability resolver is unavailable",
		})
		return report
	}

	for _, requirement := range RequiredVMBlockBTFCapabilities() {
		capability, err := resolver.Resolve(ctx, requirement)
		capability.Name = requirement.Name
		capability.Kind = requirement.Kind
		capability.Required = requirement.Required
		if err != nil {
			capability.Available = false
			capability.Status, capability.Error = classifyVMBlockCapabilityError(requirement, err)
		}
		if capability.Status == "" {
			if capability.Available {
				capability.Status = VMBlockCapabilityAvailable
			} else if requirement.Required {
				capability.Status = VMBlockCapabilityRequiredMemberMissing
			} else {
				capability.Status = VMBlockCapabilityOptionalMemberMissing
			}
		}
		if !capability.Available {
			report.UnavailableSections = append(report.UnavailableSections, VMBlockLatencyUnavailableSection{
				Name: "btf:" + requirement.Name, Status: capability.Status, Error: capability.Error,
			})
			if requirement.Required {
				report.Available = false
				if report.Status == VMBlockCapabilityAvailable || report.Status == "partial" {
					report.Status = capability.Status
				}
			} else if report.Status == VMBlockCapabilityAvailable {
				report.Status = "partial"
			}
		}
		report.Capabilities = append(report.Capabilities, capability)
	}
	normalizeVMBlockCapabilityReport(&report)
	return report
}

// classifyVMBlockCapabilityError maps VM block capability error to the package's stable public
// status categories.
func classifyVMBlockCapabilityError(requirement VMBlockBTFCapabilityRequirement, err error) (string, string) {
	var capabilityError *VMBlockCapabilityError
	if errors.As(err, &capabilityError) && capabilityError.Status != "" {
		return capabilityError.Status, capabilityError.Error()
	}
	if errors.Is(err, ErrVMBlockLatencyPermission) {
		return VMBlockCapabilityPermissionDenied, err.Error()
	}
	if requirement.Required {
		return VMBlockCapabilityResolutionError, err.Error()
	}
	return VMBlockCapabilityOptionalMemberMissing, err.Error()
}

// normalizeVMBlockCapabilityReport normalizes vm block capability report into its canonical
// representation.
func normalizeVMBlockCapabilityReport(report *VMBlockBTFCapabilityReport) {
	sort.Slice(report.Capabilities, func(i, j int) bool {
		if report.Capabilities[i].Name != report.Capabilities[j].Name {
			return report.Capabilities[i].Name < report.Capabilities[j].Name
		}
		return report.Capabilities[i].Kind < report.Capabilities[j].Kind
	})
	sort.Slice(report.UnavailableSections, func(i, j int) bool {
		if report.UnavailableSections[i].Name != report.UnavailableSections[j].Name {
			return report.UnavailableSections[i].Name < report.UnavailableSections[j].Name
		}
		return report.UnavailableSections[i].Status < report.UnavailableSections[j].Status
	})
}
