package ebpf

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
)

var vmBlockMetadataRequirements = []string{
	"request.cmd_flags",
	"request.part",
	"block_device.bd_dev",
	"req_op",
}

var vmBlockOwnershipRequirements = []string{
	"request.bio",
	"bio.bi_blkg",
	"blkcg_gq.blkcg",
	"blkcg.css.cgroup",
	"cgroup.kn",
	"kernfs_node.id",
}

type kernelVMBlockBTFCapabilityResolver struct {
	spec vmBlockBTFTypeFinder
}

// inspectKernelVMBlockBTFCapabilities inspects kernel VM block BTF capabilities without mutating
// the observed host.
func inspectKernelVMBlockBTFCapabilities() (VMBlockBTFCapabilityReport, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return VMBlockBTFCapabilityReport{}, fmt.Errorf("load kernel BTF capability spec: %w", err)
	}
	return resolveKernelVMBlockBTFCapabilities(spec), nil
}

// resolveKernelVMBlockBTFCapabilities resolves kernel vm block btf capabilities from the available
// inputs.
func resolveKernelVMBlockBTFCapabilities(spec vmBlockBTFTypeFinder) VMBlockBTFCapabilityReport {
	return ResolveVMBlockBTFCapabilities(context.Background(), kernelVMBlockBTFCapabilityResolver{spec: spec})
}

// Resolve resolves source identities from validated inputs and reports unsupported layouts.
func (resolver kernelVMBlockBTFCapabilityResolver) Resolve(_ context.Context, requirement VMBlockBTFCapabilityRequirement) (VMBlockBTFCapability, error) {
	available := VMBlockBTFCapability{Available: true, Status: VMBlockCapabilityAvailable}
	if resolver.spec == nil {
		return VMBlockBTFCapability{}, &VMBlockCapabilityError{Status: VMBlockCapabilityResolutionError, Name: requirement.Name, Err: errors.New("kernel BTF spec is unavailable")}
	}
	switch requirement.Kind {
	case VMBlockCapabilityBTF:
		return available, nil
	case VMBlockCapabilityTypedTracepoint:
		name := strings.TrimSpace(strings.SplitN(requirement.Name, "(", 2)[0])
		var tracepoint *btf.Typedef
		if err := resolver.spec.TypeByName("btf_trace_"+name, &tracepoint); err != nil {
			return VMBlockBTFCapability{}, &VMBlockCapabilityError{Status: VMBlockCapabilityTracepointMissing, Name: requirement.Name, Err: err}
		}
		return available, nil
	case VMBlockCapabilityStructMember:
		if err := resolveVMBlockMemberPath(resolver.spec, requirement.Name); err != nil {
			status := VMBlockCapabilityOptionalMemberMissing
			if requirement.Required {
				status = VMBlockCapabilityRequiredMemberMissing
			}
			return VMBlockBTFCapability{}, &VMBlockCapabilityError{Status: status, Name: requirement.Name, Err: err}
		}
		return available, nil
	case VMBlockCapabilityEnum:
		var enumeration *btf.Enum
		if err := resolver.spec.TypeByName(requirement.Name, &enumeration); err != nil {
			return VMBlockBTFCapability{}, &VMBlockCapabilityError{Status: VMBlockCapabilityOptionalMemberMissing, Name: requirement.Name, Err: err}
		}
		if requirement.Name == "req_op" {
			if err := validateVMBlockRequestOperationEnum(enumeration); err != nil {
				return VMBlockBTFCapability{}, &VMBlockCapabilityError{Status: VMBlockCapabilityOptionalMemberMissing, Name: requirement.Name, Err: err}
			}
		}
		return available, nil
	default:
		return VMBlockBTFCapability{}, &VMBlockCapabilityError{Status: VMBlockCapabilityResolutionError, Name: requirement.Name, Err: errors.New("unsupported BTF capability kind")}
	}
}

// validateVMBlockRequestOperationEnum validates vm block request operation enum against its
// required contract.
func validateVMBlockRequestOperationEnum(enumeration *btf.Enum) error {
	if enumeration == nil {
		return errors.New("enum req_op is unavailable")
	}
	required := map[string]uint64{
		"REQ_OP_READ": 0, "REQ_OP_WRITE": 1, "REQ_OP_FLUSH": 2, "REQ_OP_DISCARD": 3,
	}
	for _, value := range enumeration.Values {
		if expected, ok := required[value.Name]; ok && value.Value == expected {
			delete(required, value.Name)
		}
	}
	if len(required) == 0 {
		return nil
	}
	missing := make([]string, 0, len(required))
	for name := range required {
		missing = append(missing, name)
	}
	return fmt.Errorf("enum req_op is missing expected values: %s", strings.Join(sortedUniqueStrings(missing), ", "))
}

// resolveVMBlockMemberPath resolves vm block member path from the available inputs.
func resolveVMBlockMemberPath(spec vmBlockBTFTypeFinder, path string) error {
	parts := strings.Split(strings.TrimSpace(path), ".")
	if len(parts) < 2 {
		return errors.New("member path must contain a type and member")
	}
	var current *btf.Struct
	if err := spec.TypeByName(parts[0], &current); err != nil {
		return fmt.Errorf("resolve struct %s: %w", parts[0], err)
	}
	for index, name := range parts[1:] {
		member, ok := vmBlockStructMember(current, name)
		if !ok {
			return fmt.Errorf("struct %s has no member %s", current.Name, name)
		}
		if index == len(parts[1:])-1 {
			return nil
		}
		next, ok := vmBlockUnderlyingStruct(member.Type)
		if !ok {
			return fmt.Errorf("member %s.%s does not resolve to a struct", current.Name, name)
		}
		current = next
	}
	return nil
}

// vmBlockStructMember builds VM block struct member from validated inputs.
func vmBlockStructMember(value *btf.Struct, name string) (btf.Member, bool) {
	if value == nil {
		return btf.Member{}, false
	}
	for _, member := range value.Members {
		if member.Name == name {
			return member, true
		}
	}
	return btf.Member{}, false
}

// vmBlockUnderlyingStruct builds VM block underlying struct from validated inputs.
func vmBlockUnderlyingStruct(value btf.Type) (*btf.Struct, bool) {
	value = btf.UnderlyingType(value)
	if pointer, ok := value.(*btf.Pointer); ok {
		value = btf.UnderlyingType(pointer.Target)
	}
	structure, ok := value.(*btf.Struct)
	return structure, ok
}

// vmBlockCapabilityAvailable reports whether VM block capability available.
func vmBlockCapabilityAvailable(report VMBlockBTFCapabilityReport, name string) bool {
	for _, capability := range report.Capabilities {
		if capability.Name == name {
			return capability.Available
		}
	}
	return false
}

// missingVMBlockCapabilities builds missing VM block capabilities from validated inputs.
func missingVMBlockCapabilities(report VMBlockBTFCapabilityReport, names []string) []string {
	missing := make([]string, 0)
	for _, name := range names {
		if !vmBlockCapabilityAvailable(report, name) {
			missing = append(missing, name)
		}
	}
	return sortedUniqueStrings(missing)
}

// vmBlockAttributionPreflight builds VM block attribution preflight from validated inputs.
func vmBlockAttributionPreflight(report VMBlockBTFCapabilityReport) VMBlockAttributionPreflight {
	if len(report.Capabilities) == 0 {
		return VMBlockAttributionPreflight{
			Available:     false,
			Status:        "not_evaluated",
			MissingFields: append([]string(nil), vmBlockOwnershipRequirements...),
			Caveats:       vmBlockAttributionPreflightCaveats(),
		}
	}
	missing := missingVMBlockCapabilities(report, vmBlockOwnershipRequirements)
	result := VMBlockAttributionPreflight{
		Available:     len(missing) == 0,
		Status:        "preflight_only",
		MissingFields: missing,
		Caveats:       vmBlockAttributionPreflightCaveats(),
	}
	if len(missing) > 0 {
		result.Status = "missing_fields"
	}
	return result
}

// vmBlockAttributionPreflightCaveats builds VM block attribution preflight caveats from validated
// inputs.
func vmBlockAttributionPreflightCaveats() []string {
	return []string{
		"VM attribution is not enabled; this result validates BTF field availability only",
		"request merging and requeues can affect future ownership attribution",
		"missing bio or blkcg ownership must remain explicitly unattributed",
		"stacked block devices can make physical-layer ownership ambiguous",
		"a runtime cgroup identity must match a validated libvirt VM mapping before attribution is trusted",
	}
}

// vmBlockAttributionEnabledCaveats builds VM block attribution enabled caveats from validated
// inputs.
func vmBlockAttributionEnabledCaveats() []string {
	return []string{
		"experimental runtime ownership extraction is enabled for this collection window",
		"request merging and requeues can affect ownership attribution",
		"missing bio or blkcg ownership remains explicitly unattributed",
		"stacked block devices can make physical-layer ownership ambiguous",
		"only an exact cgroup identity match to a validated libvirt VM mapping is attributed",
	}
}
