package ebpf

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf/btf"
)

type mapVMBlockBTFTypeFinder map[string]btf.Type

func (finder mapVMBlockBTFTypeFinder) TypeByName(name string, target any) error {
	value, ok := finder[name]
	if !ok {
		return btf.ErrNotFound
	}
	switch output := target.(type) {
	case **btf.Typedef:
		resolved, ok := value.(*btf.Typedef)
		if !ok {
			return fmt.Errorf("%s is %T, not typedef", name, value)
		}
		*output = resolved
	case **btf.Struct:
		resolved, ok := value.(*btf.Struct)
		if !ok {
			return fmt.Errorf("%s is %T, not struct", name, value)
		}
		*output = resolved
	case **btf.Enum:
		resolved, ok := value.(*btf.Enum)
		if !ok {
			return fmt.Errorf("%s is %T, not enum", name, value)
		}
		*output = resolved
	default:
		return fmt.Errorf("unsupported target %T", target)
	}
	return nil
}

func completeVMBlockBTFTypes() mapVMBlockBTFTypeFinder {
	integer := &btf.Int{Name: "unsigned int", Size: 4}
	blockDevice := &btf.Struct{Name: "block_device", Members: []btf.Member{{Name: "bd_dev", Type: integer}}}
	kernfsNode := &btf.Struct{Name: "kernfs_node", Members: []btf.Member{{Name: "id", Type: &btf.Int{Name: "u64", Size: 8}}}}
	cgroup := &btf.Struct{Name: "cgroup", Members: []btf.Member{{Name: "kn", Type: &btf.Pointer{Target: kernfsNode}}}}
	css := &btf.Struct{Name: "cgroup_subsys_state", Members: []btf.Member{{Name: "cgroup", Type: &btf.Pointer{Target: cgroup}}}}
	blkcg := &btf.Struct{Name: "blkcg", Members: []btf.Member{{Name: "css", Type: css}}}
	blkg := &btf.Struct{Name: "blkcg_gq", Members: []btf.Member{{Name: "blkcg", Type: &btf.Pointer{Target: blkcg}}}}
	bio := &btf.Struct{Name: "bio", Members: []btf.Member{
		{Name: "bi_bdev", Type: &btf.Pointer{Target: blockDevice}},
		{Name: "bi_opf", Type: integer},
		{Name: "bi_blkg", Type: &btf.Pointer{Target: blkg}},
	}}
	gendisk := &btf.Struct{Name: "gendisk", Members: []btf.Member{{Name: "major", Type: integer}, {Name: "first_minor", Type: integer}}}
	queue := &btf.Struct{Name: "request_queue", Members: []btf.Member{{Name: "disk", Type: &btf.Pointer{Target: gendisk}}}}
	request := &btf.Struct{Name: "request", Members: []btf.Member{
		{Name: "bio", Type: &btf.Pointer{Target: bio}},
		{Name: "biotail", Type: &btf.Pointer{Target: bio}},
		{Name: "part", Type: &btf.Pointer{Target: blockDevice}},
		{Name: "cmd_flags", Type: integer},
	}}
	return mapVMBlockBTFTypeFinder{
		"btf_trace_block_rq_issue":    &btf.Typedef{Name: "btf_trace_block_rq_issue", Type: integer},
		"btf_trace_block_rq_complete": &btf.Typedef{Name: "btf_trace_block_rq_complete", Type: integer},
		"request":                     request,
		"bio":                         bio,
		"blkcg_gq":                    blkg,
		"blkcg":                       blkcg,
		"cgroup":                      cgroup,
		"kernfs_node":                 kernfsNode,
		"block_device":                blockDevice,
		"request_queue":               queue,
		"gendisk":                     gendisk,
		"req_op": &btf.Enum{Name: "req_op", Size: 4, Values: []btf.EnumValue{
			{Name: "REQ_OP_READ", Value: 0}, {Name: "REQ_OP_WRITE", Value: 1},
			{Name: "REQ_OP_FLUSH", Value: 2}, {Name: "REQ_OP_DISCARD", Value: 3},
		}},
	}
}

func TestVMBlockAttributionPreflightSuccessIsStillPreflightOnly(t *testing.T) {
	report := resolveKernelVMBlockBTFCapabilities(completeVMBlockBTFTypes())
	preflight := vmBlockAttributionPreflight(report)
	if !preflight.Available || preflight.Status != "preflight_only" || len(preflight.MissingFields) != 0 {
		t.Fatalf("preflight = %#v; capabilities = %#v", preflight, report)
	}
	if len(preflight.Caveats) == 0 {
		t.Fatal("preflight lacks ownership caveats")
	}
}

func TestVMBlockAttributionPreflightReportsMissingOwnershipField(t *testing.T) {
	types := completeVMBlockBTFTypes()
	bio := types["bio"].(*btf.Struct)
	bio.Members = bio.Members[:2]
	report := resolveKernelVMBlockBTFCapabilities(types)
	preflight := vmBlockAttributionPreflight(report)
	if preflight.Available || preflight.Status != "missing_fields" || fmt.Sprint(preflight.MissingFields) != "[bio.bi_blkg]" {
		t.Fatalf("preflight = %#v", preflight)
	}
}

func TestVMBlockRequestOperationEnumMustMatchExpectedValues(t *testing.T) {
	types := completeVMBlockBTFTypes()
	enumeration := types["req_op"].(*btf.Enum)
	enumeration.Values[1].Value = 99
	report := resolveKernelVMBlockBTFCapabilities(types)
	if vmBlockCapabilityAvailable(report, "req_op") {
		t.Fatalf("incompatible req_op was accepted: %#v", report)
	}
}
