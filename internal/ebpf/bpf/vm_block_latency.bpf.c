#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct vmblock_count_values {
	__u64 issue_seen;
	__u64 complete_seen;
	__u64 null_request;
	__u64 duplicate_issue;
	__u64 lookup_miss;
	__u64 map_full;
	__u64 completed_latency_events;
	__u64 metadata_unavailable;
	__u64 device_unavailable;
	__u64 operation_unknown;
	__u64 missing_bio;
	__u64 missing_blkcg;
};

#define VM_BLOCK_LATENCY_BUCKETS 14
#define VM_BLOCK_REQUEST_MAX_ENTRIES 65536
#define VM_BLOCK_DEVICE_MAX_ENTRIES 4096
#define VM_BLOCK_CGROUP_DEVICE_MAX_ENTRIES 4096
#define VM_BLOCK_REQ_OP_MASK 0xffU

enum vmblock_operation {
	VM_BLOCK_OP_READ = 0,
	VM_BLOCK_OP_WRITE = 1,
	VM_BLOCK_OP_FLUSH = 2,
	VM_BLOCK_OP_DISCARD = 3,
	VM_BLOCK_OP_UNKNOWN = 4,
};

struct vmblock_issue_value {
	__u64 timestamp_ns;
	__u64 cgroup_id;
	__u32 major;
	__u32 minor;
	__u8 operation;
	__u8 device_available;
	__u8 ownership_available;
	__u8 reserved;
};

struct vmblock_device_operation_key {
	__u32 major;
	__u32 minor;
	__u32 operation;
};

struct vmblock_cgroup_device_operation_key {
	__u64 cgroup_id;
	__u32 major;
	__u32 minor;
	__u32 operation;
};

struct vmblock_latency_values {
	__u64 count;
	__u64 total_ns;
	__u64 min_ns;
	__u64 max_ns;
	__u64 buckets[VM_BLOCK_LATENCY_BUCKETS];
	__u64 read_ops;
	__u64 write_ops;
	__u64 flush_ops;
	__u64 discard_ops;
	__u64 unknown_ops;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct vmblock_count_values);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VM_BLOCK_REQUEST_MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct vmblock_issue_value);
} request_starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct vmblock_latency_values);
} latency_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, VM_BLOCK_DEVICE_MAX_ENTRIES);
	__type(key, struct vmblock_device_operation_key);
	__type(value, struct vmblock_latency_values);
} device_operation_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, VM_BLOCK_CGROUP_DEVICE_MAX_ENTRIES);
	__type(key, struct vmblock_cgroup_device_operation_key);
	__type(value, struct vmblock_latency_values);
} cgroup_device_operation_stats SEC(".maps");

static __always_inline struct vmblock_count_values *get_counts(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&counters, &key);
}

static __always_inline struct vmblock_latency_values *get_latency_stats(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&latency_stats, &key);
}

static __always_inline __u32 latency_bucket(__u64 latency_ns)
{
	if (latency_ns < 100000ULL)
		return 0;
	if (latency_ns < 250000ULL)
		return 1;
	if (latency_ns < 500000ULL)
		return 2;
	if (latency_ns < 1000000ULL)
		return 3;
	if (latency_ns < 2000000ULL)
		return 4;
	if (latency_ns < 5000000ULL)
		return 5;
	if (latency_ns < 10000000ULL)
		return 6;
	if (latency_ns < 20000000ULL)
		return 7;
	if (latency_ns < 50000000ULL)
		return 8;
	if (latency_ns < 100000000ULL)
		return 9;
	if (latency_ns < 250000000ULL)
		return 10;
	if (latency_ns < 500000000ULL)
		return 11;
	if (latency_ns < 1000000000ULL)
		return 12;
	return 13;
}

static __always_inline __u8 classify_operation(blk_opf_t cmd_flags)
{
	switch (cmd_flags & VM_BLOCK_REQ_OP_MASK) {
	case REQ_OP_READ:
		return VM_BLOCK_OP_READ;
	case REQ_OP_WRITE:
		return VM_BLOCK_OP_WRITE;
	case REQ_OP_FLUSH:
		return VM_BLOCK_OP_FLUSH;
	case REQ_OP_DISCARD:
		return VM_BLOCK_OP_DISCARD;
	default:
		return VM_BLOCK_OP_UNKNOWN;
	}
}

static __always_inline void extract_cgroup_identity(
	struct request *rq, struct vmblock_issue_value *issue,
	struct vmblock_count_values *values)
{
	struct bio *bio = 0;
	struct blkcg_gq *blkg = 0;
	struct blkcg *blkcg = 0;
	struct cgroup *cgroup = 0;
	struct kernfs_node *kn = 0;
	__u64 cgroup_id = 0;

	if (BPF_CORE_READ_INTO(&bio, rq, bio) < 0 || !bio) {
		values->missing_bio++;
		return;
	}
	if (BPF_CORE_READ_INTO(&blkg, bio, bi_blkg) < 0 || !blkg ||
	    BPF_CORE_READ_INTO(&blkcg, blkg, blkcg) < 0 || !blkcg ||
	    BPF_CORE_READ_INTO(&cgroup, blkcg, css.cgroup) < 0 || !cgroup ||
	    BPF_CORE_READ_INTO(&kn, cgroup, kn) < 0 || !kn ||
	    BPF_CORE_READ_INTO(&cgroup_id, kn, id) < 0 || !cgroup_id) {
		values->missing_blkcg++;
		return;
	}
	issue->cgroup_id = cgroup_id;
	issue->ownership_available = 1;
}

static __always_inline void observe_latency(struct vmblock_latency_values *values,
					     __u64 latency_ns, __u8 operation)
{
	__u32 bucket;

	if (!values)
		return;
	if (!values->count || latency_ns < values->min_ns)
		values->min_ns = latency_ns;
	if (latency_ns > values->max_ns)
		values->max_ns = latency_ns;
	values->count++;
	values->total_ns += latency_ns;
	bucket = latency_bucket(latency_ns);
	values->buckets[bucket]++;
	switch (operation) {
	case VM_BLOCK_OP_READ:
		values->read_ops++;
		break;
	case VM_BLOCK_OP_WRITE:
		values->write_ops++;
		break;
	case VM_BLOCK_OP_FLUSH:
		values->flush_ops++;
		break;
	case VM_BLOCK_OP_DISCARD:
		values->discard_ops++;
		break;
	default:
		values->unknown_ops++;
		break;
	}
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(on_block_rq_issue, struct request *rq)
{
	struct vmblock_count_values *values = get_counts();
	__u64 request_key;
	struct vmblock_issue_value issue = {};
	struct vmblock_issue_value *existing;
	struct block_device *part = 0;
	blk_opf_t cmd_flags = 0;
	dev_t dev = 0;
	int operation_result;
	int device_result;

	if (!values)
		return 0;
	values->issue_seen++;
	if (!rq) {
		values->null_request++;
		return 0;
	}

	request_key = (__u64)rq;
	existing = bpf_map_lookup_elem(&request_starts, &request_key);
	if (existing)
		values->duplicate_issue++;
	issue.timestamp_ns = bpf_ktime_get_ns();
	operation_result = BPF_CORE_READ_INTO(&cmd_flags, rq, cmd_flags);
	if (operation_result < 0) {
		issue.operation = VM_BLOCK_OP_UNKNOWN;
		values->operation_unknown++;
	} else {
		issue.operation = classify_operation(cmd_flags);
		if (issue.operation == VM_BLOCK_OP_UNKNOWN)
			values->operation_unknown++;
	}
	device_result = BPF_CORE_READ_INTO(&part, rq, part);
	if (!device_result && part)
		device_result = BPF_CORE_READ_INTO(&dev, part, bd_dev);
	if (device_result < 0 || !part || !dev) {
		values->device_unavailable++;
	} else {
		issue.major = dev >> 20;
		issue.minor = dev & ((1U << 20) - 1);
		issue.device_available = 1;
	}
	if (operation_result < 0 || device_result < 0 || !issue.device_available)
		values->metadata_unavailable++;
	extract_cgroup_identity(rq, &issue, values);
	if (bpf_map_update_elem(&request_starts, &request_key, &issue,
				BPF_ANY) < 0)
		values->map_full++;
	return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(on_block_rq_complete, struct request *rq,
	     blk_status_t error, unsigned int nr_bytes)
{
	struct vmblock_count_values *values = get_counts();
	struct vmblock_latency_values *latency_values;
	struct vmblock_latency_values zero_latency = {};
	struct vmblock_latency_values *device_latency;
	struct vmblock_device_operation_key device_key = {};
	struct vmblock_cgroup_device_operation_key cgroup_device_key = {};
	__u64 request_key;
	struct vmblock_issue_value *issue;
	__u64 now_ns;
	__u64 latency_ns;
	__u8 operation;
	__u8 device_available;
	__u8 ownership_available;
	__u64 cgroup_id;

	if (!values)
		return 0;
	values->complete_seen++;
	if (!rq) {
		values->null_request++;
		return 0;
	}

	request_key = (__u64)rq;
	issue = bpf_map_lookup_elem(&request_starts, &request_key);
	if (!issue) {
		values->lookup_miss++;
		return 0;
	}
	now_ns = bpf_ktime_get_ns();
	latency_ns = now_ns - issue->timestamp_ns;
	device_key.major = issue->major;
	device_key.minor = issue->minor;
	device_key.operation = issue->operation;
	operation = issue->operation;
	device_available = issue->device_available;
	ownership_available = issue->ownership_available;
	cgroup_id = issue->cgroup_id;
	bpf_map_delete_elem(&request_starts, &request_key);

	latency_values = get_latency_stats();
	if (!latency_values)
		return 0;
	observe_latency(latency_values, latency_ns, operation);
	if (device_available) {
		device_latency = bpf_map_lookup_elem(&device_operation_stats,
						     &device_key);
		if (!device_latency) {
			bpf_map_update_elem(&device_operation_stats, &device_key,
					    &zero_latency, BPF_NOEXIST);
			device_latency = bpf_map_lookup_elem(&device_operation_stats,
							     &device_key);
		}
		if (device_latency)
			observe_latency(device_latency, latency_ns, operation);
		else
			values->metadata_unavailable++;
		if (ownership_available) {
			cgroup_device_key.cgroup_id = cgroup_id;
			cgroup_device_key.major = device_key.major;
			cgroup_device_key.minor = device_key.minor;
			cgroup_device_key.operation = device_key.operation;
			device_latency = bpf_map_lookup_elem(
				&cgroup_device_operation_stats, &cgroup_device_key);
			if (!device_latency) {
				bpf_map_update_elem(&cgroup_device_operation_stats,
					&cgroup_device_key, &zero_latency, BPF_NOEXIST);
				device_latency = bpf_map_lookup_elem(
					&cgroup_device_operation_stats, &cgroup_device_key);
			}
			if (device_latency)
				observe_latency(device_latency, latency_ns, operation);
			else
				values->map_full++;
		}
	}
	values->completed_latency_events++;
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
