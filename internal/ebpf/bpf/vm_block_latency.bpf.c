#include <common.h>
#include <bpf_tracing.h>
#include "vmlinux_min.h"

struct vmblock_count_values {
	__u64 issue_seen;
	__u64 complete_seen;
	__u64 null_request;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct vmblock_count_values);
} counters SEC(".maps");

static __always_inline struct vmblock_count_values *get_counts(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&counters, &key);
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(on_block_rq_issue, void *unused, struct request *rq)
{
	struct vmblock_count_values *values = get_counts();

	if (!values)
		return 0;
	values->issue_seen++;
	if (!rq)
		values->null_request++;
	return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(on_block_rq_complete, void *unused, struct request *rq,
	     blk_status_t error, unsigned int nr_bytes)
{
	struct vmblock_count_values *values = get_counts();

	if (!values)
		return 0;
	values->complete_seen++;
	if (!rq)
		values->null_request++;
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
