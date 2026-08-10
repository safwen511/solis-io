#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct vmblock_count_values {
	__u64 issue_seen;
	__u64 complete_seen;
	__u64 null_request;
	__u64 duplicate_issue;
	__u64 lookup_miss;
	__u64 map_full;
	__u64 completed_latency_events;
};

#define VM_BLOCK_LATENCY_BUCKETS 14
#define VM_BLOCK_REQUEST_MAX_ENTRIES 65536

struct vmblock_latency_values {
	__u64 count;
	__u64 total_ns;
	__u64 min_ns;
	__u64 max_ns;
	__u64 buckets[VM_BLOCK_LATENCY_BUCKETS];
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
	__type(value, __u64);
} request_starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct vmblock_latency_values);
} latency_stats SEC(".maps");

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

SEC("tp_btf/block_rq_issue")
int BPF_PROG(on_block_rq_issue, struct request *rq)
{
	struct vmblock_count_values *values = get_counts();
	__u64 request_key;
	__u64 timestamp_ns;
	__u64 *existing;

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
	timestamp_ns = bpf_ktime_get_ns();
	if (bpf_map_update_elem(&request_starts, &request_key, &timestamp_ns,
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
	__u64 request_key;
	__u64 *issued_at_ns;
	__u64 now_ns;
	__u64 latency_ns;
	__u32 bucket;

	if (!values)
		return 0;
	values->complete_seen++;
	if (!rq) {
		values->null_request++;
		return 0;
	}

	request_key = (__u64)rq;
	issued_at_ns = bpf_map_lookup_elem(&request_starts, &request_key);
	if (!issued_at_ns) {
		values->lookup_miss++;
		return 0;
	}
	now_ns = bpf_ktime_get_ns();
	latency_ns = now_ns - *issued_at_ns;
	bpf_map_delete_elem(&request_starts, &request_key);

	latency_values = get_latency_stats();
	if (!latency_values)
		return 0;
	if (!latency_values->count || latency_ns < latency_values->min_ns)
		latency_values->min_ns = latency_ns;
	if (latency_ns > latency_values->max_ns)
		latency_values->max_ns = latency_ns;
	latency_values->count++;
	latency_values->total_ns += latency_ns;
	bucket = latency_bucket(latency_ns);
	latency_values->buckets[bucket]++;
	values->completed_latency_events++;
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
