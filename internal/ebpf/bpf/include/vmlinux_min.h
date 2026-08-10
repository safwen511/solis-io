#ifndef SOLIS_VMLINUX_MIN_H
#define SOLIS_VMLINUX_MIN_H

/*
 * Minimal kernel-style scalar declarations required before including the
 * packaged libbpf headers. This is deliberately not a helper header; the only
 * structure fields below are the whitelisted CO-RE metadata fields.
 */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef __u8 blk_status_t;
typedef __u32 blk_opf_t;
typedef __u32 dev_t;

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
};

enum bpf_map_update_elem_flags {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
};

enum req_op {
	REQ_OP_READ = 0,
	REQ_OP_WRITE = 1,
	REQ_OP_FLUSH = 2,
	REQ_OP_DISCARD = 3,
};

/*
 * Minimal CO-RE views. Only these named request metadata and blkcg ownership
 * fields are read by the experimental collector; no payload field is present.
 */
struct block_device {
	dev_t bd_dev;
} __attribute__((preserve_access_index));

struct kernfs_node {
	__u64 id;
} __attribute__((preserve_access_index));

struct cgroup {
	struct kernfs_node *kn;
} __attribute__((preserve_access_index));

struct cgroup_subsys_state {
	struct cgroup *cgroup;
} __attribute__((preserve_access_index));

struct blkcg {
	struct cgroup_subsys_state css;
} __attribute__((preserve_access_index));

struct blkcg_gq {
	struct blkcg *blkcg;
} __attribute__((preserve_access_index));

struct bio {
	struct blkcg_gq *bi_blkg;
} __attribute__((preserve_access_index));

struct request {
	blk_opf_t cmd_flags;
	struct bio *bio;
	struct block_device *part;
} __attribute__((preserve_access_index));

#endif
