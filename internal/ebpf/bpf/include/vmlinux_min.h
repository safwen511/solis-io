#ifndef SOLIS_VMLINUX_MIN_H
#define SOLIS_VMLINUX_MIN_H

/*
 * Minimal kernel-style scalar declarations required before including the
 * packaged libbpf headers. This is deliberately not a helper header and does
 * not declare payload structures or fields.
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

enum bpf_map_type {
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
};

/* No request member is dereferenced by the count-only Task 3A programs. */
struct request;

#endif
