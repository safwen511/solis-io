#ifndef SOLIS_VMLINUX_MIN_H
#define SOLIS_VMLINUX_MIN_H

/*
 * Minimal type declarations for the count-only tp_btf programs. No request
 * member is dereferenced in Task 3A. Future CO-RE attribution must replace or
 * regenerate these declarations from the target kernel BTF before accessing
 * request, bio, or blkcg fields.
 */
typedef __u8 blk_status_t;

struct request;

#endif
