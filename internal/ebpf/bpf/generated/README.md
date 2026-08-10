# Generated eBPF object

`go generate ./internal/ebpf` places the authentic little-endian BPF object
`vm_block_latency_bpfel.o` in this directory. The Go binary embeds that object.

After regeneration from the current C source, the Task 7 object correlates
request issue and completion identities only inside a bounded kernel map,
classifies operations, and exports sanitized host and cgroup/device/operation
latency aggregates. CO-RE reads are restricted to request operation and device
metadata plus the bio -> blkcg -> cgroup -> kernfs ID ownership path. It does
not export request addresses, kernel pointers, process metadata, or payloads.
Userspace attributes an aggregate only when its cgroup ID exactly matches a
validated libvirt VM cgroup ID; all other work remains explicit and
unattributed.

The object is intentionally absent when the controlled Clang/LLVM generator
has not run. The generator image is not yet digest/package-version pinned; see
the repository README for that reproducibility limitation. In the absence of
the object, Solis reports `object_unavailable` and never fabricates attachment
success or counters.
