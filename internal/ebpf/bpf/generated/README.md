# Generated eBPF object

`go generate ./internal/ebpf` places the authentic little-endian BPF object
`vm_block_latency_bpfel.o` in this directory. The Go binary embeds that object.

The object is intentionally absent when the controlled Clang/LLVM generator
has not run. The generator image is not yet digest/package-version pinned; see
the repository README for that reproducibility limitation. In the absence of
the object, Solis reports `object_unavailable` and never fabricates attachment
success or counters.
