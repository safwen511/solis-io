package ebpf

// The script uses github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 to compile the
// host request-correlation typed-BTF C source. It copies only the authentic
// ELF object into bpf/generated; normal target builds embed it and do not
// require Clang.
//go:generate ./bpf/generate.sh
