# Authentic generated eBPF object

This directory contains the committed little-endian eBPF ELF used by Solis:

```text
vm_block_latency_bpfel.o
```

The Go binary embeds this object at build time. Normal development builds,
tests, installations, and release builds use the committed object and do not
regenerate it. A missing, empty, non-ELF, or layout-incompatible object is an
explicit build/runtime failure; Solis never substitutes a placeholder or
fabricates collection results.

## Current object behavior

The object implements the current VM-attributed block-latency data path:

```text
block_rq_issue / block_rq_complete
    -> bounded request correlation
    -> operation and major:minor classification
    -> bio / blkcg / cgroup ownership extraction
    -> sanitized host, device, and cgroup aggregate maps
```

Opaque request identities exist only as bounded in-kernel map keys. The object
does not emit request addresses, kernel pointers, process metadata, command
lines, environment values, guest data, query text, bodies, payloads, or
secrets. Userspace attributes an aggregate only when its cgroup identity exactly
matches a validated libvirt VM mapping; all other work remains explicit and
unattributed.

## Intentional regeneration

Regenerate only after changing the BPF C source or its required headers. The
controlled Docker convenience environment runs the pinned Cilium `bpf2go`
command from `internal/ebpf/bpf/generate.sh`:

```bash
docker build \
  --tag solis-ebpf-generator \
  --file build/ebpf/Dockerfile \
  .

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --env HOME=/tmp \
  --env GOPATH=/tmp/go \
  --env GOMODCACHE=/tmp/go/pkg/mod \
  --env GOCACHE=/tmp/go-build \
  --volume "$PWD:/src" \
  --workdir /src \
  solis-ebpf-generator \
  ./internal/ebpf/bpf/generate.sh
```

Run those commands from the repository root. That script is the implementation
behind:

```bash
go generate ./internal/ebpf
```

The generator uses `github.com/cilium/ebpf/cmd/bpf2go@v0.22.0`, Clang/LLVM,
packaged libbpf headers, CO-RE debug information, and the `bpfel` target. It
writes through a temporary directory and installs the resulting authentic ELF
at mode `0644`.

After regeneration, review the C/object diff and run the eBPF package tests and
the full non-privileged validation before committing the new object:

```bash
go test -count=1 ./internal/ebpf
go test -count=1 ./...
go build -o solis ./cmd/solis
git diff --check
```

The generator container is a controlled convenience environment, not a
bit-for-bit reproducible object builder: its base image and Debian package
versions are not yet digest/version locked. The release archive is reproducible
from the already committed authentic object when the documented Go toolchain
and module inputs match. Release construction additionally checks ELF magic,
non-zero size, and Go/BPF map-layout compatibility.
