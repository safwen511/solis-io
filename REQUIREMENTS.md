# Solis I/O requirements

This file separates requirements for running a release, building from source,
regenerating the eBPF object, and operating the optional lab. Most users need
only the runtime section.

## Release runtime

- Little-endian x86-64 Linux (`linux/amd64`).
- Local KVM/QEMU virtual machines managed by libvirt.
- cgroup v2 mounted at `/sys/fs/cgroup`.
- Kernel BTF at `/sys/kernel/btf/vmlinux` with compatible typed-BTF
  `block_rq_issue` and `block_rq_complete` hooks.
- The block request, bio, blkcg, cgroup, and kernfs BTF fields checked by
  `solis ebpf doctor`.
- Access to the local libvirt inventory and the required procfs/sysfs metrics.
- Sufficient eBPF privileges, normally supplied through `sudo`, including the
  capabilities permitted by the host policy for BPF loading and tracing.
- A lockdown/LSM policy that permits the temporary eBPF load and attach.

The release binary embeds the authentic eBPF ELF. Target hosts do not require
Go, Python, Clang, LLVM, libbpf headers, Docker, or a persistent service.

## Building from source

- Go 1.25 or newer, matching the `go` directive in `go.mod`.
- Git and Bash.
- GNU core utilities used by validation and release scripts.
- GNU tar, gzip, `jq`, and `sha256sum` for deterministic release archives.
- Network access to download the modules pinned by `go.mod` and `go.sum` when
  they are not already present in the Go module cache.

Go dependencies are declared in `go.mod` and verified by `go.sum`; Solis does
not use a Python package file for its Go binary.

## Regenerating the eBPF object

Normal builds must use the committed authentic object and do not regenerate
it. Intentional regeneration additionally requires:

- Docker compatible with `build/ebpf/Dockerfile`, or an equivalent controlled
  Linux toolchain.
- Clang/LLVM and packaged `libbpf-dev` headers inside that environment.
- Cilium `bpf2go` v0.22.0, pinned by the generator command.

The generated object must remain a real non-empty eBPF ELF and pass the Go map
layout tests before release.

## Optional lab environment

The included lab additionally uses local libvirt tooling, `virsh`,
`virt-install`, `qemu-img`, `cloud-localds`, SSH/SCP, `curl`, `jq`, and Bash.
Guest packages are role-specific:

- client: `curl`, `apache2-utils`, and Python 3 for the bounded clients
- web: Nginx, Python 3, and the distribution package `python3-psycopg2`
- database: PostgreSQL and its client tools
- stress: fio

The Python client workloads use only the Python standard library. The lab web
application imports `psycopg2`, supplied by the guest OS package above; no
untracked `pip` environment or secrets file is required.
