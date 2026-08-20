# Installing Solis I/O

This archive contains one experimental, single-host Linux/amd64 binary. It
does not install or enable a daemon, service, controller, remote agent, kernel
module, or persistent eBPF program.

## Verify the archive

From the directory containing the downloaded archive and checksum file:

```bash
archive=solis-v1.0.0-experimental-linux-amd64.tar.gz
sha256sum -c "${archive}.sha256"
tar -xzf "$archive"
cd "${archive%.tar.gz}"
sha256sum -c SHA256SUMS
./solis version --json
```

Replace the example version in those filenames when installing a later
release. Inspect `RELEASE-METADATA.json` to confirm the Git commit, source
timestamp, Go toolchain, target platform, binary digest, and embedded eBPF
object digest. Read `NOTICE` for copyright and project attribution, and
`REQUIREMENTS.md` for runtime and optional tooling details. This release does
not grant a public source-code license.

## Host requirements

The current release targets one local Linux KVM/libvirt host with:

- x86-64 little-endian Linux
- cgroup v2 mounted at `/sys/fs/cgroup`
- running VMs managed by local libvirt/QEMU
- kernel BTF at `/sys/kernel/btf/vmlinux`
- compatible typed-BTF `block_rq_issue` and `block_rq_complete` hooks
- the block-layer and blkcg/cgroup BTF fields required by `solis ebpf doctor`
- sufficient privileges for eBPF loading and tracing, normally through `sudo`

Secure Boot kernel lockdown, LSM policy, missing `CAP_BPF`, `CAP_PERFMON`, or
`CAP_SYS_ADMIN`, incompatible kernel BTF, or restricted tracing can prevent
the eBPF collector from loading. Solis reports those conditions rather than
fabricating measurements. Disabling security controls is not an installation
step; follow the host's security policy when deciding whether privileged eBPF
is permitted.

The release binary embeds the authentic eBPF ELF. Clang, LLVM, and libbpf
development headers are not required on the target host. They are needed only
by the separate controlled object-regeneration workflow.

## Install

Use the fixed system path `/usr/local/bin/solis`. First reject an unexpected
symbolic link or non-regular existing target:

```bash
target=/usr/local/bin/solis
if sudo test -L "$target"; then
  echo "Refusing symbolic-link target: $target" >&2
  exit 1
fi
if sudo test -e "$target" && ! sudo test -f "$target"; then
  echo "Refusing non-regular target: $target" >&2
  exit 1
fi
```

`/usr/local/bin` must be an existing root-owned directory. Install through a
root-created temporary file in that same directory, then atomically rename it
into place:

```bash
target=/usr/local/bin/solis
temporary=$(sudo mktemp /usr/local/bin/.solis.install.XXXXXXXX)
if ! sudo install -o root -g root -m 0755 ./solis "$temporary"; then
  sudo rm -f -- "$temporary"
  exit 1
fi
if ! sudo mv -T -- "$temporary" "$target"; then
  sudo rm -f -- "$temporary"
  exit 1
fi
```

This installs only the binary. It does not create users, directories,
services, scheduled jobs, configuration, or persistent tracing state.

For a non-lab host, pass an explicit Solis configuration using `--config` or
`SOLIS_CONFIG`; the built-in defaults describe the repository lab.

## Post-install checks

The first two checks do not load eBPF programs. `ebpf doctor` is also
non-invasive: it inspects readiness but does not attach programs.

```bash
solis version --json
solis status --json
sudo solis ebpf doctor
```

Review the doctor result for BTF, typed tracepoints, embedded-object presence,
cgroup ownership-path readiness, effective capabilities, and lockdown state.
A successful doctor readiness report still does not load the collector. The
explicit `solis ebpf vm-block-latency` command performs temporary privileged
loading and detaches during cleanup.

## Uninstall

Uninstall only the fixed binary path. Reject anything other than the installed
regular file and never use recursive deletion:

```bash
target=/usr/local/bin/solis
if sudo test -L "$target"; then
  echo "Refusing symbolic-link target: $target" >&2
  exit 1
fi
if sudo test -e "$target" && ! sudo test -f "$target"; then
  echo "Refusing non-regular target: $target" >&2
  exit 1
fi
if sudo test -f "$target"; then
  sudo rm -- "$target"
fi
```

There is no service to stop or disable. Solis does not leave an attached eBPF
program after a completed command. Evidence bundles and explicit configuration
files are user-managed data and are not deleted by these uninstall steps.
