# Solis I/O

**Single-host KVM storage observability and VM attribution for Linux/libvirt.**

<p align="center">
  <a href="https://www.eodatacenter.com/">
    <img src="docs/assets/eo-data-center-logo.webp" alt="EO Data Center logo" width="260">
  </a>
</p>

<p align="center">
  <em>Developed by Safwen as an internship project hosted by
  <a href="https://www.eodatacenter.com/">EO Data Center</a>, Tunisia.</em>
</p>

Solis helps a provider investigate whether host-side storage pressure affected a
VM and which neighboring VM contributed to that pressure. It combines live host
metrics, libvirt inventory, QEMU I/O activity, storage topology, and real
VM-attributed eBPF block latency in one read-only terminal application.

| Project status | Current release | Platform | License |
|---|---|---|---|
| Experimental; working in the included lab | [`v1.0.0-experimental`](https://github.com/safwen511/solis-io/releases/tag/v1.0.0-experimental) | Linux/amd64, KVM, libvirt, cgroup v2 | [GPL-3.0-only](LICENSE) |

> Solis is an operator-driven experimental tool, not a production service. It
> does not control VMs, remediate incidents, or prove customer impact by itself.

## Contents

- [Why Solis](#why-solis)
- [Internship context](#internship-context)
- [What works today](#what-works-today)
- [Quick start](#quick-start)
- [Interactive console](#interactive-console)
- [Core workflows](#core-workflows)
- [How VM attribution works](#how-vm-attribution-works)
- [Evidence and capture bundles](#evidence-and-capture-bundles)
- [Configuration](#configuration)
- [Controlled lab scenario](#controlled-lab-scenario)
- [Validation](#validation)
- [Safety and privacy](#safety-and-privacy)
- [Requirements and compatibility](#requirements-and-compatibility)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [License and attribution](#license-and-attribution)

## Why Solis

Host-wide disk utilization can show that storage is busy, but it usually does
not answer the questions an operator actually has during a noisy-neighbor
incident:

- Which local VM issued the block I/O?
- What issue-to-completion latency did its requests experience?
- Did the suspected VM and victim share the same physical storage path?
- Was one QEMU process the dominant writer during the same window?
- How much block work could not be attributed safely?
- Is the evidence strong enough to support a diagnosis, or is it degraded?

Solis builds that evidence chain without entering guests or inspecting
application payloads. It keeps unavailable and unattributed work visible instead
of filling gaps with invented measurements.

## Internship context

Solis I/O was developed by Safwen as an internship project hosted by
[EO Data Center](https://www.eodatacenter.com/) in Tunisia. The project applies
Linux, KVM/libvirt, and eBPF observability to a practical data-center problem:
investigating host storage contention and attributing I/O activity to individual
virtual machines.

EO Data Center is acknowledged as the internship host organization. Solis I/O
remains an experimental project and should not be interpreted as an official EO
Data Center product, service, or support commitment.

## What works today

The `v1.0.0-experimental` milestone includes:

- A keyboard-navigable, read-only provider console launched with `sudo solis`.
- Live inventory for running and stopped local libvirt VMs.
- Host CPU, memory, I/O pressure, physical-disk throughput, and queue state.
- Per-QEMU write-rate and write-syscall pressure classification.
- Real typed-BTF eBPF attachment to `block_rq_issue` and
  `block_rq_complete`.
- Host request issue/completion correlation and fixed-bucket latency
  histograms.
- Read, write, flush, discard, and unknown operation classification.
- Device aggregation by stable block-device `major:minor` identity.
- Exact blkcg/cgroup-ID matching to validated libvirt VM cgroup mappings.
- Per-VM operation totals, latency summaries, device operations, attribution
  quality, and explicit loss counters.
- Selected-VM investigation, recent evidence history, and derived events.
- An in-application Command Center for fixed, allowlisted Solis workflows.
- Diagnosis, private evidence capture, bounded watch, unified observe, doctor,
  inventory, status, and version workflows.
- JSON output for automation and checksummed incident bundles for handoff.
- A deterministic Linux/amd64 release archive with the authentic eBPF object,
  build identity, and SHA-256 checksums.
- Reproducible controlled-lab scenarios for normal traffic, moderate neighbor
  pressure, VM attribution, application impact, and collector safety.

Solis does **not** currently provide multi-host collection, remote agents, a
daemon, VM controls, automatic remediation, package-manager integration, or a
production support guarantee.

## Quick start

### 1. Check the host

Read [REQUIREMENTS.md](REQUIREMENTS.md) before loading eBPF. At minimum, the
host needs local KVM/libvirt VMs, cgroup v2, kernel BTF, compatible typed-BTF
block hooks, and policy that permits privileged eBPF tracing.

From a source checkout:

```bash
go test ./...
go build -o solis ./cmd/solis
./solis doctor
sudo ./solis ebpf doctor
```

Both doctor commands are non-invasive: they inspect readiness but do not load
or attach programs.

### 2. Run the application

```bash
sudo ./solis
```

The interactive monitor enables VM-attributed eBPF evidence by default. Without
the required privilege or kernel support, the console still reports the
available host/QEMU evidence and explains why eBPF is unavailable.

### 3. Install the development command

To run `solis` from any directory while developing this checkout:

```bash
./scripts/install-dev-command.sh
hash -r
sudo solis
```

The installer creates a root-owned `/usr/local/bin/solis` and a root-owned
`/etc/solis/config.json` pointing to this checkout. It installs no daemon or
service. To update an existing development installation intentionally:

```bash
./scripts/install-dev-command.sh --replace
```

For the standalone release archive, checksum verification, atomic installation,
post-install checks, and uninstall instructions, use
[docs/INSTALL.md](docs/INSTALL.md).

## Interactive console

`sudo solis` is the primary operator interface. The screen refreshes every
200 ms for responsive navigation while evidence is collected in bounded
multi-second windows. The UI always distinguishes current collection state from
the last completed evidence window; a fast repaint is not presented as a new
kernel sample.

### Panels

| Panel | Purpose |
|---|---|
| **Home** | Host/storage health and every resolved VM, including stopped VMs |
| **Investigate VM** | Identity, addressing, capacity, QEMU pressure, attributed operations, latency, devices, mapping quality, recent windows, and storage peers |
| **Events** | Bounded derived state transitions and evidence-quality events; not raw kernel events |
| **Command Center** | Fixed Solis workflows run inside the application without a shell |

Wide terminals also show Solis's own CPU use, RSS, process disk-I/O rate,
goroutine count, and uptime. Those are self-observability metrics for the Solis
process, not VM or host totals.

### Controls

| Key | Action |
|---|---|
| `j` / `k`, down / up | Select a VM, workflow, or output line |
| `Tab`, left / right | Change panel |
| `1` / `2` / `3` / `4` | Open Home, Investigate, Events, or Command Center |
| `Enter` | Investigate the selected VM or run the selected workflow |
| `b` | Return from details/output and resume live collection when complete |
| `s` | Save an Observe detail artifact when the output panel offers it |
| `n` / `p` / `w` / `o` / `l` | Sort by name, pressure, write rate, attributed operations, or p95 latency |
| `r` | Request an immediate evidence refresh |
| `?` / `h` | Toggle help |
| `q` / `Ctrl-C` | Quit and restore the terminal |

Workflow output is scrollable with the same up/down keys. Solis pauses the live
collector and detaches its eBPF links before an embedded workflow starts, then
resumes monitoring after the operator returns. The Command Center accepts no
arbitrary shell text.

Set `NO_COLOR=1` to disable terminal color. Solis uses an alternate screen and
restores the cursor and terminal mode on normal exit or interruption.

### Reading attribution state

Collector availability and attribution quality are separate:

- **Collector available** means the authentic programs loaded, attached, and
  produced readable maps.
- **Attribution available** means at least one VM matched and no more than 5%
  of accounted work was unattributed.
- **Degraded** means more than 5% but no more than 25% was unattributed.
- **Unavailable** means coverage exceeded 25%, no VM matched, no attributed
  event completed, or the ownership path was unsupported.

Quiet windows may therefore show a working collector but unavailable
attribution: a handful of host/background requests can dominate a very small
sample. A sustained, bounded workload usually provides a more meaningful
denominator. Solis never converts that weak window into a successful result.

## Core workflows

The short commands cover normal operator use:

```bash
# Interactive provider console; eBPF attribution enabled by default.
sudo solis

# Explicit equivalent with optional timing controls.
sudo solis monitor

# Discover a same-storage suspect automatically.
sudo solis investigate a-web

# Investigate a specific victim/suspect pair.
sudo solis investigate a-web b-stress

# Create a private checksummed bundle under the configured capture root.
sudo solis bundle a-web

# Readiness checks.
solis doctor
sudo solis ebpf doctor
```

`investigate` and `bundle` include VM-attributed eBPF evidence by default. Use
`--include-ebpf-latency=false` only when an explicitly non-eBPF run is wanted.

### Non-interactive and automation commands

| Goal | Command |
|---|---|
| List resolved VMs | `solis inventory` |
| One status report | `solis status` |
| Machine-readable status | `solis status --json` |
| Finite terminal monitor | `solis top --iterations 3 --every 5s --no-clear` |
| Raw VM-attributed latency JSON | `sudo solis ebpf vm-block-latency --duration 10s --interval 2s --all-vms --json` |
| JSON diagnosis | `sudo solis investigate a-web --json --output diagnosis.json` |
| Unified snapshot | `sudo solis observe snapshot --victim a-web --discover-suspects --include-ebpf-latency --json` |
| Bounded watch | `sudo solis watch noisy-neighbor --victim a-web --discover-suspects --include-ebpf-latency --iterations 5` |
| Build identity | `solis version --json` |

The parent directory for a single-file `--output` must already exist. Hardened
writers reject symlink parents, symlink targets, and non-regular targets, and
write private files using a same-directory temporary file plus atomic rename.
Human confirmation remains on the terminal; a JSON output file contains JSON
only.

The established long forms remain available for scripts and advanced options:

- `solis diagnose noisy-neighbor`
- `solis capture noisy-neighbor`
- `solis watch noisy-neighbor`
- `solis observe snapshot`
- `solis observe watch`
- `solis vm storage-stats`
- `solis qemu io-summary`
- `solis storage snapshot`

Run `solis --help` or `<command> --help` for the current parser contract rather
than copying an older invocation from documentation.

## How VM attribution works

### Evidence layers

1. **Libvirt inventory** resolves VM name, tenant, role, runtime state, QEMU
   PID, disk backend, cgroup path, and validated cgroup inode ID.
2. **Storage topology** maps a VM disk through its filesystem source, parent
   device, and physical disk.
3. **QEMU pressure** samples per-QEMU byte and syscall counters to identify
   dominant writers without reading command lines or memory.
4. **Typed-BTF eBPF** measures block request issue-to-completion latency,
   classifies operation/device metadata, and extracts blkcg ownership.
5. **Userspace matching** attributes only exact cgroup-ID matches to the
   validated local libvirt inventory.
6. **Diagnosis and capture** combine those independent layers while preserving
   missing evidence and caveats.

### Kernel ownership path

```text
request -> bio -> bi_blkg -> blkcg -> css -> cgroup -> kernfs_node.id
```

At `block_rq_issue`, the BPF program stores a timestamp and sanitized metadata
in bounded maps. At `block_rq_complete`, it correlates the same opaque request,
calculates latency, and updates host, device/operation, and
cgroup/device/operation aggregates.

The request identity is an internal map key only. Request addresses, bio
pointers, blkcg pointers, cgroup pointers, and other kernel addresses are never
emitted to userspace or JSON.

Userspace accepts an attribution only when the extracted `kernfs_node.id`
exactly matches a validated libvirt VM cgroup ID. Missing bio/blkcg ownership,
unknown cgroups, lookup misses, reissues, requests incomplete at the window
boundary, and map pressure remain explicit unattributed counters.

### What latency means

Solis measures Linux host block-request **issue-to-completion** latency. It is
not HTTP response time, SQL execution time, exact guest-visible latency, or
physical-media service time. Percentiles are approximate fixed-bucket
estimates; count, total, minimum, maximum, and average use observed aggregates.

### Cilium eBPF integration

The project pins `github.com/cilium/ebpf` at `v0.22.0` for:

- parsing and loading the embedded authentic ELF;
- verifier diagnostics and object/map assignment;
- typed tracing attachment and link cleanup;
- kernel BTF/type/member inspection;
- safe map lookup and iteration; and
- the pinned `bpf2go` generation command.

The attribution algorithm itself is project-owned BPF C and Go code. Cilium
provides the pure-Go loading, BTF, link, and map lifecycle layer; Solis does not
use BCC or Go libbpf bindings.

## Evidence and capture bundles

`solis bundle <victim> [suspect]` writes a private incident directory beneath
the configured capture root. Directories use mode `0700`, files use `0600`, and
the manifest records file modes and SHA-256 checksums.

Start with these files:

| File | Use |
|---|---|
| `evidence-summary.json` | Best compact machine-readable overview: selected suspect, verdict, attribution percentages, VM totals, and safety flags |
| `incident-report.md` | Concise human operator report with evidence and caveats |
| `observe-snapshot.json` | Unified host, VM, topology, QEMU, attribution, correlation, and evidence-quality snapshot |
| `ebpf-vm-block-latency.json` | Full VM-attributed block-latency report, counters, histograms, diagnostics, and privacy flags |
| `diagnosis.txt` | Human diagnosis rendered for the incident window |
| `manifest.json` | Bundle inventory, modes, and SHA-256 digests |

Supporting topology, QEMU, trace-plan, and experiment files remain separate so
their semantics are not blurred into one synthetic metric.

Verify a bundle:

```bash
capture=/path/to/capture-directory
jq . "$capture/evidence-summary.json" >/dev/null
jq -r --arg directory "$capture" \
  '.files[] | "\(.sha256)  \($directory)/\(.path)"' \
  "$capture/manifest.json" | sha256sum -c -
```

The interactive Observe workflow first displays a compact summary. Its detailed
JSON stays in memory unless the operator presses `s`; an explicit save creates
a private `observe-<timestamp>-<vm>.json` below the existing configured capture
root. Pressing `b` discards unsaved detail and returns to monitoring.

## Configuration

Configuration precedence is:

```text
--config <path>
    > SOLIS_CONFIG
    > installer-embedded default
    > built-in development defaults
```

The repository lab configuration is [lab/config/solis.json](lab/config/solis.json)
and its inventory is [lab/config/vms.csv](lab/config/vms.csv). Built-in paths
describe this repository lab; a different host should provide an explicit
configuration.

Examples:

```bash
solis --config /etc/solis/config.json doctor
sudo env SOLIS_CONFIG=/etc/solis/config.json solis monitor
```

Treat configuration and inventory as trusted operator input. Solis does not
discover or manage an arbitrary fleet.

## Controlled lab scenario

The optional lab keeps two small application paths active:

```text
a-client -> a-web -> PostgreSQL on a-db
b-client -> b-web -> PostgreSQL on b-db
```

It can add a bounded storage neighbor on `b-stress`: two 4 KiB direct-write fio
jobs, 800 IOPS each by default (about 1,600 IOPS or 6.25 MiB/s total), using a
fixed 1 GiB file. Random writes overwrite that fixed range; the file does not
grow indefinitely.

### One-time deployment

The lab VMs must already exist, be running, and be reachable through the fixed
lab inventory. Install both application paths and their two-hour database
retention timers:

```bash
./lab/scripts/deploy-tenant-workload.sh tenant-a
./lab/scripts/deploy-tenant-workload.sh tenant-b
```

Review the active scenario plan, then install it:

```bash
./lab/scripts/manage-active-lab.sh setup --dry-run
./lab/scripts/manage-active-lab.sh setup
```

`setup` starts five requests/second per tenant and installs the pressure unit on
`b-stress`, but leaves pressure inactive.

### Operate the scenario

```bash
# Applications active; pressure stopped and its file removed.
./lab/scripts/manage-active-lab.sh normal

# Applications active plus bounded b-stress pressure.
./lab/scripts/manage-active-lab.sh pressure

# Read-only client/service/file status.
./lab/scripts/manage-active-lab.sh status

# Stop generated traffic and delete the pressure file.
./lab/scripts/manage-active-lab.sh stop

# Remove scenario services and the pressure file.
./lab/scripts/manage-active-lab.sh remove
```

Then observe the transition in another terminal:

```bash
sudo solis
```

These guest services and workloads are opt-in lab fixtures. They are not
installed by the Solis binary and are not a production workload model. The
clients retain no bodies or secrets and emit only bounded aggregate summaries;
the database retention timer removes demonstration rows older than two hours.

## Validation

### Source validation

```bash
gofmt -w cmd internal
go mod tidy -diff
go mod verify
go test -count=1 ./...
go build -o solis ./cmd/solis
bash -n lab/scripts/run-mvp-demo.sh
bash -n internal/ebpf/bpf/generate.sh
git diff --check
```

Normal builds use the committed authentic eBPF ELF. They do not regenerate it.

### VM-attribution scenarios

```bash
./lab/scripts/validate-vm-attribution.sh --dry-run
./lab/scripts/validate-vm-attribution.sh --scenario all
```

The harness covers idle, suspect-only, victim-only, and mixed activity. It
validates JSON, manifest checksums, file modes, attribution expectations, and
privacy boundaries.

### Live application-impact scenario

```bash
./lab/scripts/validate-live-app-impact.sh --dry-run
./lab/scripts/validate-live-app-impact.sh
```

This aligns normal application traffic, `b-stress` pressure, a Solis capture,
and recovery. It retains aggregate timing/status counters only. The recorded
lab run completed all 3,600 scheduled requests, selected `b-stress`, attributed
more than 99% of block work, and showed recovery after pressure. That is a
controlled time correlation, not a universal causality claim.

### eBPF overhead and safety

```bash
./lab/scripts/benchmark-ebpf-overhead.sh --dry-run

mkdir -m 0700 /tmp/solis-ebpf-review
./lab/scripts/benchmark-ebpf-overhead.sh \
  --iterations 6 \
  --control-pairs 2 \
  --duration-seconds 60 \
  --rate-mib 25 \
  --output-dir /tmp/solis-ebpf-review
```

The completed six-pair/two-control lab run passed collector lifecycle, bounded
instrumentation, attribution, and privacy safety checks. Userspace collection
used about 0.91% of one CPU core and roughly 31 MiB maximum RSS on that host.
Large baseline/control variance prevented a directional latency-overhead
conclusion, so the benchmark deliberately reports manual review rather than an
automatic performance pass.

### Temporary lab cleanup

Preview before deleting current-user-owned, allowlisted Solis artifacts:

```bash
./lab/scripts/cleanup-solis-temp.sh
./lab/scripts/cleanup-solis-temp.sh --kind evidence --older-than-days 7
```

Apply only after reviewing the preview, and do not run this helper with sudo:

```bash
./lab/scripts/cleanup-solis-temp.sh --kind evidence --older-than-days 7 --apply
```

## Safety and privacy

Solis is read-only with respect to VM lifecycle, guest services, storage
configuration, and kernel policy. Its eBPF programs are attached temporarily
for an observation window and detached during cleanup.

Solis telemetry does **not** collect or emit:

- process command lines or arguments;
- process environment variables;
- SQL or normalized query text;
- guest file contents or database table data;
- HTTP request or response bodies;
- application payloads;
- passwords, tokens, private keys, or other secrets; or
- raw kernel pointers, request addresses, or other kernel addresses.

Reports retain aggregate counters, timings, VM identity, sanitized topology,
bounded diagnostic text, evidence quality, and explicit privacy flags. Access
is still governed by normal Linux, libvirt, procfs, filesystem, and eBPF
permissions.

## Requirements and compatibility

See [REQUIREMENTS.md](REQUIREMENTS.md) for the complete runtime, build,
regeneration, and optional-lab dependency sets.

The release runtime currently expects:

- little-endian x86-64 Linux;
- local KVM/QEMU VMs managed by libvirt;
- cgroup v2 mounted at `/sys/fs/cgroup`;
- kernel BTF at `/sys/kernel/btf/vmlinux`;
- compatible typed-BTF `block_rq_issue` and `block_rq_complete` hooks;
- compatible request/bio/blkcg/cgroup/kernfs BTF fields;
- access to local libvirt and required procfs/sysfs metrics; and
- host policy and capabilities that permit BPF loading and typed tracing.

Secure Boot lockdown, LSM policy, `perf_event_paranoid`, BPF sysctls, capability
sets, or incompatible BTF can prevent attachment even when effective UID is 0.
`solis ebpf doctor` reports readiness and relevant diagnostics; changing
security policy remains an operator decision.

The release binary embeds the authentic eBPF ELF. A target host does not need
Go, Clang, LLVM, Docker, Python, or libbpf development headers merely to run
Solis.

## Release and installation

The current release is [`v1.0.0-experimental`](https://github.com/safwen511/solis-io/releases/tag/v1.0.0-experimental).
Its Linux/amd64 archive includes:

- `solis`;
- `INSTALL.md`;
- `REQUIREMENTS.md`;
- `LICENSE` and `NOTICE`;
- `RELEASE-METADATA.json`; and
- internal plus archive SHA-256 checksums.

The release builder requires a clean exact `vMAJOR.MINOR.PATCH-experimental`
tag, verifies the authentic embedded object and its Go map layouts, embeds
version/commit/build-time/Go/platform metadata, and normalizes archive metadata:

```bash
./scripts/test-release-workflow.sh
./scripts/build-release.sh --output-dir dist
```

Byte-identical rebuilds require the same Go toolchain, module inputs, committed
eBPF object, and release script. The release tag is signed; archive artifacts
currently have SHA-256 checksums but no detached signature, SBOM, or provenance
attestation.

## Limitations

- Solis is experimental and validated primarily on the included lab host.
- Collection is single-host and focused on Linux/KVM/libvirt with cgroup v2.
- The published release target is Linux/amd64 only.
- Kernel BTF and typed-BTF hook/field compatibility remain hard requirements
  for VM-attributed latency.
- CO-RE reduces kernel-layout sensitivity but cannot remove it completely.
- Secure Boot lockdown, LSM rules, or missing capabilities may block eBPF.
- Request merging, requeues, missing bio/blkcg ownership, unknown cgroups,
  window boundaries, and map pressure can reduce attribution coverage.
- Device mapper, LVM, encryption, partitions, and other stacked devices can
  make physical-layer interpretation ambiguous.
- Block-request latency is not equivalent to customer-facing application
  latency or proof of causality.
- Fixed-bucket p50/p95/p99 values are approximate.
- QEMU, cgroup `io.stat`, and libvirt block counters are supporting evidence,
  not interchangeable latency measurements.
- The dashboard keeps bounded in-memory history and derived events; it is not a
  durable time-series database.
- There is no API server, daemon, fleet controller, automatic remediation, VM
  control, authentication layer, Debian/RPM package, or package-manager
  lifecycle.
- Collector safety has been exercised in the lab, but a defensible universal
  performance-overhead bound has not been established.
- Archive checksums and a signed tag exist; detached artifact signatures, SBOM,
  and provenance attestations do not yet.

## Roadmap

Near-term work stays focused on making the existing single-host product more
defensible rather than broadening it prematurely:

1. Longer attach/detach, cancellation, VM-restart, cgroup-replacement, and map
   pressure soak tests.
2. A published compatibility matrix across kernels, BTF layouts,
   libvirt/QEMU versions, cgroup layouts, and storage stacks.
3. Performance characterization on quieter and additional hosts with balanced
   controls.
4. Detached artifact signatures, SBOM/provenance metadata, and fresh-host
   installation smoke tests.
5. More compact trend visualization and evidence filtering while keeping the
   console read-only and honest about unavailable data.

Multi-host orchestration, remote agents, automatic VM remediation, and broader
hypervisor support remain outside the current roadmap.

## License and attribution

Copyright (C) 2026 Safwen.

Solis I/O is licensed under [GPL-3.0-only](LICENSE). Distributed copies and
modified versions must preserve the applicable notices and comply with GPLv3,
including corresponding-source and same-license obligations. See [NOTICE](NOTICE)
for project attribution.

This project was developed as an internship project hosted by
[EO Data Center](https://www.eodatacenter.com/), Tunisia. The EO Data Center
name and logo remain the property of EO Data Center; the logo is included only
to identify and acknowledge the host organization and is not covered by the
project's GPL-3.0-only license.
