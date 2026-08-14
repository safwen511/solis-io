# Solis I/O

Solis I/O is a single-host Linux/KVM/libvirt observability tool that correlates provider-side block latency with local VM ownership to investigate storage noisy-neighbor incidents.

> **Current release milestone:** `v0.3.0-experimental` — working and repeatably validated in the included lab, but not production-ready.

## What problem it solves

When a customer reports that a VM is slow, host-wide disk metrics rarely answer the operational questions that matter:

- Is the slowdown consistent with provider-side storage pressure?
- Do the victim and a suspected neighbor share the same storage path?
- Which VM was issuing block I/O during the observation window?
- What latency did those attributed block requests experience?
- How much work could not be attributed safely?

Solis combines libvirt inventory, storage topology, QEMU process accounting, cgroup validation counters, and eBPF block-request latency into one provider-side evidence chain. It can identify a dominant local VM contributor and show whether the victim and suspect shared a storage path during the same observation window. Report-backed or controlled-lab application measurements can strengthen that correlation; infrastructure telemetry alone does not prove customer impact or root cause.

## Current milestone

`v0.3.0-experimental` provides a working experimental single-host investigation path:

- Real typed-BTF eBPF programs attach to `block_rq_issue` and `block_rq_complete`.
- Issue and completion events are correlated inside the kernel to measure request latency.
- Read, write, flush, discard, and unknown operations are classified.
- Latency is aggregated by block-device `major:minor` identity.
- Requests are attributed through blkcg ownership to exact validated libvirt VM cgroup IDs.
- Host and per-VM totals, fixed histograms, approximate percentiles, attribution quality, and unattributed counters are reported.
- VM-attributed latency is integrated into `diagnose noisy-neighbor`, `capture noisy-neighbor`, and `watch noisy-neighbor`.
- Capture-generated `observe-snapshot.json` reuses the same VM-attribution report without a second eBPF attachment and preserves the report's own timestamp and duration.
- Suspect discovery ranks same-storage local VMs and can select the dominant writer without an explicit `--suspect`.
- Diagnosis supports human output and machine-readable JSON; capture writes private evidence bundles with checksums and an operator report.
- A bounded `a-client -> a-web -> a-db` workload and a live-impact harness align application baseline, pressure, and recovery phases with Solis evidence.
- A paired eBPF overhead/safety harness separates collector safety from inconclusive or review-only performance results.
- A deterministic Linux/amd64 archive workflow embeds the authentic eBPF ELF and records release identity and checksums.
- The current source includes a read-only, keyboard-navigable `solis top`
  dashboard that refreshes bounded QEMU pressure and optional VM-attributed
  eBPF latency windows. It also includes the shorter `monitor`, `investigate`,
  and `bundle` operator commands, a bounded derived state-change feed, and a
  generic selected-VM investigation panel with recent evidence windows and
  same-storage peers. The bare interactive application keeps the Solis wordmark
  visible and adds a fixed allowlisted Command Center for existing workflows;
  it does not provide arbitrary command execution or VM controls.
- An opt-in lab-only steady-traffic service can keep both tenant application
  paths active at a low bounded rate. A database timer retains only two hours
  of demonstration rows; it is not installed by the Solis binary.

The following remain deliberately out of scope: a daemon or service, multi-host collection, a controller, remote agents, VM control operations, automatic remediation, and package-manager integration. Solis remains a local, operator-driven observability and attribution tool.

## Architecture

Solis builds evidence in layers:

1. **Libvirt VM inventory** resolves VM identity, tenant, role, runtime state, QEMU PID, qcow2 disk, and validated VM cgroup paths and inode IDs.
2. **Storage topology** maps qcow2 files through filesystem source, parent device, and physical disk.
3. **QEMU pressure** samples `/proc/<qemu-pid>/io` byte and syscall counters. High `syscw/s` is a fallback activity signal when byte counters do not advance meaningfully; it is not treated as an exact byte count.
4. **Validation counters** use cgroup v2 `io.stat` and `virsh domstats --block` deltas. These provide byte, operation, and virtual-disk timing evidence, not host block-latency histograms.
5. **Typed-BTF eBPF latency** correlates block request issue and completion, extracts operation and device metadata, and resolves blkcg ownership.
6. **Top, observe, diagnosis, capture, and watch** present or combine storage sharing, QEMU pressure, VM-attributed eBPF evidence, explicit missing evidence, and conservative correlations or verdict rules.

The capture workflow writes private, atomic evidence bundles containing the human diagnosis, `incident-report.md`, `evidence-summary.json`, raw `ebpf-vm-block-latency.json` when requested, a compact privacy-safe attribution projection in `observe-snapshot.json`, and `manifest.json` checksums. The observe projection excludes raw loader diagnostics and cgroup identifiers and labels the reused diagnosis evidence window explicitly.

## eBPF attribution design

The runtime ownership path is:

```text
request -> bio -> bi_blkg -> blkcg -> css -> cgroup -> kernfs_node.id
```

`block_rq_issue` stores an issue timestamp and sanitized metadata in bounded BPF maps. `block_rq_complete` looks up the same opaque request identity, calculates latency, and updates fixed host, device/operation, and cgroup/device/operation aggregates.

The measured interval is Linux block-request issue-to-completion latency on the host. It is not HTTP latency, database execution time, guest-visible device latency, or an exact physical-media service-time measurement. The live-impact harness reports application timing separately so those evidence layers are not conflated.

The request identity is used only inside the kernel as a bounded correlation key. Raw request addresses, bio pointers, blkcg pointers, cgroup pointers, and other kernel addresses are never emitted to userspace or JSON.

Userspace attributes an aggregate only when the extracted cgroup ID exactly matches a cgroup ID from the validated libvirt VM mapping. Missing bio or blkcg ownership, unknown cgroups, lookup misses, duplicate or reissued requests, map pressure, and requests incomplete at window end remain explicit unattributed work.

Attribution quality is conservative:

- `available`: no more than 5% unattributed work
- `degraded`: more than 5% and no more than 25% unattributed work
- `unavailable`: more than 25%, no completed attributed events, no VM match, or an unsupported ownership path

Request merging, requeues, stacked storage layers, and kernel-specific layouts can still affect what is attributable. The result is evidence, not perfect attribution or proof of customer impact.

### What Solis uses from Cilium eBPF

The Go module pins `github.com/cilium/ebpf` at `v0.22.0`. Solis uses its
userspace APIs to parse the embedded authentic ELF (`LoadCollectionSpecFromReader`),
load and assign programs and maps (`LoadAndAssign`), retain bounded verifier
diagnostics (`VerifierError`), attach the two typed tracing programs
(`link.AttachTracing`), inspect kernel BTF (`btf.LoadKernelSpec` plus type and
member lookups), and read, iterate, and close BPF maps, programs, and links. The
generator also pins Cilium's `bpf2go` command at `v0.22.0`.

Cilium is not the attribution algorithm, and Solis does not use BCC or libbpf
Go bindings. The project-owned BPF C program defines request correlation,
CO-RE metadata reads, blkcg ownership traversal, counters, and aggregate maps.
Packaged libbpf headers are used only while compiling that source in the
controlled generator container. Cilium supplies the pure-Go loading,
typed-tracing attachment, BTF inspection, map access, and lifecycle layer.

## Example output

A compact, sanitized successful result resembles:

```json
{
  "collection_mode": "typed_btf_vm_attributed_latency",
  "attribution_method": "blkcg_cgroup_id_to_libvirt_vm",
  "attribution_quality": "available",
  "attribution_summary": {
    "attributed_ops": 32094,
    "unattributed_ops": 122,
    "attributed_percent": 99.62,
    "matched_vm_count": 1
  },
  "vms": [
    {"name": "a-web", "total_ops": 0},
    {"name": "b-stress", "total_ops": 32094}
  ],
  "privacy": {
    "process_arguments_collected": false,
    "environment_collected": false,
    "guest_files_collected": false,
    "query_text_collected": false,
    "table_data_collected": false,
    "request_body_collected": false,
    "response_body_collected": false,
    "secrets_collected": false
  }
}
```

The numbers above illustrate the validated lab shape; they are not performance guarantees.

## Build and commands

Solis is built with Go. A normal build uses the authentic embedded eBPF object and does not require Clang:

```bash
go test ./...
go build -o solis ./cmd/solis
./solis doctor
./solis inventory
```

### Experimental release archive

Release archives are built only from a clean commit carrying an exact tag of
the form `vMAJOR.MINOR.PATCH-experimental`:

```bash
mkdir -p dist
./scripts/test-release-workflow.sh
./scripts/build-release.sh --output-dir dist
(cd dist && sha256sum -c solis-v0.3.0-experimental-linux-amd64.tar.gz.sha256)
```

The builder verifies that the committed eBPF object is a non-empty ELF and
that its map layouts match the Go runtime types before compiling. It produces
a statically configured `linux/amd64` binary with the version, full Git commit,
commit-derived UTC build time, Go version, and platform embedded in `solis
version`. Host paths and the linker build ID are removed, and archive ownership,
ordering, and timestamps are normalized to the tagged commit. Byte-identical
rebuilds require the same Go toolchain, module inputs, committed eBPF object,
and release script.

Each archive contains `solis`, `INSTALL.md`, `LICENSE`, `RELEASE-METADATA.json`, and
internal checksums; the adjacent `.sha256` verifies archive integrity. See
[`docs/INSTALL.md`](docs/INSTALL.md) for fixed-path atomic installation,
uninstallation, non-invasive post-install checks, kernel/libvirt/cgroup
requirements, privileges, and lockdown limitations. The archive installs no
daemon, service, user, scheduled job, controller, or remote agent. Target hosts
do not need Clang or LLVM because the authentic object is embedded.

The release workflow was validated by building the same tagged source twice
and comparing byte-identical archives. This reproducibility statement is
conditional on the same Go toolchain, module inputs, committed eBPF object,
and release script. The release tag is cryptographically signed; the archive
is checksummed but does not yet have a detached artifact signature, SBOM, or
provenance attestation.

Portable configuration is selected with `--config`, then `SOLIS_CONFIG`, then
an installer-embedded default path when present, and finally built-in
development defaults. The built-in paths are intended for the repository lab,
not installed production use.

### Fast operator workflow

On an interactive terminal, running Solis without a subcommand opens the live
monitor. `monitor` is the explicit equivalent and enables VM-attributed eBPF
collection by default:

```bash
sudo ./solis
sudo ./solis monitor
```

For the current development checkout, install a checkout-aware command once
and then invoke Solis from any directory:

```bash
./scripts/install-dev-command.sh
cd /tmp
sudo solis
```

The installer atomically rebuilds Solis, installs a root-owned
`/usr/local/bin/solis` binary, and installs a root-owned
`/etc/solis/config.json`. That generated configuration contains absolute paths
to this checkout's inventory and report directories, so they do not depend on
the caller's working directory. It installs no daemon or service. The installed
binary never executes a user-writable wrapper or checkout binary under sudo.
Because this is a development installation, the checkout must remain at the
same path; use the release installation procedure in
[`docs/INSTALL.md`](docs/INSTALL.md) for a standalone binary and supply an
explicit production configuration. A caller-provided `--config` still takes
precedence over the installed default.
The installer refuses existing targets unless an intentional update is
requested with `./scripts/install-dev-command.sh --replace`.

The application keeps Solis branding visible on every interactive frame rather
than treating it as a transient splash. Wide terminals keep the full block
wordmark even when their height is modest; narrow terminals use a compact
persistent brand so the working data remains readable. Boxed Session, Live Evidence, Navigation,
and active-workspace regions give timing, measurements, navigation, and the VM
table distinct visual hierarchy. Home shows host/storage status and all VMs in
the resolved Solis inventory; VM profiles, events, and a Command Center live in
separate panels so a normal terminal does not scroll on every refresh. Running VMs receive live QEMU
pressure and, when quality permits, VM-attributed block operations and latency.
Stopped or paused VMs remain selectable but never receive fabricated zero-I/O
metrics. Press Enter on a selected VM to open its identity, network, addressing,
configured capacity, disk-backend, pressure, operation, latency, and attribution
details. The Command Center exposes fixed allowlisted in-application workflows for investigation,
private capture, watch, observe, system/eBPF doctors, inventory, status, and
version. It never accepts a shell command. Before a workflow starts, Solis
cancels the active evidence window and detaches the collector and eBPF links.
The workflow then runs asynchronously in a bounded, sanitized output panel
without leaving the application. Press `b` after completion to return to the
Command Center and resume live evidence collection. The terminal is restored
only when the operator quits Solis.

The wide header's upper-right process block reports Solis's own CPU use as a
percentage of one core, current RSS memory, actual process disk-read and
disk-write rates, goroutine count, and uptime. These are live aggregate
self-metrics, not host totals or VM metrics. Disk I/O is process throughput for
the current interval; it is not evidence-directory size or total disk capacity.
The self-meter reads no process arguments, environment values, open filenames,
payloads, or other-process data.

Observe renders a compact evidence summary instead of paging through the full
JSON snapshot. The detailed JSON remains in memory until the operator answers
the on-screen prompt: press `s` to save it as a private `0600`
`observe-<timestamp>-<vm>.json` file directly beneath the configured
`capture_output_root`, or press `b` to discard it and resume monitoring. The
save uses the same symlink-resistant, same-parent atomic private writer as
other hardened single-file output. The parent directory must already exist.

The short investigation commands reuse the existing diagnosis and private
capture implementations. With one VM argument, Solis discovers a same-storage
suspect; a second VM argument selects the suspect explicitly:

```bash
sudo ./solis investigate a-web
sudo ./solis investigate a-web b-stress

sudo ./solis bundle a-web
sudo ./solis bundle a-web b-stress
```

`bundle` writes beneath the configured `capture_output_root`. `investigate`
and `bundle` enable VM-attributed eBPF evidence by default; pass
`--include-ebpf-latency=false` for an explicitly non-eBPF run. The established
long forms remain supported for scripting and fine-grained options. Bare Solis
prints help instead of starting an endless monitor when input or output is not
a terminal. These are fixed, allowlisted command aliases—not arbitrary command
execution.

### VM and host status

```bash
./solis status
./solis status --json
./solis status --watch --iterations 5 --sort pressure --no-clear
./solis vm storage-stats --victim a-web --suspect b-stress --duration 5s --interval 1s --json
```

### Read-only terminal dashboard

`solis top` repeatedly samples the existing provider-side status model. It
shows mapped physical storage, per-VM QEMU write pressure, and explicit
unavailable states without requiring eBPF:

```bash
./solis top

# A finite, log-friendly run without terminal clear sequences.
./solis top --iterations 3 --every 5s --sort write --no-clear
```

VM-attributed block operations and approximate p95 latency are opt-in because
loading the eBPF collector normally requires elevated host privileges:

```bash
sudo ./solis top \
  --include-ebpf-latency \
  --duration 3s \
  --interval 1s \
  --every 5s \
  --sort ops
```

For the normal interactive experience, `sudo ./solis monitor` selects a 5-second
observation window, a 7-second evidence-collection cadence, a 200 ms display
refresh, and eBPF attribution by default. The fast display refresh updates
navigation, collection state, and the age of the last completed measurement;
it does not present stale evidence as a new 200 ms kernel sample. A custom
display cadence can be selected with `--ui-refresh 500ms` (minimum 100 ms).
The lower-level `top` defaults remain unchanged.

Each refresh starts bounded status and eBPF samples in the same local
observation window. On a real terminal, the dashboard temporarily enables
character-at-a-time input while preserving normal Ctrl-C signal handling, and
uses the terminal alternate screen so redraws do not accumulate as repeated
applications in shell scrollback. It restores the cursor, primary screen, and
original terminal settings only after active collector cleanup. The header
separately reports collection state, evidence cadence, display refresh, last
completion time, and data age. Each complete frame is assembled in memory and
written to the terminal in one operation. Every occupied row is erased before
it is repainted, and unused rows below the frame are cleared afterward. This
prevents shorter rows or panels from retaining stale suffixes without a
flashing full-screen clear or visible partial-frame tearing during the default
200 ms display refresh. Terminal dimensions are queried on every frame: a
narrow resized terminal switches to a compact wordmark, split status
rows, reduced VM columns, shorter keys, and a compact Command Center instead of
allowing wide tables to corrupt adjacent rows or pushing controls off-screen.
Use `j`/`k` or the up/down arrows to select a VM. Tab or left/right cycles Home,
Investigate VM, Events, and Command Center; the number keys `1` through `4`
open them directly. Enter investigates the selected VM or runs the selected
fixed workflow inside Solis. Workflow output has a persistent line-position and
keyboard hint and is scrollable with `j`/`k` or the up/down arrows; `b` returns
to the Command Center and resumes monitoring after the workflow completes.
Observe additionally offers `s` to persist its private detailed snapshot.
Selected VMs and commands use a `▶` marker, and table columns have explicit
visual separators. Interactive frames use restrained semantic terminal colors
for selection, availability, degraded/error states, and section identity;
redirected output stays plain, and setting `NO_COLOR` disables color. `n`,
`p`, `w`, `o`, and `l` sort by
name, pressure, write rate, attributed operations, and p95 latency; `r`
refreshes, `?` shows help, and `q` exits. The selected-VM panel shows operation
classes, p50/p95/p99, mapping
quality, and bounded device/operation aggregates. The event panel retains at
most 12 controlled state transitions derived from adjacent samples: QEMU
pressure changes, attribution availability/quality changes, and changes in the
dominant attributed VM. It is explicitly not a raw kernel event stream or an
alert/root-cause timeline.
Redirected output, `--iterations`, and `--no-clear` retain the deterministic
non-interactive renderer. Live monitoring is read-only and has no VM actions,
arbitrary command execution, daemon, or new verdict logic. Command Center
actions reuse established CLI workflows inside a bounded output panel;
monitoring, diagnosis, readiness,
inventory, status, watch, observe, and version are read-only until the operator
explicitly confirms an Observe detail save. Bundle writes a private evidence
directory through the hardened capture writer; confirmed Observe detail uses
the hardened private atomic file writer. Parameter-heavy pair/report commands remain listed in the
Command Center as advanced CLI capabilities rather than receiving guessed
inputs.
When the eBPF collector is not requested, denied, degraded, or unavailable,
that state remains visible and missing per-VM latency is rendered as `-` rather
than a fabricated zero. Access to per-QEMU `/proc/<pid>/io` counters may also
require elevated permission; the dashboard marks those VM pressure rows
unavailable instead of treating them as idle.

When running the lab fio helper in the background beside the interactive
application, detach its stdin so the shell cannot suspend its SSH process for
attempting terminal input:

```bash
./lab/scripts/run-fio-noise.sh b-stress 60 --durable --rate-iops 3200 \
  </dev/null >/tmp/solis-app-fio.txt 2>&1 &
fio_pid=$!
sleep 10
sudo ./solis
wait "$fio_pid"
```

The helper itself also invokes SSH with detached stdin; the explicit redirect
makes that ownership clear in copied operator commands.

### Unified observe snapshot

```bash
./solis observe snapshot \
  --victim a-web \
  --discover-suspects \
  --duration 10s \
  --interval 2s \
  --json
```

The standalone command combines host, VM/QEMU, storage, and configured guest/service/database evidence without claiming causality. When capture is run with `--include-ebpf-latency`, its `observe-snapshot.json` also embeds the already-collected VM-attribution summary; it does not attach a second eBPF collector. The embedded report keeps its original `observed_at_utc`, `duration`, quality, and unattributed percentage so adjacent evidence windows are not presented as identical.

### eBPF readiness and VM-attributed latency

```bash
./solis ebpf doctor

sudo ./solis ebpf vm-block-latency \
  --victim a-web \
  --suspect b-stress \
  --duration 10s \
  --interval 1s \
  --json
```

`ebpf doctor` is non-invasive and does not load a program. The latency command requires the kernel permissions needed to load and attach eBPF; Solis never invokes `sudo` internally.

### Diagnose

Human report:

```bash
sudo ./solis diagnose noisy-neighbor \
  --victim a-web \
  --suspect b-stress \
  --duration 10s \
  --interval 2s \
  --include-ebpf-latency
```

Machine-readable diagnosis:

```bash
sudo ./solis diagnose noisy-neighbor \
  --victim a-web \
  --suspect b-stress \
  --duration 10s \
  --interval 2s \
  --include-ebpf-latency \
  --json \
  --output ./diagnosis.json
```

The output file contains JSON only. The confirmation message is written separately to stdout. Diagnosis output uses a private mode-`0600` same-directory temporary file and atomic rename; its parent directory must already exist, and symbolic-link or non-regular targets are rejected. The equivalent leading global form is also accepted:

```bash
sudo ./solis --json diagnose noisy-neighbor \
  --victim a-web \
  --suspect b-stress \
  --duration 10s \
  --include-ebpf-latency \
  --output ./diagnosis.json
```

Add `--report-dir <dir>` for report-backed application evidence, or use `--discover-suspects` instead of an explicit suspect.

### Capture and watch

```bash
sudo ./solis capture noisy-neighbor \
  --victim a-web \
  --discover-suspects \
  --duration 10s \
  --interval 2s \
  --include-ebpf-latency \
  --output-dir ./captures

sudo ./solis watch noisy-neighbor \
  --victim a-web \
  --discover-suspects \
  --window 10s \
  --every 30s \
  --include-ebpf-latency \
  --capture-on-alert \
  --output-dir ./captures
```

Watch uses VM-attributed eBPF latency as an additional evidence layer. Degraded or unavailable attribution does not independently create an alert; existing non-eBPF evidence must still support it.

## Lab validation

The release was validated on the included x86-64 Ubuntu/KVM/libvirt lab with
Linux `7.0.0-29-generic`, kernel BTF, cgroup v2, local qcow2-backed VMs, and the
committed little-endian eBPF object. Controlled durable fio workloads produced
these outcomes:

- Typed-BTF programs loaded and attached successfully on the test kernel.
- Host request issue/completion latency events and fixed histograms populated.
- Idle, suspect-only, victim-only, and mixed-load scenarios all passed their
  expected attribution assertions.
- Suspect-only attribution selected `b-stress` with 99.53% attributed work in
  the recorded run; the victim-only run retained 93.98%, and the mixed run
  retained 96.52% while representing both active VMs.
- The idle scenario remained honest: it did not fabricate VM latency when no
  useful attributed activity was present.
- Diagnosis, discovery, capture, observe projection, manifest checksums, file
  modes, and privacy scans passed together.
- All privacy flags remained false.

These are recorded results from one controlled host profile, not fixed expected
operation counts or compatibility/performance guarantees. They validate the
implementation and evidence path in this lab; they do not establish universal
kernel compatibility or causality for arbitrary workloads.

The repeatable lab harness validates idle, suspect-only, victim-only, or mixed VM activity. It checks capture modes, JSON, manifest checksums, attribution expectations, stale evidence states, permissions, and privacy boundaries:

```bash
# Inspect the plan without sudo, SSH, or workload generation.
./lab/scripts/validate-vm-attribution.sh --dry-run

# Short targeted validation.
./lab/scripts/validate-vm-attribution.sh --scenario suspect

# Longer mixed-load window. The output directory must already exist,
# must not be a symlink, and must have mode 0700.
mkdir -m 0700 /tmp/solis-long-validation
./lab/scripts/validate-vm-attribution.sh \
  --scenario mixed \
  --window-seconds 600 \
  --interval-seconds 2 \
  --warmup-seconds 10 \
  --fio-seconds 1220 \
  --output-dir /tmp/solis-long-validation
```

Without `--output-dir`, the harness creates a private directory under `/tmp`. It requires interactive sudo authentication and allowlisted SSH access to the included stress VMs. Non-idle scenarios create only the fixed `/home/flint/solis-noise.dat` fio test file on `a-stress` and/or `b-stress`; cleanup stops its fixed fio job and removes that file. The harness uses the fio helper's opt-in durable mode, which requests a data sync after every 1,024 writes so the evidence window observes provider-side block activity instead of only QEMU page-cache pressure. Normal uses of `run-fio-noise.sh` remain unchanged. To avoid disturbing work it does not own, preflight refuses to run if the fixed job or file already exists. Each scenario retains its private capture and checks, and the root ends with a compact `validation-report.json`. The harness does not alter VM configuration or services.

The repository's lab-only workload and demo scripts are not part of the Solis product command path.

### Normal tenant-A application traffic

The lab includes a bounded client workload for the existing application path:

```text
a-client -> a-web GET /write -> PostgreSQL INSERT on a-db
```

Deploying the client copies one project-owned Python program to `a-client`; it does not enable a daemon or background service:

```bash
./lab/scripts/deploy-client-workload.sh
```

Generate a fixed 30 requests/second for 60 seconds, with no more than 20 requests in flight:

```bash
client_report=$(mktemp /tmp/a-client-traffic-XXXXXXXX.json)
./lab/scripts/run-client-workload.sh \
  --duration 60 \
  --rate 30 \
  --concurrency 20 \
  > "$client_report"
echo "Client report: $client_report"
```

The client has a fixed target (`a-web` at `192.168.130.20/write`), bounded duration/rate/concurrency, and produces deterministic aggregate JSON with one-second windows. It retains no request or response bodies, SQL text, table data, or secrets. The default represents steady lab traffic rather than a literal count of production users; increase the rate only after confirming that `a-client` itself is not saturated. This traffic can run continuously across a baseline, `b-stress` pressure, and recovery sequence while Solis captures provider-side evidence.

### Always-on two-tenant lab traffic

For a monitor that always has a small realistic application baseline, deploy
both tenant web/database services first. Re-running these commands also installs
and starts a database retention timer that deletes demonstration rows older
than two hours every 15 minutes:

```bash
./lab/scripts/deploy-tenant-workload.sh tenant-a
./lab/scripts/deploy-tenant-workload.sh tenant-b
```

Review the continuous-client plan without SSH or changes, then deploy it to
`a-client` and `b-client` at the default two requests/second each:

```bash
./lab/scripts/manage-steady-traffic.sh deploy --tenant all --rate 2 --dry-run
./lab/scripts/manage-steady-traffic.sh deploy --tenant all --rate 2
./lab/scripts/manage-steady-traffic.sh status
```

The fixed paths are `a-client -> a-web -> a-db` and
`b-client -> b-web -> b-db`. The client services restart after a failure and at
boot, retain no request or response bodies, and emit only one bounded aggregate
summary every five minutes. Deploy/start refuses to run unless the matching
database retention timer is active. Stop or remove only these exact lab
services with:

```bash
./lab/scripts/manage-steady-traffic.sh stop
./lab/scripts/manage-steady-traffic.sh remove
```

This is an opt-in controlled lab fixture, not a Solis daemon, remote agent,
production traffic model, or product installation side effect. Even at the
bounded rate it intentionally writes guest storage; qcow2 allocation and
PostgreSQL vacuum behavior should still be monitored during long soak tests.

### Active moderate-pressure lab

The active-lab manager combines both tenant application paths with an optional
moderate `b-stress` storage neighbor. Its default pressure is two rate-limited
4 KiB direct-write jobs at 800 IOPS each: about 1,600 IOPS or 6.25 MiB/s total.
This is intended to yield thousands of completed requests per five-second eBPF
window without reproducing the earlier 50–100 MiB/s stress runs.

Review and install the profile. Setup deploys both clients at five
requests/second and installs, but does not start, the pressure service:

```bash
./lab/scripts/manage-active-lab.sh setup --dry-run
./lab/scripts/manage-active-lab.sh setup
```

All six application VMs and `b-stress` must already be running and reachable
over the fixed lab SSH addresses. Setup preflights `b-stress`, fio, and its
passwordless lab sudo before modifying the client tier; it does not start or
control VMs automatically.

Move between a normal application baseline and moderate neighbor pressure:

```bash
./lab/scripts/manage-active-lab.sh normal
./lab/scripts/manage-active-lab.sh pressure
./lab/scripts/manage-active-lab.sh status
sudo ./solis
```

`normal`, `stop`, and `remove` stop the pressure service and delete its exact
fixed `/var/lib/solis-moderate-pressure/pressure.dat` file. Its dedicated
directory is private to the fixed lab service and is the only writable path
granted through the systemd filesystem sandbox. The pressure file is limited
to 1 GiB and random writes overwrite that fixed range; it does not append
indefinitely. `normal` leaves tenant traffic active, while `stop` also stops
both clients. `remove` removes the scenario services and the empty private
directory. The PostgreSQL two-hour retention timer remains a required
precondition.

The rate can be changed only during setup and remains bounded:

```bash
./lab/scripts/manage-active-lab.sh setup \
  --client-rate 5 \
  --pressure-iops 800
```

The profile is controlled traffic for exercising attribution and latency UI;
it is not a benchmark, production workload model, or proof of application
impact. Exact latency still depends on the host, storage cache, kernel, and
other activity.

### Temporary artifact cleanup

Solis validation can leave disposable build caches and deliberately retained
evidence under `/tmp`. Preview the exact current-user-owned, non-symlink,
allowlisted paths first; the helper defaults to a dry run:

```bash
./lab/scripts/cleanup-solis-temp.sh
./lab/scripts/cleanup-solis-temp.sh --kind evidence --older-than-days 7
```

Apply only after reviewing that preview. Do not run this helper with `sudo`:

```bash
./lab/scripts/cleanup-solis-temp.sh --kind cache --apply
./lab/scripts/cleanup-solis-temp.sh --kind evidence --older-than-days 7 --apply
```

The cache class contains only allowlisted Solis Go caches. The evidence class
contains allowlisted Solis lab captures, reports, and test output directly
under `/tmp`; it may contain the only copy of a validation result. Unrelated
paths, symbolic links, paths owned by another user, and guest fio files are not
removed. The validation and fio helpers separately clean only their fixed guest
test file when they own the workload.

### Live application-impact validation

The live-impact harness automates that complete controlled timeline: normal `a-client` traffic, a baseline window, durable `b-stress` pressure, an overlapping Solis noisy-neighbor capture, and a recovery window. Deploy the current client first so its fixed non-payload process identity is available to safe lifecycle checks:

```bash
./lab/scripts/deploy-client-workload.sh

# Show timing and targets without sudo, SSH, or workload generation.
./lab/scripts/validate-live-app-impact.sh --dry-run

# Run the default 30s baseline, 60s pressure, and 30s recovery scenario.
./lab/scripts/validate-live-app-impact.sh
```

To retain the result at a chosen location, create an empty private directory first:

```bash
mkdir -m 0700 /tmp/solis-live-impact
./lab/scripts/validate-live-app-impact.sh \
  --rate 30 \
  --concurrency 20 \
  --output-dir /tmp/solis-live-impact
```

The harness refuses existing client/fio processes and the fixed fio file, uses exact process names rather than process arguments for lifecycle checks, and cleans up only the workloads it starts. It requires interactive sudo authentication and allowlisted SSH access to `a-client` and `b-stress`. All directories and files are private (`0700` and `0600`). The final `live-impact-report.json` combines baseline/pressure/recovery application timing, selected-suspect evidence, VM-attributed block latency, attribution coverage, caveats, and false privacy flags. It also validates capture JSON, manifest checksums, file modes, phase completeness, and forbidden pointer/process-path output. Application latency movement and VM-attributed storage pressure are time-correlated controlled-lab evidence; the report does not claim universal causality or production impact.

In the recorded default run, all 3,600 requests completed successfully at 30
requests/second without client saturation. Average application latency rose
9.01% during `b-stress` pressure, the worst one-second p95 rose 47.64%, and
recovery average returned to 1.50% below baseline. During the overlapping
Solis window, 99.35% of work was attributed, with 703,153 operations assigned
to `b-stress` and 6 to `a-web`. This is a useful controlled time correlation,
not a general customer-impact or causality claim.

### eBPF overhead and safety benchmark

The paired benchmark harness compares the same bounded fio workload with and without the VM block-latency collector. It rate-limits the default workload to approximately 50 MiB/s, uses periodic data syncs so provider-side block activity is observable, alternates phase order across iterations, and retains collector CPU time, maximum RSS, attribution coverage, map pressure, event-loss counters, fio throughput, and guest-visible latency:

```bash
# Print the benchmark plan without sudo, SSH, or workload generation.
./lab/scripts/benchmark-ebpf-overhead.sh --dry-run

# One short baseline/eBPF pair using b-stress.
./lab/scripts/benchmark-ebpf-overhead.sh

# Six balanced eBPF pairs plus two baseline/baseline variance controls.
mkdir -m 0700 /tmp/solis-ebpf-benchmark
./lab/scripts/benchmark-ebpf-overhead.sh \
  --iterations 6 \
  --control-pairs 2 \
  --duration-seconds 60 \
  --rate-mib 25 \
  --output-dir /tmp/solis-ebpf-benchmark
```

The output directories and files are private (`0700` and `0600`) and end with schema-v2 `benchmark-report.json`, which records the Solis build, kernel, architecture, workload, paired observations, control observations, and aggregate measurements. Each fio phase retains total-latency mean/standard deviation and completion-latency mean, p50, p95, and p99. The report provides mean, median, range, sample standard deviation, and an exploratory paired Student-t 95% interval. Baseline/baseline controls estimate ordinary phase-to-phase variance. At least six eBPF pairs with balanced phase order and two control pairs are required before the report is marked ready for manual performance review.

Safety validation requires a successful collector, target-VM attribution, false privacy flags, and zero map-full, dropped-event, and ring-loss counters. That safety result is separate from performance: the benchmark never emits an automatic performance pass or fail. The rate ceiling deliberately bounds writes and can hide throughput differences, so a zero throughput delta is not evidence of zero overhead. Latency distributions, control variance, confidence intervals, CPU, and RSS must be reviewed together. Even a review-ready result is experimental rather than a production overhead guarantee, and collector CPU time does not include every in-kernel execution cost. The fixed fio file is removed after each phase, and preflight refuses existing fio processes or files it does not own without reading process arguments.

The recorded six-pair/two-control run passed collector safety: attribution stayed
above 99.6%, userspace collector CPU averaged about 0.91% of one core, maximum
RSS was about 31.4 MiB, and map-full, dropped-event, ring-loss, and incomplete
counters remained zero. Performance remained unresolved: paired mean-latency
change averaged +4.41%, the median was -0.82%, and the exploratory 95% interval
spanned -18.53% to +27.35%. Baseline/baseline controls showed much larger
natural variance, so no directional eBPF latency effect or production overhead
bound was established.

## Safety and privacy

The eBPF attribution, diagnosis, capture, watch, and status telemetry paths are designed around counters, timings, topology, and health metadata. They do not collect:

- process command lines or process arguments
- process environment variables
- SQL or normalized query text
- guest file contents
- database table data or dumps
- request or response bodies
- application payloads
- passwords, tokens, private keys, or other secrets
- raw kernel pointers or request addresses

Solis does not modify VMs, services, storage, kernel settings, or tracing mounts. eBPF programs are temporary and detached during cleanup. Access remains governed by normal Linux, libvirt, procfs, and eBPF permissions.

## Limitations

- **Maturity:** Solis is experimental. The working lab and release workflow do
  not constitute a production support, availability, or compatibility promise.
- **Deployment scope:** collection is limited to one local Linux KVM/libvirt
  host using cgroup v2. There is no fleet, remote-host agent, controller, or
  cross-host correlation.
- **Release target:** the current archive is little-endian `linux/amd64` only.
  It is not a Debian/RPM package and does not install a daemon or service.
- **Kernel dependency:** VM attribution requires kernel BTF, compatible
  typed-BTF block hooks and ownership fields, the embedded object, and adequate
  eBPF capabilities. CO-RE reduces but does not eliminate kernel-layout drift.
- **Security policy:** Secure Boot lockdown, LSM policy, tracing permissions,
  or missing capabilities can prevent load/attach even for UID 0. Solis reports
  unavailability; changing host security policy is an operator decision.
- **Latency semantics:** measured latency is host block-request
  issue-to-completion time. It is not directly application latency, guest I/O
  latency, database time, customer impact, or exact physical-media service time.
- **Attribution semantics:** `available` means coverage passed the documented
  unattributed threshold and exact cgroup-ID matches were found. It does not
  mean every request was assigned correctly or that a VM caused victim impact.
- **Block lifecycle:** request merging, requeues, flush behavior, missing
  `bio`/`blkcg`, unknown cgroups, VM/cgroup replacement during a window,
  incomplete requests, and bounded-map pressure can reduce coverage.
- **Storage topology:** device-mapper, encryption, LVM, partitions, and other
  stacked layers can make physical-device interpretation ambiguous. Solis keeps
  validation rows separate rather than blindly summing layers.
- **Percentiles:** p50/p95/p99 values use fixed bounded histograms and are
  approximate bucket estimates. Count, total, minimum, maximum, and average use
  the observed aggregates.
- **Supporting evidence:** cgroup `io.stat`, `virsh domstats`, and QEMU process
  accounting are validation/correlation counters, not equivalent latency
  measurements. QEMU procfs access may require elevated permissions.
- **Diagnosis:** live infrastructure evidence can support a noisy-neighbor
  verdict but cannot independently prove application slowdown. Controlled or
  external application evidence is needed for an impact claim.
- **Performance:** the completed benchmark established safe collector lifecycle
  and stable userspace resource use on one host, but natural storage variance
  prevented a directional latency-overhead conclusion or upper bound.
- **Release trust:** the release tag is signed and archives have SHA-256
  checksums and deterministic metadata, but archive artifacts do not yet have
  detached signatures and do not include an SBOM or provenance attestation.
  Byte-identical rebuilding depends on matching toolchain and module inputs.
- **Operator interface:** the current source includes a compact read-only
  keyboard-navigable, multi-panel dashboard plus CLI/JSON/report workflows.
  The investigation panel retains only eight in-memory completed windows per
  VM and is not a time-series database.
  Its bounded event feed contains derived local state transitions rather than
  raw block events or a durable incident timeline. It has no mouse interface,
  scrollable/height-aware pane engine, API server, automatic remediation, VM
  control, authentication layer, retention manager, or package-manager
  lifecycle. Width changes are handled with a compact adaptive layout.
- **Lab tooling:** workload and validation scripts use the included fixed VM
  names, addresses, and files. They are controlled lab fixtures, not a generic
  production workload framework. The optional steady-traffic systemd units and
  two-hour request-log retention exist only inside the lab VMs.

## Roadmap

With the first read-only terminal dashboard in place, the priorities are:

1. **Soak and lifecycle validation:** exercise longer windows, cancellation,
   repeated attach/detach, VM restart and cgroup replacement, high event rates,
   map pressure, partial evidence, and cleanup failures.
2. **Compatibility matrix:** test additional supported Linux kernels, BTF
   layouts, libvirt/QEMU versions, cgroup v2 layouts, and storage stacks; publish
   explicit supported/degraded/unavailable outcomes.
3. **Performance characterization:** repeat balanced/control measurements on
   quieter and additional hosts, add carefully bounded non-rate-limited trials,
   and avoid publishing an overhead bound until variance supports one.
4. **Release provenance:** automate clean-tag artifact verification, add
   signatures, SBOM/provenance metadata, and fresh-host install smoke tests.
5. **Operator polish:** add clearer compact trend visualization, bounded event
   filtering, and optional report/capture context
   while keeping the interface read-only and raw counters, caveats, privacy
   flags, and unavailable sections visible.

Multi-host orchestration, fleet management, remote agents, automatic VM
remediation, and broader hypervisor support remain outside the current
single-host KVM/libvirt roadmap.

## Copyright and license

Copyright (c) 2026 Safwen. All rights reserved.

Solis I/O is proprietary source code. Access to the repository does not grant
permission to use, copy, modify, redistribute, sublicense, sell, or create
derivative works. See [`LICENSE`](LICENSE) for the complete terms. Third-party
dependencies remain governed by their own licenses.
