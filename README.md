# Solis I/O

Solis I/O is a Linux/KVM/libvirt single-host storage-latency attribution tool for identifying whether provider-side I/O pressure affected a VM and which neighboring VM contributed.

> **Status:** Experimental, working in the included lab, and not production-ready.

## What problem it solves

When a customer reports that a VM is slow, host-wide disk metrics rarely answer the operational questions that matter:

- Is the slowdown consistent with provider-side storage pressure?
- Do the victim and a suspected neighbor share the same storage path?
- Which VM was issuing block I/O during the observation window?
- What latency did those attributed block requests experience?
- How much work could not be attributed safely?

Solis combines libvirt inventory, storage topology, QEMU process accounting, cgroup validation counters, and eBPF block-request latency into one provider-side evidence chain. Report-backed diagnosis can correlate that infrastructure evidence with an application experiment. Live-only diagnosis remains cautious because infrastructure evidence alone cannot prove application impact.

## Current milestone

The current milestone provides a working experimental single-host path:

- Real typed-BTF eBPF programs attach to `block_rq_issue` and `block_rq_complete`.
- Issue and completion events are correlated inside the kernel to measure request latency.
- Read, write, flush, discard, and unknown operations are classified.
- Latency is aggregated by block-device `major:minor` identity.
- Requests are attributed through blkcg ownership to exact validated libvirt VM cgroup IDs.
- Host and per-VM totals, fixed histograms, approximate percentiles, attribution quality, and unattributed counters are reported.
- VM-attributed latency is integrated into `diagnose noisy-neighbor`, `capture noisy-neighbor`, and `watch noisy-neighbor`.
- Capture-generated `observe-snapshot.json` reuses the same VM-attribution report without a second eBPF attachment and preserves the report's own timestamp and duration.
- Diagnosis supports human output and machine-readable JSON.

This is working in the lab, but it remains experimental. Multi-host operation is out of scope, and production packaging and service lifecycle are not implemented.

## Architecture

Solis builds evidence in layers:

1. **Libvirt VM inventory** resolves VM identity, tenant, role, runtime state, QEMU PID, qcow2 disk, and validated VM cgroup paths and inode IDs.
2. **Storage topology** maps qcow2 files through filesystem source, parent device, and physical disk.
3. **QEMU pressure** samples `/proc/<qemu-pid>/io` byte and syscall counters. High `syscw/s` is a fallback activity signal when byte counters do not advance meaningfully; it is not treated as an exact byte count.
4. **Validation counters** use cgroup v2 `io.stat` and `virsh domstats --block` deltas. These provide byte, operation, and virtual-disk timing evidence, not host block-latency histograms.
5. **Typed-BTF eBPF latency** correlates block request issue and completion, extracts operation and device metadata, and resolves blkcg ownership.
6. **Observe, diagnosis, capture, and watch** combine storage sharing, QEMU pressure, VM-attributed eBPF evidence, explicit missing evidence, and conservative correlations or verdict rules.

The capture workflow writes private, atomic evidence bundles containing the human diagnosis, `incident-report.md`, `evidence-summary.json`, raw `ebpf-vm-block-latency.json` when requested, a compact privacy-safe attribution projection in `observe-snapshot.json`, and `manifest.json` checksums. The observe projection excludes raw loader diagnostics and cgroup identifiers and labels the reused diagnosis evidence window explicitly.

## eBPF attribution design

The runtime ownership path is:

```text
request -> bio -> bi_blkg -> blkcg -> css -> cgroup -> kernfs_node.id
```

`block_rq_issue` stores an issue timestamp and sanitized metadata in bounded BPF maps. `block_rq_complete` looks up the same opaque request identity, calculates latency, and updates fixed host, device/operation, and cgroup/device/operation aggregates.

The request identity is used only inside the kernel as a bounded correlation key. Raw request addresses, bio pointers, blkcg pointers, cgroup pointers, and other kernel addresses are never emitted to userspace or JSON.

Userspace attributes an aggregate only when the extracted cgroup ID exactly matches a cgroup ID from the validated libvirt VM mapping. Missing bio or blkcg ownership, unknown cgroups, lookup misses, duplicate or reissued requests, map pressure, and requests incomplete at window end remain explicit unattributed work.

Attribution quality is conservative:

- `available`: no more than 5% unattributed work
- `degraded`: more than 5% and no more than 25% unattributed work
- `unavailable`: more than 25%, no completed attributed events, no VM match, or an unsupported ownership path

Request merging, requeues, stacked storage layers, and kernel-specific layouts can still affect what is attributable. The result is evidence, not perfect attribution or proof of customer impact.

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

Portable configuration is selected with `--config`, then `SOLIS_CONFIG`, then built-in development defaults. The built-in paths are intended for the repository lab, not installed production use.

### VM and host status

```bash
./solis status
./solis status --json
./solis status --watch --iterations 5 --sort pressure --no-clear
./solis vm storage-stats --victim a-web --suspect b-stress --duration 5s --interval 1s --json
```

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

The current milestone was validated with a controlled fio random-write workload inside the `b-stress` lab VM while `a-web` was the victim:

- Typed-BTF programs loaded and attached successfully on the test kernel.
- Host request issue/completion latency events and fixed histograms populated.
- The blkcg/cgroup ownership path attributed the dominant I/O to `b-stress`.
- `a-web` remained at low or zero VM-attributed operations during that window.
- Attribution coverage was high and the unattributed percentage remained low.
- Diagnosis rendered the VM attribution evidence and kept its caveats visible.
- All privacy flags remained false.

This validates the implementation path in the lab. It does not establish universal kernel compatibility, production overhead bounds, or causality for every workload.

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

- Solis is experimental and not production-ready.
- The current implementation is focused on a single Linux KVM/libvirt host with cgroup v2.
- VM-attributed eBPF latency requires kernel BTF, compatible typed block tracepoints, the embedded object, and sufficient eBPF capabilities.
- Secure Boot kernel lockdown or LSM policy can prevent program loading even for root.
- Kernel BTF and block-layer layout changes can make metadata or ownership fields unavailable.
- Request merging, requeues, flush semantics, missing bio/blkcg ownership, unknown cgroups, and map capacity can reduce attribution coverage.
- Device-mapper, encryption, LVM, partitions, and other stacked layers can make device interpretation ambiguous; Solis reports layers separately where practical.
- QEMU procfs counters are process-accounting signals and may require elevated access.
- Live-only infrastructure evidence cannot prove application slowdown without report or external application evidence.
- Multi-host collection, a controller, production daemon lifecycle, authentication, retention policy, compatibility guarantees, and production packaging are not implemented.

## Roadmap

- Run and retain long-duration harness results across idle, victim-load, noisy-neighbor, and mixed-load scenarios.
- Benchmark eBPF map pressure, event coverage, CPU overhead, and cleanup safety under sustained I/O.
- Polish operator-facing demo and incident reports around attribution quality and caveats.
- Add an install/package workflow with versioned embedded objects and compatibility checks.
- Evaluate broader hypervisor support only after the single-host KVM/libvirt path is hardened.
