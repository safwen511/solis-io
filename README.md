# Solis I/O

Solis I/O is a Linux-only, provider-side KVM/libvirt storage-latency attribution CLI written in Go. It helps infrastructure operators determine whether a tenant VM slowdown correlates with host-side storage pressure from another VM—without logging in to guests or inspecting customer payloads.

> **Project status:** Solis I/O is currently a lab/demo project. It is useful for controlled experiments and development, but it is not production-ready or production-hardened.

## The question Solis answers

> Customer VM is slow. Did our infrastructure cause it? If yes, which VM/layer contributed?

Solis combines application experiment results with provider-visible metadata and counters. Its attribution path is:

```text
VM inventory
    -> QEMU PID
    -> qcow2 disk path
    -> host source, parent, and physical block devices
    -> per-QEMU process I/O
    -> noisy-neighbor diagnosis
```

This provides evidence about both sides of an incident: the tenant-visible slowdown and the host-side VM or storage activity that may explain it.

## Current capabilities

- Inventory KVM/libvirt VMs and show tenant, role, state, planned and leased IPs, QEMU PID, and disk path.
- Inspect one VM's configuration, libvirt state, storage path, QEMU process, and guest-agent presence.
- Parse ApacheBench and fio workload reports and summarize throughput, latency, failures, IOPS, bandwidth, and disk utilization.
- Explain an experiment incident for a selected victim and suspect.
- Produce a trace plan that resolves victim and suspect VMs and describes future host evidence collection.
- Resolve qcow2 files through filesystem, device-mapper/LVM, parent-device, and physical-disk layers.
- Capture and watch read-only host block counters from `/sys/class/block/<device>/stat` across storage layers.
- Watch and summarize per-QEMU I/O using `/proc/<qemu-pid>/io`.
- Combine experiment, storage-topology, and QEMU-process evidence into a noisy-neighbor verdict.
- Save diagnosis output to an exact path or a timestamped file without changing the diagnosis text.

The `doctor` and `top` commands currently remain placeholders.

## Architecture

### VM inventory

The inventory layer reads configured VM metadata, queries libvirt for runtime state, lease addresses, and block devices, then maps each VM to its QEMU PID and command line.

### Storage topology mapping

Solis maps each VM disk path to its containing mountpoint, filesystem source, parent block device, and physical disk. It supports ordinary block devices and device-mapper/LVM-backed filesystems.

### Experiment report parser

The experiment package parses existing ApacheBench and fio text reports. It calculates changes between baseline, during-noise, and post-noise phases without duplicating workload parsing in higher-level commands.

### QEMU process I/O accounting

Solis samples Linux process counters from `/proc/<qemu-pid>/io` and calculates per-interval and observation-window read/write rates. Access is controlled by normal Linux procfs permissions; Solis does not elevate privileges internally.

### Noisy-neighbor diagnosis

The diagnosis layer combines three independent signals:

1. An application slowdown: throughput falls and latency rises during noise.
2. A shared physical storage device between victim and suspect.
3. Meaningful suspect QEMU write pressure, with the suspect dominant over the victim group.

When all signals agree, Solis reports probable noisy-neighbor storage interference. Missing, contradictory, or low-activity evidence produces a more conservative verdict.

## Prerequisites

- Linux host running KVM/libvirt and QEMU.
- Go 1.25 or a compatible newer toolchain.
- `virsh`, `findmnt`, and `lsblk` available for the relevant inventory and topology commands.
- Permission to query the local libvirt instance.
- Permission to read the selected QEMU processes' `/proc/<pid>/io` files when using QEMU I/O or combined diagnosis commands.

The repository's demo inventory is read from `lab/config/vms.csv`.

## Quickstart

From the repository root:

```bash
go test ./...
go build -o solis ./cmd/solis
./solis inventory
```

The binary is written to `./solis`.

## Demo commands

Summarize an existing workload experiment:

```bash
./solis experiment summarize lab/reports/workload/20260808T174825Z
```

Explain the application-visible incident:

```bash
./solis incidents explain lab/reports/workload/20260808T174825Z --victim tenant-a --suspect b-stress
```

Show the host evidence and tracing plan:

```bash
./solis trace plan --victim tenant-a --suspect b-stress
```

Summarize live per-QEMU process I/O:

```bash
sudo ./solis qemu io-summary --victim tenant-a --suspect b-stress --duration 10s --interval 2s
```

Run the combined diagnosis:

```bash
sudo ./solis diagnose noisy-neighbor --report-dir lab/reports/workload/20260808T174825Z --victim tenant-a --suspect b-stress --duration 10s --interval 2s
```

Solis itself never invokes `sudo`. These examples use it because Linux commonly restricts access to `/proc/<qemu-pid>/io` for QEMU processes owned by another account. Use the minimum privileges appropriate for your environment.

To save a combined diagnosis, add either `--output <path>` or `--output-dir <dir>`. The latter generates a UTC timestamped filename and will not overwrite an existing report with the same name.

## Sample result

In the included lab experiment and a corresponding live QEMU I/O sample:

- HTTP throughput dropped **23.61%** during storage noise.
- HTTP latency increased **30.92%**.
- `b-stress` was the dominant QEMU writer.
- Verdict: **Probable noisy-neighbor storage interference.**

This is evidence from a controlled demo, not a guarantee that the same conclusion applies to unrelated production incidents.

## Safety and privacy

- Provider-side only; no guest login is required.
- The Solis CLI does not SSH into tenant VMs.
- Does not inspect guest memory, guest filesystems, customer disk contents, database contents, or application payloads.
- Uses provider-visible VM metadata, disk topology, experiment summaries, kernel block counters, and QEMU process counters.
- Collection commands are read-only and do not create, stop, start, or modify VMs.
- Does not bypass host permissions or invoke `sudo` internally.

## Current limitations

- No live eBPF block tracing yet.
- No per-VM block-latency histograms yet.
- QEMU process counters require sufficient procfs permissions and reflect process accounting rather than request-level block latency.
- Experiment and attribution workflows are currently designed around the included lab/demo environment.
- No production hardening, long-running service mode, retention policy, authentication layer, or stability guarantees yet.
- Not production-ready.

## Roadmap

- eBPF block latency tracing.
- Per-VM latency histograms.
- Live incident windows and time correlation.
- Prometheus/export support.
- HTML and PDF reports.

## License

No license has been declared in this repository yet.
