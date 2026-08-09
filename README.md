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
- Discover a dominant same-storage suspect automatically when only the victim VM is known.
- Optionally include an experimental host/storage-path eBPF block-latency histogram in diagnoses and captures.
- Save diagnosis output to an exact path or a timestamped file without changing the diagnosis text.
- Capture experiment, incident, topology, storage, QEMU I/O, diagnosis, and metadata evidence in a timestamped directory.
- Check host, lab, inventory, storage, and QEMU procfs readiness with `solis doctor`.
- Check eBPF readiness, inspect tracepoint formats, count block events, and collect an experimental host-wide block latency histogram with optional VM storage-topology context.

The `top` command remains a placeholder.

## Current command set

Commands that use `/proc/<qemu-pid>/io` are shown with `sudo` because that procfs file is commonly protected when QEMU runs under another account. Experimental eBPF inspection and attachment may also require elevated capabilities. Solis never invokes `sudo` itself.

```text
./solis doctor
./solis ebpf doctor
./solis ebpf block-watch --duration 10s
sudo ./solis ebpf block-events --duration 10s
sudo ./solis ebpf block-count --duration 10s
sudo ./solis ebpf block-latency --duration 10s
sudo ./solis ebpf block-latency --victim a-web --suspect b-stress --duration 10s
./solis inventory
./solis inspect <vm> [--verbose]
./solis experiment summarize <report-dir>
./solis incidents explain <report-dir> --victim <name> --suspect <name>
./solis trace plan --victim <name> --suspect <name>
./solis storage snapshot --victim <name> --suspect <name>
./solis storage watch --victim <name> --suspect <name> --duration 10s --interval 2s
sudo ./solis qemu io-watch --victim <name> --suspect <name> --duration 10s --interval 2s
sudo ./solis qemu io-summary --victim <name> --suspect <name> --duration 10s --interval 2s
sudo ./solis diagnose noisy-neighbor --report-dir <dir> --victim <name> --suspect <name> --duration 10s --interval 2s
sudo ./solis diagnose noisy-neighbor --report-dir <dir> --victim <name> --suspect <name> --duration 10s --interval 2s --include-ebpf-latency
sudo ./solis diagnose noisy-neighbor --report-dir <dir> --victim <vm> --discover-suspects --duration 10s --interval 2s --include-ebpf-latency
sudo ./solis diagnose noisy-neighbor --report-dir <dir> --victim <name> --suspect <name> --duration 10s --interval 2s --output-dir lab/reports/diagnosis
sudo ./solis capture noisy-neighbor --report-dir <dir> --victim <name> --suspect <name> --duration 10s --interval 2s --output-dir lab/reports/captures
sudo ./solis capture noisy-neighbor --report-dir <dir> --victim <name> --suspect <name> --duration 10s --interval 2s --include-ebpf-latency --output-dir lab/reports/captures
sudo ./solis capture noisy-neighbor --report-dir <dir> --victim <vm> --discover-suspects --duration 10s --interval 2s --include-ebpf-latency --output-dir lab/reports/captures
```

For `--victim`, a tenant selector includes all configured VMs belonging to that tenant; a VM selector targets only that VM. The suspect must resolve to one VM.

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
./solis doctor
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

## Run the demo diagnosis

The manual demo starts the existing fio workload inside `b-stress`, allows it to become active, and samples QEMU process I/O while diagnosing `tenant-a`. Run these commands from the repository root:

```bash
./lab/scripts/run-fio-noise.sh b-stress 20 > /tmp/solis-fio-diagnose.txt 2>&1 &
fio_pid=$!
sleep 3
sudo ./solis diagnose noisy-neighbor --report-dir lab/reports/workload/20260808T174825Z --victim tenant-a --suspect b-stress --duration 10s --interval 2s
wait "$fio_pid"
```

The fio helper uses the configured lab SSH access to run the workload in the stress guest. The Solis diagnosis remains provider-side and does not log in to the victim tenant VMs.

## Create a capture package

Create a timestamped incident directory containing the experiment summary, incident explanation, trace plan, storage snapshot, QEMU I/O summary, combined diagnosis, and capture metadata:

```bash
sudo ./solis capture noisy-neighbor --report-dir lab/reports/workload/20260808T174825Z --victim tenant-a --suspect b-stress --duration 10s --interval 2s --output-dir lab/reports/captures
```

The generated directory is written beneath `lab/reports/captures/`. If QEMU procfs counters cannot be read, capture still preserves the other evidence and records the permission error in the relevant files.

## Run the full demo

The demo runner builds Solis, starts the existing fio workload on `b-stress`, waits for noise to become active, runs the combined diagnosis, and saves the result under `lab/reports/diagnosis/`. It then waits for fio, prints its summary, and reports the generated diagnosis path.

```bash
./lab/scripts/run-noisy-neighbor-diagnosis-demo.sh
```

Run it from any directory inside the checked-out repository; the script resolves and changes to the repository root automatically. It requires the configured lab SSH access and interactive or cached `sudo` authorization for reading QEMU procfs counters. The workload writes only to the existing fio test file inside the `b-stress` guest.

## Run the end-to-end MVP lab demo

The MVP runner demonstrates the victim-only workflow: it starts temporary fio random-write pressure inside `b-stress`, asks Solis to discover the suspect automatically, captures QEMU and experimental eBPF evidence, and produces a timestamped evidence bundle with `incident-report.md`.

From the repository root, run:

```bash
./lab/scripts/run-mvp-demo.sh
```

> **Lab only:** This script logs in to the configured stress VM at `192.168.140.40` and generates temporary fio write load inside that guest. SSH and fio orchestration remain outside the Solis CLI product path.

The script validates SSH, remote fio, and local `sudo` access before starting the workload. It waits for fio, removes `/home/flint/solis-mvp-demo.dat` from the stress guest, runs `fstrim`, prints the fio summary, and reports both the capture directory and Markdown incident-report path. Its main settings can be overridden through environment variables, for example:

```bash
VICTIM=a-web FIO_RUNTIME=90 FIO_SIZE=512M ./lab/scripts/run-mvp-demo.sh
```

## Sample result

In the included lab experiment and a corresponding live QEMU I/O sample:

- HTTP throughput dropped **23.61%** during storage noise.
- HTTP latency increased **30.92%**.
- The victim and suspect shared physical disk `/dev/nvme0n1`.
- `b-stress` was the dominant QEMU writer during fio.
- Verdict: **Probable noisy-neighbor storage interference.**

This is evidence from a controlled demo, not a guarantee that the same conclusion applies to unrelated production incidents.

## Safety and privacy

- Provider-side only; no guest login is required.
- The Solis CLI does not SSH into tenant VMs.
- Does not inspect guest memory, guest filesystems, customer disk contents, database contents, or application payloads.
- Uses provider-visible VM metadata, disk topology, experiment summaries, kernel block counters, and QEMU process counters.
- Collection commands are read-only and do not create, stop, start, or modify VMs.
- Does not bypass host permissions or invoke `sudo` internally.
- QEMU I/O commands may need to be launched with `sudo` because Linux can protect `/proc/<qemu-pid>/io` from other users.

## Current limitations

- Experimental host-wide eBPF block latency measurement can show victim/suspect storage-path context, but it does not attribute latency histograms to individual VMs. Use `qemu io-summary` for VM writer attribution.
- `ebpf doctor` and `ebpf block-watch` are readiness-only. `ebpf block-events` reads tracepoint formats, while `ebpf block-count` and `ebpf block-latency` temporarily attach limited-purpose programs.
- No per-VM block-latency histograms yet.
- QEMU process counters require sufficient procfs permissions and reflect process accounting rather than request-level block latency.
- Experiment and attribution workflows are currently designed around the included lab/demo environment.
- No production hardening, long-running service mode, retention policy, authentication layer, or stability guarantees yet.
- Not production-ready.

## Roadmap

- Per-VM eBPF block latency attribution and production hardening.
- Per-VM latency histograms.
- Live incident windows and time correlation.
- Prometheus/export support.
- HTML and PDF reports.

## License

No license has been declared in this repository yet.
