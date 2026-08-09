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

Report-backed mode provides evidence about both sides of an incident: the tenant-visible slowdown and the host-side VM or storage activity that may explain it. Live-only mode evaluates current provider-side pressure without claiming application slowdown.

## Current capabilities

- Enrich VM inventory from libvirt with tenant, role, state, planned and leased IPs, QEMU PID, and qcow2 disk path.
- Inspect individual VMs, with optional verbose QEMU command-line output.
- Resolve VM → QEMU PID → qcow2 disk → filesystem source → parent device → physical disk.
- Parse workload experiment reports and summarize throughput, latency, failures, fio activity, and disk utilization.
- Explain report-backed incidents using application slowdown and fio evidence.
- Collect read-only host storage snapshots and per-layer block-device watch deltas.
- Sample per-QEMU `/proc/<pid>/io` counters and attribute write activity using byte rates, with conservative write-syscall pressure fallback when byte counters do not advance meaningfully.
- Automatically discover same-physical-disk suspect VMs and rank them by write-byte or syscall pressure.
- Run report-backed or live-only noisy-neighbor diagnosis.
- Monitor live noisy-neighbor conditions in repeated windows, alert on likely pressure, and optionally create cooldown-controlled capture bundles.
- Collect experimental host/storage-path eBPF block latency counts and histograms, with optional victim/suspect topology context.
- Produce timestamped capture bundles containing text evidence, a human-readable `incident-report.md`, and machine-readable `evidence-summary.json`.
- Expose live VM status as a terminal table or JSON document.
- Refresh VM status continuously with sorting, pressure counts, finite iterations, and clean signal handling.
- Check host, lab, inventory, storage, and QEMU procfs readiness with `solis doctor`.

The `top` command remains a placeholder.

## Current command set

Commands that use `/proc/<qemu-pid>/io` are shown with `sudo` because that procfs file is commonly protected when QEMU runs under another account. Experimental eBPF inspection and attachment may also require elevated capabilities. Solis never invokes `sudo` itself.

The explicit `10s` and `2s` values below are example observation settings, not universal defaults; defaults vary by command.

```text
./solis doctor
./solis ebpf doctor
./solis ebpf block-watch --duration 10s
sudo ./solis ebpf block-events --duration 10s
sudo ./solis ebpf block-count --duration 10s
sudo ./solis ebpf block-latency --duration 10s
sudo ./solis ebpf block-latency --victim a-web --suspect b-stress --duration 10s
./solis inventory
sudo ./solis status
sudo ./solis status --duration 3s --interval 1s
sudo ./solis status --duration 3s --interval 1s --json
sudo ./solis status --duration 3s --interval 1s --sort syscw
sudo ./solis status --watch --duration 1s --interval 1s --every 2s --iterations 5 --no-clear --sort pressure
./solis inspect <vm> [--verbose]
./solis experiment summarize <report-dir>
./solis incidents explain <report-dir> --victim <name> --suspect <name>
./solis trace plan --victim <name> --suspect <name>
./solis storage snapshot --victim <name> --suspect <name>
./solis storage watch --victim <name> --suspect <name> --duration 10s --interval 2s
sudo ./solis qemu io-watch --victim <name> --suspect <name> --duration 10s --interval 2s
sudo ./solis qemu io-summary --victim <name> --suspect <name> --duration 10s --interval 2s
sudo ./solis diagnose noisy-neighbor [--report-dir <dir>] --victim <name> --suspect <name> --duration 10s --interval 2s
sudo ./solis diagnose noisy-neighbor [--report-dir <dir>] --victim <name> --suspect <name> --duration 10s --interval 2s --include-ebpf-latency
sudo ./solis diagnose noisy-neighbor --report-dir <dir> --victim <vm> --discover-suspects --duration 10s --interval 2s --include-ebpf-latency
sudo ./solis diagnose noisy-neighbor --victim <vm> --discover-suspects --duration 10s --interval 2s --include-ebpf-latency
sudo ./solis diagnose noisy-neighbor --victim <vm> --discover-suspects --duration 10s --interval 2s --output lab/reports/live-diagnosis.txt
sudo ./solis diagnose noisy-neighbor --report-dir <dir> --victim <name> --suspect <name> --duration 10s --interval 2s --output-dir lab/reports/diagnosis
sudo ./solis capture noisy-neighbor [--report-dir <dir>] --victim <name> --suspect <name> --duration 10s --interval 2s --output-dir lab/reports/captures
sudo ./solis capture noisy-neighbor [--report-dir <dir>] --victim <name> --suspect <name> --duration 10s --interval 2s --include-ebpf-latency --output-dir lab/reports/captures
sudo ./solis capture noisy-neighbor --report-dir <dir> --victim <vm> --discover-suspects --duration 10s --interval 2s --include-ebpf-latency --output-dir lab/reports/captures
sudo ./solis capture noisy-neighbor --victim <vm> --discover-suspects --duration 10s --interval 2s --include-ebpf-latency --output-dir lab/reports/captures
sudo ./solis watch noisy-neighbor --victim <vm> --suspect <vm> --window 10s --every 30s --iterations 3
sudo ./solis watch noisy-neighbor --victim <vm> --discover-suspects --window 10s --every 30s --include-ebpf-latency --capture-on-alert --output-dir lab/reports/captures
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

Solis samples Linux process counters from `/proc/<qemu-pid>/io` and calculates per-interval and observation-window read/write rates. Byte counters remain the primary attribution signal. When they are zero or low, Solis uses `AVG_SYSCW/S` and `MAX_SYSCW/S` as a conservative write-syscall pressure signal; those syscall rates indicate activity, not exact bytes written. Access is controlled by normal Linux procfs permissions, and Solis does not elevate privileges internally.

### Noisy-neighbor diagnosis

Report-backed diagnosis combines three independent signals:

1. An application slowdown: throughput falls and latency rises during noise.
2. A shared physical storage device between victim and suspect.
3. Meaningful suspect QEMU write pressure, with the suspect dominant over the victim group.

When all signals agree, Solis reports probable noisy-neighbor storage interference. Missing, contradictory, or low-activity evidence produces a more conservative verdict.

Live-only diagnosis omits application slowdown claims and evaluates current storage topology, QEMU byte or syscall pressure, suspect discovery, and optional host/storage-path eBPF latency.

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

## Live VM status

Show a compact table of running VMs, their QEMU and qcow2 mappings, physical storage, and sampled write pressure:

```bash
sudo ./solis status --duration 3s --interval 1s
```

Emit the same reusable status model as one JSON document for dashboards, automation, or a future TUI:

```bash
sudo ./solis status --duration 3s --interval 1s --json
```

The defaults are a three-second observation window and a one-second sampling interval. Solis does not elevate privileges internally; `sudo` is shown because Linux commonly protects QEMU processes' `/proc/<pid>/io` counters. No guest payloads, guest files, process memory, or application contents are inspected.

Use the live-refresh terminal view before reaching for a longer diagnosis:

```bash
sudo ./solis status --watch \
  --duration 1s \
  --interval 1s \
  --every 2s \
  --iterations 5 \
  --no-clear \
  --sort pressure
```

Each frame includes `HIGH`, `LOW`, and `IDLE` pressure counts. Watch mode clears the terminal before each refresh by default and runs until interrupted. Use `--iterations <n>` for a bounded view, `--no-clear` to preserve prior frames, or `--sort pressure` to show high-pressure VMs first. Other sort fields are `name`, `tenant`, `role`, `write`, and `syscw`. On exit, Solis prints the iterations run and high-pressure observations. Watch mode does not support `--json` yet.

Sorting is also available in one-shot status mode:

```bash
sudo ./solis status --duration 3s --interval 1s --sort syscw
```

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

Run a report-backed combined diagnosis. This mode correlates provider-side evidence with the application slowdown recorded by the workload experiment:

```bash
sudo ./solis diagnose noisy-neighbor --report-dir lab/reports/workload/20260808T174825Z --victim tenant-a --suspect b-stress --duration 10s --interval 2s
```

Run a live-only diagnosis when the operator knows only which VM is slow now:

```bash
sudo ./solis diagnose noisy-neighbor --victim a-web --discover-suspects --duration 10s --interval 2s --include-ebpf-latency
```

Live-only mode discovers same-storage candidates and evaluates current storage topology, QEMU writer activity, syscall pressure, and optional host-path eBPF latency. It can identify likely provider-side storage-neighbor pressure, but without an external report it cannot prove that application-level slowdown occurred.

Solis itself never invokes `sudo`. These examples use it because Linux commonly restricts access to `/proc/<qemu-pid>/io` for QEMU processes owned by another account. Use the minimum privileges appropriate for your environment.

To save a combined diagnosis, add either `--output <path>` or `--output-dir <dir>`. The latter generates a UTC timestamped filename and will not overwrite an existing report with the same name.

For example, save a live-only diagnosis to an exact path:

```bash
sudo ./solis diagnose noisy-neighbor \
  --victim a-web \
  --discover-suspects \
  --duration 10s \
  --interval 2s \
  --output lab/reports/live-diagnosis.txt
```

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

Create a timestamped incident directory containing:

- `experiment-summary.txt`
- `incident-explanation.txt`
- `trace-plan.txt`, or `victim-topology.txt` when discovery selects no suspect
- `storage-snapshot.txt`
- `qemu-io-summary.txt`
- `diagnosis.txt`
- `metadata.txt`
- `incident-report.md`
- `evidence-summary.json`
- `suspect-discovery.txt` when discovery mode is used
- `ebpf-block-latency.txt` when eBPF latency is requested, containing either collected evidence or an availability warning

```bash
sudo ./solis capture noisy-neighbor --report-dir lab/reports/workload/20260808T174825Z --victim tenant-a --suspect b-stress --duration 10s --interval 2s --output-dir lab/reports/captures
```

For a live-only capture with automatic suspect discovery, omit `--report-dir`:

```bash
sudo ./solis capture noisy-neighbor --victim a-web --discover-suspects --duration 10s --interval 2s --include-ebpf-latency --output-dir lab/reports/captures
```

Live-only captures mark application evidence unavailable in `diagnosis.txt`, `experiment-summary.txt`, and `incident-report.md`; they do not print zero-valued application metrics as evidence.

## Watch live noisy-neighbor evidence

Watch mode repeats the live-only provider-side diagnosis for a known victim VM. By default, it samples a 10-second window every 30 seconds and continues until interrupted:

```bash
sudo ./solis watch noisy-neighbor \
  --victim a-web \
  --discover-suspects \
  --window 10s \
  --every 30s \
  --include-ebpf-latency \
  --capture-on-alert \
  --output-dir lab/reports/captures
```

When the suspect is already known, use pairwise mode. This bounded example runs three observation windows:

```bash
sudo ./solis watch noisy-neighbor \
  --victim a-web \
  --suspect b-stress \
  --window 10s \
  --every 30s \
  --iterations 3
```

Each iteration prints only the selected suspect, writer metrics, discovery reason, and live verdict. Add `--verbose` to include the full diagnosis. Use `--iterations <n>` for a bounded run; otherwise press Ctrl-C to stop and print the final iteration, alert, and capture counters.

An alert fires only for the cautious live verdict `Likely storage-neighbor pressure observed during live sampling.` With `--capture-on-alert`, the same already-sampled evidence is written as a live-only capture bundle. Repeated alerts continue to print, but captures default to a two-minute cooldown; change it with `--cooldown <duration>`.

The generated directory is written beneath `lab/reports/captures/`. Solis prints the capture directory, `incident-report.md` path, and `evidence-summary.json` path. If QEMU procfs counters cannot be read, capture still preserves the other evidence and records the permission error in the relevant files.

## Run the full demo

The demo runner builds Solis, starts the existing fio workload on `b-stress`, waits for noise to become active, runs the combined diagnosis, and saves the result under `lab/reports/diagnosis/`. It then waits for fio, prints its summary, and reports the generated diagnosis path.

```bash
./lab/scripts/run-noisy-neighbor-diagnosis-demo.sh
```

Run it from any directory inside the checked-out repository; the script resolves and changes to the repository root automatically. It requires the configured lab SSH access and interactive or cached `sudo` authorization for reading QEMU procfs counters. The workload writes only to the existing fio test file inside the `b-stress` guest.

## Run the end-to-end MVP lab demo

The MVP runner demonstrates the victim-only workflow: it starts temporary fio random-write pressure inside `b-stress`, asks Solis to discover the suspect automatically, captures QEMU and experimental eBPF evidence, and produces a timestamped evidence bundle with `incident-report.md` and `evidence-summary.json`.

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

- Solis is currently a lab/demo project and is not production-ready.
- Experimental eBPF block latency is attributed to the host or shared storage path, not to an individual VM. Per-VM block-latency histograms are not implemented.
- QEMU process I/O counters require sufficient procfs permissions. Write-syscall pressure is an activity signal and must not be interpreted as an exact byte count.
- Live-only diagnosis can identify likely provider-side storage-neighbor pressure, but it cannot prove application-level slowdown without report or external application evidence.
- Inventory configuration, bundled workload reports, doctor lab checks, and demo scripts still reflect the included lab environment.
- Watch commands are foreground CLI loops, not a daemonized monitoring service.
- There is no production retention policy, authentication layer, compatibility guarantee, or stability guarantee.
- `ebpf doctor` and `ebpf block-watch` are readiness-oriented. `block-events` reads tracepoint metadata, while `block-count` and `block-latency` attach temporary limited-purpose programs.

## Roadmap

- Per-VM eBPF block-latency attribution and per-VM latency histograms.
- Cross-signal timestamp correlation across application, QEMU, and host block evidence.
- Durable incident timelines and longer-running observation storage.
- Prometheus metrics and external exporter integrations.
- Interactive terminal UI built on the existing status model.
- HTML and PDF incident-report generation.
- Daemon/service lifecycle, retention controls, authentication, compatibility testing, and production hardening.

## License

No license has been declared in this repository yet.
