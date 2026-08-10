# Solis I/O

Solis I/O is a Linux-only, provider-side KVM/libvirt storage-latency attribution CLI written in Go. Its core diagnosis works without guest access and helps infrastructure operators determine whether a tenant VM slowdown correlates with host-side storage pressure from another VM. An optional, strictly allowlisted guest/service collector can add sanitized health metadata; neither mode inspects customer payloads.

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
- Collect time-bounded per-VM storage validation counters from cgroup v2 `io.stat`, `virsh domstats --block`, and optional QEMU procfs accounting.
- Sample per-QEMU `/proc/<pid>/io` counters and attribute write activity using byte rates, with conservative write-syscall pressure fallback when byte counters do not advance meaningfully.
- Automatically discover same-physical-disk suspect VMs and rank them by write-byte or syscall pressure.
- Run report-backed or live-only noisy-neighbor diagnosis.
- Monitor live noisy-neighbor conditions in repeated windows, alert on likely pressure, and optionally create cooldown-controlled capture bundles.
- Collect experimental host/storage-path eBPF block latency counts and histograms, with optional victim/suspect topology context.
- Expose an experimental VM block-latency JSON contract, libvirt cgroup-inode mapper, validation parsers, and a Cilium typed-BTF host request-latency collector; request pointers are bounded kernel-only correlation keys, while VM ownership attribution remains deliberately unimplemented.
- Produce private, atomically finalized capture bundles containing text evidence, a human-readable `incident-report.md`, machine-readable `evidence-summary.json`, and a SHA-256 integrity manifest.
- Expose live VM status as a terminal table or JSON document.
- Refresh VM status continuously with sorting, pressure counts, finite iterations, and clean signal handling.
- Collect opt-in guest resource, listening-port, process-pressure, configured systemd unit, and HTTP health metadata through fixed allowlisted SSH commands.
- Collect opt-in PostgreSQL version, database counters, non-idle activity aggregates, extension names, and numeric `pg_stat_statements` counters through fixed read-only queries.
- Combine host, VM/QEMU, guest, service, database, and storage evidence into one window-correlated, privacy-safe JSON observation snapshot.
- Stream repeated unified observation snapshots as JSON Lines for automation and correlation workflows.
- Check host, lab, inventory, storage, and QEMU procfs readiness with `solis doctor`.

The `top` command remains a placeholder.

## Current command set

Commands that use `/proc/<qemu-pid>/io` are shown with `sudo` because that procfs file is commonly protected when QEMU runs under another account. Experimental eBPF inspection and attachment may also require elevated capabilities. Host-side Solis commands do not elevate themselves. The opt-in PostgreSQL SSH collector can use one fixed remote `sudo -n -u postgres psql` command for local peer statistics access; it cannot run arbitrary sudo commands.

The explicit `10s` and `2s` values below are example observation settings, not universal defaults; defaults vary by command.

```text
./solis version
./solis version --json
./solis doctor
./solis doctor --lab
./solis ebpf doctor
./solis ebpf block-watch --duration 10s
sudo ./solis ebpf block-events --duration 10s
sudo ./solis ebpf block-count --duration 10s
sudo ./solis ebpf block-latency --duration 10s
sudo ./solis ebpf block-latency --victim a-web --suspect b-stress --duration 10s
sudo ./solis ebpf vm-block-latency --duration 5s --interval 1s --all-vms --json
sudo ./solis ebpf vm-block-latency --victim a-web --suspect b-stress --duration 5s --interval 1s --json
./solis inventory
./solis host status --json
./solis --config ./solis.json guest status --vm a-web --json
./solis --config ./solis.json service status --vm a-web --json
./solis --config ./solis.json db status --vm a-db --json
./solis --config ./solis.json observe snapshot --victim a-web --discover-suspects --duration 10s --interval 2s --json
./solis --config ./solis.json observe watch --victim a-web --discover-suspects --duration 10s --interval 2s --every 30s --iterations 2 --json
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
./solis vm storage-stats --victim a-web --suspect b-stress --duration 10s --interval 1s --json
./solis vm storage-stats --all-vms --duration 10s --interval 1s --json
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

### Per-VM storage validation counters

`solis vm storage-stats` collects two read-only samples around an observation window. Cgroup v2 `io.stat` provides byte, operation, and optional discard-counter deltas for the mapped libvirt VM cgroup. The collector verifies that the source cgroup inode is unchanged across the window; an emulator-cgroup fallback is labelled partial, and arbitrary vCPU/child cgroups are not treated as aggregate VM accounting. `virsh domstats <vm> --block` provides virtual-disk request, byte, flush, and cumulative timing deltas. `/proc/<qemu-pid>/io` provides optional process-accounting correlation only after the PID is verified as the same QEMU process in the same libvirt machine scope at both samples; insufficient procfs permissions make only that section unavailable.

With no selector, or with `--all-vms`, the command targets all inventory VMs currently reported as running. Explicit `--victim` and optional `--suspect` selectors retain a named VM even when it is shut off so its unavailable state can be represented. JSON is required for now, and `--output` atomically writes the same document to a mode-`0600` regular file while refusing symbolic links. The output parent directory must already exist; Solis does not create it.

These are validation counters, not per-VM host block-latency measurements. Missing baselines, disappeared rows, duplicate identities, and counter resets are explicit and never converted into apparent window activity. Device-mapper, LVM, partition, and physical-device rows remain separate because summing stacked layers would double-count I/O. The command is intended to validate the cgroup and libvirt evidence used by the experimental `ebpf vm-block-latency` design; it does not prove exact physical-device latency, customer impact, or root cause.

### Experimental per-VM block latency

The host-wide `ebpf block-latency` command measures a shared host/storage-path histogram using a best-effort device-and-sector correlation key. QEMU I/O commands instead measure process accounting and writer pressure; they do not measure block request latency. Cgroup v2 `io.stat` supplies per-cgroup byte and operation counters, while `virsh domstats --block` supplies virtual-disk counters and cumulative timing. Neither is a host physical-device latency histogram.

`ebpf vm-block-latency` defines the experimental per-VM JSON report, maps known libvirt QEMU processes to cgroup v2 inode IDs without reading command lines or environments, aggregates fake request-pointer event streams in tests, and parses `io.stat` and `virsh domstats` validation counters without combining stacked block-device layers. Its intended kernel attribution path is:

```text
block_rq_issue request pointer
  -> request bio
  -> bio blkcg ownership
  -> libvirt cgroup inode ID
  -> VM
  -> block_rq_complete request pointer latency
```

Task 4 correlates `block_rq_issue` and `block_rq_complete` by request address inside a bounded kernel hash map. The address is never emitted. Completion updates a fixed per-CPU latency histogram and exact count/total/min/max values; userspace reads only those aggregates plus instrumentation counters. The programs do not dereference `request`, `bio`, `blkcg`, or cgroup fields and do not attribute activity to a VM. Successful output is labeled `collection_mode: typed_btf_request_correlation_host_only`, `attribution_method: host_request_pointer_correlation_no_vm_attribution`, and `attribution_quality: unavailable`. Per-VM latency totals remain zero.

An authentic embedded ELF matching the C source enables the Cilium source to attempt the host request-correlation load and attach; without it, preflight returns `availability.available: false` and `availability.status: object_unavailable`. A stale object fails loading rather than fabricating results. `experimental_not_implemented` is reserved for the still-missing bio/blkcg VM-attribution implementation. Automation must inspect `availability.available` and `availability.status`, not process exit status alone. Object loading and attachment distinguish `object_invalid`, `object_load_failed`, `btf_incompatible`, `btf_missing`, `typed_tracepoint_missing`, `unsupported_endianness`, `permission_denied`, `verifier_rejected`, `attach_failed`, and `cleanup_failed`. Failed JSON includes the exact bounded stage, effective UID, underlying diagnostic, effective capability mask and relevant named capability bits when readable, lockdown mode, memlock limits, `perf_event_paranoid`, and `unprivileged_bpf_disabled`. Cleanup failures are retained as structured `ebpf_cleanup` unavailable sections even when another collection stage also fails. Solis never invokes `sudo` internally.

The kernel request map is capped at 65,536 entries. Duplicate issues, completion lookup misses, map-update failures, and requests incomplete at window end are reported explicitly. Latency uses 14 fixed buckets (`<100 us` through `1 s+`); p50, p95, and p99 are approximate bucket-derived estimates, while min, max, count, and average use exact aggregate values. No ring buffer or unbounded request-latency slice is used. Fake event and loader sources are exercised only in tests. Bio/blkcg ownership and per-VM latency remain unimplemented.

For `tp_btf`, kernel BTF describes each trace callback typedef with a leading internal `void *` callback-data parameter. That parameter is not part of the effective BPF program context. The count-only programs therefore declare `block_rq_issue(struct request *)` and `block_rq_complete(struct request *, blk_status_t, unsigned int)`. Preflight and `ebpf doctor` report both the full kernel typedef parameters and the effective program parameters so a kernel prototype mismatch fails clearly before load.

The loader uses `github.com/cilium/ebpf` v0.22.0. Regenerate the little-endian object on a development host with the matching toolchain:

```bash
go generate ./internal/ebpf
```

The generation script pins `bpf2go` v0.22.0, compiles [vm_block_latency.bpf.c](internal/ebpf/bpf/vm_block_latency.bpf.c), and installs only the authentic ELF at `internal/ebpf/bpf/generated/vm_block_latency_bpfel.o`. Project-owned `vmlinux_min.h` supplies only minimal kernel-style scalar and map constants plus an opaque `struct request` declaration. Helper functions, map declaration macros, section macros, and typed tracing macros come exclusively from the packaged libbpf headers `/usr/include/bpf/bpf_helpers.h` and `/usr/include/bpf/bpf_tracing.h`. The script validates those exact paths and their helper-definition dependency before compilation. It does not depend on Cilium's example-header layout, an undeclared `common.h`, or hidden system-global search paths. [build/ebpf/Dockerfile](build/ebpf/Dockerfile) installs `libbpf-dev` and supplies a controlled convenience environment when the development host lacks Clang/LLVM:

```bash
docker build -t solis-ebpf-gen -f build/ebpf/Dockerfile .
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e GOPATH=/tmp/go \
  -e GOMODCACHE=/tmp/go/pkg/mod \
  -e GOCACHE=/tmp/go-build \
  -v "$PWD:/src" \
  -w /src \
  solis-ebpf-gen \
  ./internal/ebpf/bpf/generate.sh
```

This generator image is not yet bit-for-bit reproducible: its base image is not digest-pinned and Debian LLVM/Clang/libbpf package versions are not locked. Those pins must be added before treating generated objects as reproducible release artifacts. Do not invent pins; record verified image digests and package versions when the release build environment is established. The current object plan targets little-endian Linux first and reports `unsupported_endianness` elsewhere. Target hosts do not need Clang, LLVM, libbpf development headers, or `bpf2go` for normal builds after the generated object is committed.

Manual privileged smoke test after generation:

```bash
sudo ./solis ebpf vm-block-latency --duration 1s --interval 1s --json
```

Use `--all-vms` to make the all-running-VM context explicit, or select one or two exact inventory VM names with `--victim` and `--suspect`; these selectors do not imply VM attribution. `--device` is rejected with `device_filter_unsupported` in Task 4 because filtering would require request field access. `--output` writes the same JSON document to a mode-`0600` temporary file and atomically renames it while retaining JSON on stdout. The parent directory must already exist. Symbolic-link and non-regular targets are rejected, and Linux parent directories are opened through no-follow traversal before writing.

Per-VM attribution will remain experimental because request merging, requeues, flush requests, missing bio/blkcg ownership, stacked devices, kernel/BTF compatibility, and unmapped cgroups can produce unattributed or ambiguous events. Validation against cgroup `io.stat`, `virsh domstats --block`, and QEMU pressure is correlation evidence, not proof of exact VM latency or customer impact.

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

## Configuration

Solis accepts an optional versioned JSON configuration. Configuration precedence is:

```text
--config <path> > SOLIS_CONFIG > built-in development defaults
```

An explicit configuration can be supplied before or after the command:

```bash
./solis --config ./solis.json status
./solis status --config ./solis.json
SOLIS_CONFIG=./solis.json ./solis inventory
```

Relative paths in an explicit configuration are resolved from the directory containing that JSON file, so commands do not need to run from the repository root. Example:

```json
{
  "schema_version": "1",
  "inventory_csv": "lab/config/vms.csv",
  "capture_output_root": "lab/reports/captures",
  "default_report_dir": "lab/reports/workload/20260808T174825Z",
  "libvirt_uri": "qemu:///system",
  "thresholds": {
    "write_mib_per_sec": 10,
    "write_syscalls_per_sec": 10000,
    "dominance_ratio": 2.0
  }
}
```

The built-in values preserve the repository-relative lab workflow for development and demos. Production or installed use should provide an explicit configuration. `capture_output_root` supplies the default alert-capture location for noisy-neighbor watch, while `default_report_dir` is checked by `doctor --lab`; omitting `--report-dir` from diagnosis or capture still deliberately selects live-only mode. Inventory CSV loading strictly validates required headers and fields, positive memory/vCPU/disk values, portable VM identifiers, IP addresses, duplicate VM names, and empty inventories.

`./solis doctor` performs product and configured-host checks: configuration identity, inventory readability, Linux `/proc` and `/sys`, required host commands, read-only libvirt access, capture-output writability and permission hygiene, optional observability configuration, storage/QEMU readiness, and explicit privacy guarantees. It does not require sudo and warns when invoked as root unnecessarily. Add `--lab` to include the bundled fio script and demo workload report checks. Effective configuration source and attribution thresholds are recorded in diagnosis output and capture metadata; capture JSON also records them in `evidence-summary.json`.

### Observability configuration

Schema version 1 remains supported. Schema version 2 adds an optional, strictly validated `observability` block for the local host, guest/service, and PostgreSQL statistics collectors:

```json
{
  "schema_version": "2",
  "inventory_csv": "inventory/vms.csv",
  "capture_output_root": "captures",
  "libvirt_uri": "qemu:///system",
  "thresholds": {
    "write_mib_per_sec": 10,
    "write_syscalls_per_sec": 10000,
    "dominance_ratio": 2.0
  },
  "observability": {
    "host": {
      "enabled": true,
      "interval": "1s",
      "collect_psi": true,
      "collect_network": true
    },
    "guest": {
      "enabled": false,
      "transport": "ssh",
      "user": "flint",
      "connect_timeout": "5s",
      "max_parallel": 4,
      "known_hosts": "known_hosts"
    },
    "services": [
      {
        "vm": "a-web",
        "units": ["nginx.service", "solis-workload.service"],
        "health_checks": [
          {
            "name": "web-health",
            "path": "/health",
            "port": 80,
            "collect_body": false
          }
        ]
      }
    ],
    "databases": [
      {
        "vm": "a-db",
        "kind": "postgresql",
        "database": "postgres",
        "credential_ref": "systemd-credential:solis-a-db-monitor",
        "collect_pg_stat_statements": true
      }
    ]
  }
}
```

Observability is opt-in. Omitting the block leaves automatic host and guest observability disabled and the database list empty; guest and service collection require an explicit `guest.enabled: true`, a validated inventory VM, and fixed service definitions. PostgreSQL collection requires an explicit database entry and configured inventory-bound SSH transport settings. An explicit `solis host status --json` invocation is still allowed and uses safe read-only defaults. Guest-agent execution is not implemented.

Do not put passwords, tokens, secrets, private keys, or credential values in the JSON file. `credential_ref` may be empty or refer to `systemd-credential:`, `file:`, or `env:` sources, but Solis does not read those references yet. The schema provides no arbitrary command, arbitrary SQL, table-scan, process-argument, environment, journal, or payload collection fields. Health-check body collection must remain `false`.

## Quickstart

From the repository root:

```bash
go test ./...
go build -o solis ./cmd/solis
./solis version
./solis doctor
./solis inventory
```

The binary is written to `./solis`.

## Version and build metadata

Display the build identity as human-readable text or deterministic JSON:

```bash
./solis version
./solis version --json
```

Development builds report version `dev` with unknown commit and build time. Release or packaging workflows can inject these values without changing source files:

```bash
go build -ldflags "\
-X github.com/safwen511/solis-io/internal/version.Version=v0.1.0 \
-X github.com/safwen511/solis-io/internal/version.GitCommit=abc1234 \
-X github.com/safwen511/solis-io/internal/version.BuildTime=2026-08-09T22:00:00Z" \
  -o solis ./cmd/solis
```

Version, commit, build time, Go version, and platform are also recorded in capture metadata, evidence JSON, integrity manifests, and incident reports.

## Product readiness checks

Run the product doctor without elevation:

```bash
./solis doctor
```

Product doctor checks the effective config source and schema, inventory readability, Linux host interfaces, required commands, read-only libvirt access, configured capture-output access and permission hygiene, optional observability configuration, storage mappings, and QEMU procfs permissions. A protected QEMU procfs check may produce a warning suggesting elevation for QEMU-specific commands; doctor itself does not invoke sudo. It also prints a privacy section confirming that observability and capture paths do not collect process arguments, environments, guest files, HTTP bodies, SQL text, table data, or secrets.

The lab mode adds checks for bundled demo assets; it does not replace or weaken product checks:

```bash
./solis doctor --lab
```

## Local host status

Collect a one-second, provider-side host pressure window as deterministic JSON:

```bash
./solis host status --json
```

The command reads fixed local procfs data, sysfs block-device names, filesystem capacity through `statfs`, and short QEMU `comm` names. It reports CPU deltas, memory capacity, optional PSI, filesystem usage, disk counters and rates, optional network counters and rates, and sanitized QEMU RSS/CPU ticks. It does not read process arguments, process environments, guest files, database data, or payloads and does not invoke `sudo`.

## Opt-in guest and service status

With schema version 2 and `observability.guest.enabled: true`, collect deterministic guest or configured-service JSON for one inventory VM:

```bash
./solis --config ./solis.json guest status --vm a-web --json
./solis --config ./solis.json service status --vm a-web --json
```

The SSH transport is non-interactive, uses the configured user and `known_hosts`, derives its destination only from inventory, bounds command output, and exposes only fixed command categories. Guest status contains resource summaries, listening socket metadata, and process pressure using short process names only. Service status contains allowlisted systemd properties for explicitly configured units plus HTTP status code and latency for configured paths; redirects are not followed and response bodies are closed without being read. Solis does not accept arbitrary commands, collect process arguments or environments, read journals, or collect request/response bodies. Guest and service collection is disabled by default.

## Opt-in PostgreSQL statistics

For an inventory VM listed under `observability.databases`, collect a one-shot PostgreSQL statistics document:

```bash
./solis --config ./solis.json db status --vm a-db --json
```

PostgreSQL is the only supported engine. The collector uses five fixed, read-only catalog/statistics queries for version, `pg_stat_database`, non-idle `pg_stat_activity` metadata, extension names, and numeric `pg_stat_statements` counters when configured and installed. It never accepts SQL from configuration or the CLI and does not collect query text, table or schema data, dumps, connection strings, credentials, or secrets. `credential_ref` is recognized by configuration validation but is not read by this collector; the current lab transport uses fixed local peer access through the configured guest SSH target.

## Unified observation snapshot

Combine provider-side host, VM/QEMU, and storage evidence with configured guest, service, and PostgreSQL status in one JSON evidence object:

```bash
./solis --config ./solis.json observe snapshot \
  --victim a-web \
  --discover-suspects \
  --duration 10s \
  --interval 2s \
  --json
```

Use `--suspect <vm>` for an explicit pair, or omit both suspect flags for a victim-centered snapshot. The command assigns one window ID, records each section's observation time, availability, and quality, and emits cautious correlation candidates. Collection is coordinated within one observation window but is not an exact simultaneous sample. It is a correlation foundation, not a diagnosis verdict engine, and it does not claim customer impact or causality. Optional guest, service, and database sections require schema version 2 observability configuration; disabled, unconfigured, unsupported, or failed optional sections are represented in the JSON rather than aborting the whole snapshot.

The snapshot does not collect process arguments, process environments, guest files, journals, request or response bodies, SQL text, table data, dumps, credentials, or secrets. `--include-ebpf-latency` is accepted as an experimental request but currently records that section as unsupported instead of attaching an eBPF program from this orchestration path.

Repeat the same collection as a machine-readable JSON Lines stream:

```bash
./solis --config ./solis.json observe watch \
  --victim a-web \
  --discover-suspects \
  --duration 1s \
  --interval 1s \
  --every 2s \
  --iterations 2 \
  --json
```

Each stdout line is one complete `ObserveSnapshot` JSON document. The final iteration summary and errors are written to stderr so stdout remains parseable JSONL. Omit `--iterations` to continue until Ctrl-C or SIGTERM. Use `--output-dir <dir>` to save the same stream to a timestamped `.jsonl` file while retaining stdout output. Watch remains a foreground CLI loop, not a daemon or verdict engine.

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

Solis does not elevate these host-side diagnosis commands internally. These examples use `sudo` because Linux commonly restricts access to `/proc/<qemu-pid>/io` for QEMU processes owned by another account. The separate opt-in DB collector has one fixed remote peer-access command; use the minimum privileges appropriate for your environment.

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
- `observe-snapshot.json`
- `diagnosis.txt`
- `metadata.txt`
- `incident-report.md`
- `evidence-summary.json`
- `manifest.json`, containing size, mode, and SHA-256 metadata for every other artifact
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

`observe-snapshot.json` contains the unified host, VM/QEMU, storage, and configured optional observability view collected for the capture. If that collection is unavailable, capture still completes and the file contains a structured error and evidence-quality record rather than fabricated metrics. Both `metadata.txt` and `incident-report.md` reference the artifact.

Capture bundles are assembled in a private `0700` staging directory under the configured output root. Artifacts and `manifest.json` are written with mode `0600`; only after every artifact and checksum succeeds does Solis atomically rename the staging directory to its final capture name. Failed writes therefore do not expose a normal-looking partial bundle. The manifest intentionally lists every other artifact rather than itself, because a stable manifest self-checksum is not possible.

Capture metadata, `evidence-summary.json`, `manifest.json`, and `incident-report.md` record the effective Solis version, Git commit, build time, Go version, and platform so evidence can be tied to the binary that produced it.

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

> **Lab only:** This script logs in to the configured stress VM at `192.168.140.40` and generates temporary fio write load inside that guest. Workload SSH/fio orchestration remains outside the Solis CLI product path.

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

- Core storage diagnosis is provider-side and requires no guest login; the optional guest/service commands use explicitly configured, allowlisted SSH access.
- Guest/service collection is disabled by default and targets inventory VMs only.
- Does not inspect guest memory, persistent guest files, process arguments or environments, journals, customer disk contents, database contents, secrets, or application payloads/bodies.
- Unified observe output does not contain SQL text, table data, request or response bodies, arbitrary command output, credentials, tokens, passwords, or private keys.
- Uses provider-visible VM metadata, disk topology, experiment summaries, kernel block counters, and QEMU process counters.
- Collection commands are read-only and do not create, stop, start, or modify VMs.
- Does not bypass host permissions or elevate local host commands internally; the opt-in DB collector may request only fixed non-interactive remote peer access as `postgres`.
- QEMU I/O commands may need to be launched with `sudo` because Linux can protect `/proc/<qemu-pid>/io` from other users.

## Current limitations

- Solis is currently a lab/demo project and is not production-ready.
- Working eBPF block latency is attributed to the host or shared storage path, not to an individual VM. Experimental `vm-block-latency` request-pointer correlation measures host-wide request latency, but it does not yet follow request → bio → blkcg ownership and does not produce per-VM latency histograms.
- QEMU process I/O counters require sufficient procfs permissions. Write-syscall pressure is an activity signal and must not be interpreted as an exact byte count.
- Live-only diagnosis can identify likely provider-side storage-neighbor pressure, but it cannot prove application-level slowdown without report or external application evidence.
- Inventory configuration, bundled workload reports, doctor lab checks, and demo scripts still reflect the included lab environment.
- Watch commands are foreground CLI loops, not a daemonized monitoring service.
- There is no production retention policy, authentication layer, compatibility guarantee, or stability guarantee.
- `ebpf doctor` and `ebpf block-watch` are readiness-oriented. Doctor reports effective UID, lockdown, selected capability bits, kernel eBPF tunables, memlock, embedded-object presence, typed-BTF symbols, and formatted tracepoint IDs, but deliberately does not load or attach a program. `block-events` reads tracepoint metadata, while `block-count` and `block-latency` attach temporary limited-purpose programs.

## Roadmap

- Implement and verifier-test request → bio → blkcg ownership on top of the host request-pointer collector, then validate experimental per-VM latency histograms against cgroup and libvirt counters.
- Cross-signal timestamp correlation across application, QEMU, and host block evidence.
- Durable incident timelines and longer-running observation storage.
- Prometheus metrics and external exporter integrations.
- Interactive terminal UI built on the existing status model.
- HTML and PDF incident-report generation.
- Daemon/service lifecycle, retention controls, authentication, compatibility testing, and production hardening.

## License

No license has been declared in this repository yet.
