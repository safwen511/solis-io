#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd -- "${script_dir}/../.." && pwd)"
readonly fio_script="${script_dir}/run-fio-noise.sh"
readonly report_filter="${script_dir}/benchmark-report.jq"
readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)
readonly fio_guest_file="/home/flint/solis-noise.dat"
readonly fio_jobs=4
readonly fio_block_kib=4

vm_name="b-stress"
duration_seconds=30
interval_seconds=1
warmup_seconds=10
settle_seconds=20
rate_mib=50
iterations=1
control_pairs=0
output_root=""
config_path=""
dry_run=false

workload_pid=""
workload_vm=""
sudo_keepalive_pid=""

# usage prints the accepted command syntax without changing host or guest state.
usage() {
  cat <<'EOF'
Usage: lab/scripts/benchmark-ebpf-overhead.sh [options]

Options:
  --vm a-stress|b-stress  VM that runs the fixed fio workload (default: b-stress)
  --duration-seconds N    Measurement duration per phase (default: 30)
  --interval-seconds N    Solis sampling interval (default: 1)
  --warmup-seconds N      fio preconditioning before each phase (default: 10)
  --settle-seconds N      Idle time between phases (default: 20)
  --rate-mib N            Approximate total fio rate limit in MiB/s (default: 50)
  --iterations N          Paired baseline/eBPF runs (default: 1)
  --control-pairs N       Baseline/baseline variance pairs (default: 0)
  --output-dir DIR        Existing writable non-symlink directory with mode 0700
  --config FILE           Optional Solis JSON configuration
  --dry-run               Print the plan without build, sudo, SSH, or workload
  --help

The benchmark alternates baseline/eBPF phase order, can measure baseline versus
baseline variance, uses the fixed lab fio file, and removes it after every
phase. A review-ready design needs at least six balanced eBPF pairs and two
control pairs. Performance deltas never receive an automatic pass/fail result.
EOF
}

# fail writes one bounded error message and terminates the script unsuccessfully.
fail() {
  echo "Error: $*" >&2
  exit 1
}

# positive_integer accepts only strictly positive decimal integers.
positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

# nonnegative_integer accepts only zero or a positive decimal integer.
nonnegative_integer() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

while (($# > 0)); do
  case "$1" in
    --vm)
      (($# >= 2)) || fail "--vm requires a value"
      vm_name=$2
      shift 2
      ;;
    --duration-seconds)
      (($# >= 2)) || fail "--duration-seconds requires a value"
      duration_seconds=$2
      shift 2
      ;;
    --interval-seconds)
      (($# >= 2)) || fail "--interval-seconds requires a value"
      interval_seconds=$2
      shift 2
      ;;
    --warmup-seconds)
      (($# >= 2)) || fail "--warmup-seconds requires a value"
      warmup_seconds=$2
      shift 2
      ;;
    --settle-seconds)
      (($# >= 2)) || fail "--settle-seconds requires a value"
      settle_seconds=$2
      shift 2
      ;;
    --rate-mib)
      (($# >= 2)) || fail "--rate-mib requires a value"
      rate_mib=$2
      shift 2
      ;;
    --iterations)
      (($# >= 2)) || fail "--iterations requires a value"
      iterations=$2
      shift 2
      ;;
    --control-pairs)
      (($# >= 2)) || fail "--control-pairs requires a value"
      control_pairs=$2
      shift 2
      ;;
    --output-dir)
      (($# >= 2)) || fail "--output-dir requires a value"
      output_root=$2
      shift 2
      ;;
    --config)
      (($# >= 2)) || fail "--config requires a value"
      config_path=$2
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

case "$vm_name" in
  a-stress|b-stress) ;;
  *) fail "--vm must be a-stress or b-stress" ;;
esac
positive_integer "$duration_seconds" || fail "--duration-seconds must be a positive integer"
positive_integer "$interval_seconds" || fail "--interval-seconds must be a positive integer"
nonnegative_integer "$warmup_seconds" || fail "--warmup-seconds must be a non-negative integer"
nonnegative_integer "$settle_seconds" || fail "--settle-seconds must be a non-negative integer"
positive_integer "$rate_mib" || fail "--rate-mib must be a positive integer"
positive_integer "$iterations" || fail "--iterations must be a positive integer"
nonnegative_integer "$control_pairs" || fail "--control-pairs must be a non-negative integer"
((iterations <= 20)) || fail "--iterations must not exceed 20"
((control_pairs <= 10)) || fail "--control-pairs must not exceed 10"
((interval_seconds <= duration_seconds)) || fail "interval cannot exceed duration"

# Four 4 KiB jobs: total MiB/s = per-job IOPS * 4 KiB * 4 / 1024.
readonly rate_iops_per_job=$((rate_mib * 1024 / fio_block_kib / fio_jobs))
((rate_iops_per_job > 0)) || fail "--rate-mib is too small for the fixed fio geometry"

if [[ -n "$config_path" ]]; then
  [[ -f "$config_path" && -r "$config_path" ]] || fail "configuration is not readable: ${config_path}"
  [[ ! -L "$config_path" ]] || fail "configuration must not be a symbolic link: ${config_path}"
  config_path="$(cd -- "$(dirname -- "$config_path")" && pwd -P)/$(basename -- "$config_path")"
fi

# vm_ip returns the fixed lab inventory address for an allowlisted VM name.
vm_ip() {
  case "$1" in
    a-stress) printf '%s\n' "192.168.130.40" ;;
    b-stress) printf '%s\n' "192.168.140.40" ;;
    *) return 1 ;;
  esac
}

# phase_order performs the bounded phase order step for this lab workflow.
phase_order() {
  local iteration=$1
  if ((iteration % 2 == 1)); then
    printf '%s\n' "baseline ebpf"
  else
    printf '%s\n' "ebpf baseline"
  fi
}

# print_plan shows the complete workload and evidence plan before any remote mutation.
print_plan() {
  echo "Solis eBPF overhead/safety benchmark plan"
  echo "VM: ${vm_name} ($(vm_ip "$vm_name"))"
  echo "Measurement duration: ${duration_seconds}s per phase"
  echo "Sampling interval: ${interval_seconds}s"
  echo "Warm-up: ${warmup_seconds}s per phase"
  echo "Settle: ${settle_seconds}s between phases"
  echo "Rate limit: approximately ${rate_mib} MiB/s total (${rate_iops_per_job} IOPS per fio job)"
  echo "Durability: fdatasync every 1,024 writes"
  echo "Iterations: ${iterations}"
  echo "Control/control pairs: ${control_pairs}"
  echo "Config: ${config_path:-built-in defaults}"
  local iteration
  for ((iteration = 1; iteration <= iterations; iteration++)); do
    echo "- iteration ${iteration}: $(phase_order "$iteration")"
  done
  local control_pair
  for ((control_pair = 1; control_pair <= control_pairs; control_pair++)); do
    echo "- control pair ${control_pair}: baseline baseline"
  done
  if ((iterations < 6 || iterations % 2 != 0 || control_pairs < 2)); then
    echo "Performance assessment: insufficient evidence (need >=6 balanced iterations and >=2 control pairs)"
  else
    echo "Performance assessment: statistics will be emitted for manual review; no automatic performance PASS"
  fi
}

if [[ "$dry_run" == true ]]; then
  print_plan
  exit 0
fi

cd "$repo_root"
umask 077
export LC_ALL=C

for command in awk date find go grep jq mktemp sleep ssh stat sudo uname; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: ${command}"
done
[[ -x /usr/bin/time ]] || fail "required command is missing: /usr/bin/time"
[[ -x "$fio_script" ]] || fail "fio helper is not executable: ${fio_script}"
[[ -r "$report_filter" ]] || fail "benchmark report filter is not readable: ${report_filter}"

if [[ -z "$output_root" ]]; then
  output_root="$(mktemp -d /tmp/solis-ebpf-overhead-XXXXXXXX)"
else
  [[ -d "$output_root" ]] || fail "output directory must already exist: ${output_root}"
  [[ ! -L "$output_root" ]] || fail "output directory must not be a symbolic link: ${output_root}"
  [[ -w "$output_root" ]] || fail "output directory is not writable: ${output_root}"
  output_root="$(cd -- "$output_root" && pwd -P)"
fi
output_mode="$(stat -c '%a' "$output_root")"
[[ "$output_mode" == "700" ]] || fail "output directory mode is ${output_mode}; mode 700 is required"

echo "=== Building Solis ==="
go build -o solis ./cmd/solis
[[ -x ./solis ]] || fail "Solis binary was not built"
./solis version --json >"${output_root}/solis-version.json"

readonly stress_ip="$(vm_ip "$vm_name")"

# check_remote_clean refuses to start when a conflicting remote workload or owned file is present.
check_remote_clean() {
  local process_status=0
  local file_status=0
  ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
    "pgrep -x 'fio' >/dev/null 2>&1" || process_status=$?
  case "$process_status" in
    0) fail "an existing solis-noise workload is running on ${vm_name}" ;;
    1) ;;
    *) fail "could not check for an existing workload on ${vm_name} (ssh status ${process_status})" ;;
  esac
  ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
    "if test -e '${fio_guest_file}'; then exit 21; fi" || file_status=$?
  case "$file_status" in
    0) ;;
    21) fail "the fixed fio file already exists on ${vm_name}: ${fio_guest_file}" ;;
    *) fail "could not check for the fixed fio file on ${vm_name} (ssh status ${file_status})" ;;
  esac
}

# stop_remote_workload terminates only the named lab workload started on the selected guest.
stop_remote_workload() {
  ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
    "pkill -TERM -x 'fio' 2>/dev/null || true" >/dev/null 2>&1 || true
}

# remove_guest_fio_file removes only the fixed fio data path owned by this validation workflow.
remove_guest_fio_file() {
  ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
    "rm -f -- '${fio_guest_file}'" >/dev/null 2>&1
}

# cleanup stops script-owned work and removes only paths allocated by this run.
cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if [[ -n "$workload_pid" ]] && kill -0 "$workload_pid" 2>/dev/null; then
    kill "$workload_pid" 2>/dev/null || true
    wait "$workload_pid" 2>/dev/null || true
  fi
  if [[ -n "$workload_vm" ]]; then
    stop_remote_workload
    remove_guest_fio_file || true
  fi
  if [[ -n "$sudo_keepalive_pid" ]] && kill -0 "$sudo_keepalive_pid" 2>/dev/null; then
    kill "$sudo_keepalive_pid" 2>/dev/null || true
    wait "$sudo_keepalive_pid" 2>/dev/null || true
  fi
  exit "$exit_code"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "=== Checking ${vm_name} (${stress_ip}) ==="
ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" true
ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
  'command -v fio >/dev/null 2>&1 && command -v pgrep >/dev/null 2>&1 && command -v pkill >/dev/null 2>&1' ||
  fail "fio, pgrep, or pkill is unavailable on ${vm_name}"
check_remote_clean

echo "=== Authenticating sudo ==="
sudo -v
(
  while kill -0 "$$" 2>/dev/null; do
    sudo -n true || exit 1
    sleep 60
  done
) &
sudo_keepalive_pid=$!

# start_fio starts fio using fixed, bounded lab arguments.
start_fio() {
  local seconds=$1
  local stdout_file=$2
  local stderr_file=$3
  "$fio_script" "$vm_name" "$seconds" \
    --durable --json --rate-iops "$rate_iops_per_job" \
    >"$stdout_file" 2>"$stderr_file" &
  workload_pid=$!
  workload_vm=$vm_name
}

# wait_fio waits for wait fio while preserving the workload's real exit status.
wait_fio() {
  local status=0
  [[ -n "$workload_pid" ]] || fail "internal error: fio workload PID is missing"
  wait "$workload_pid" || status=$?
  workload_pid=""
  return "$status"
}

# validate_fio_json checks validate fio json and fails rather than accepting incomplete evidence.
validate_fio_json() {
  local path=$1
  jq -e '
    (.jobs | type == "array" and length > 0)
    and ((.jobs[0].error // 0) == 0)
    and ((.jobs[0].write.iops // 0) > 0)
    and ((.jobs[0].write.bw_bytes // 0) > 0)
  ' "$path" >/dev/null || fail "fio did not return valid successful JSON: ${path}"
}

# write_fio_metrics writes write fio metrics in the script's deterministic report format.
write_fio_metrics() {
  local input=$1
  local output=$2
  jq '{
    iops: (.jobs[0].write.iops // 0),
    bandwidth_bytes_per_sec: (.jobs[0].write.bw_bytes // 0),
    bandwidth_mib_per_sec: ((.jobs[0].write.bw_bytes // 0) / 1048576),
    io_bytes: (.jobs[0].write.io_bytes // 0),
    runtime_ms: (.jobs[0].write.runtime // 0),
    latency_mean_ns: (.jobs[0].write.lat_ns.mean // .jobs[0].write.clat_ns.mean // 0),
    latency_stddev_ns: (.jobs[0].write.lat_ns.stddev // .jobs[0].write.clat_ns.stddev // 0),
    completion_latency_mean_ns: (.jobs[0].write.clat_ns.mean // 0),
    completion_latency_stddev_ns: (.jobs[0].write.clat_ns.stddev // 0),
    completion_latency_p50_ns: (.jobs[0].write.clat_ns.percentile["50.000000"] // 0),
    completion_latency_p95_ns: (.jobs[0].write.clat_ns.percentile["95.000000"] // 0),
    completion_latency_p99_ns: (.jobs[0].write.clat_ns.percentile["99.000000"] // 0),
    submission_latency_mean_ns: (.jobs[0].write.slat_ns.mean // 0),
    error: (.jobs[0].error // 0)
  }' "$input" >"$output"
}

# read_time_metric reads read time metric from the script-owned result files.
read_time_metric() {
  local path=$1
  local key=$2
  awk -F= -v key="$key" '$1 == key { print $2; found=1 } END { if (!found) exit 1 }' "$path"
}

# run_warmup runs warmup and propagates any command failure.
run_warmup() {
  local phase_dir=$1
  if ((warmup_seconds == 0)); then
    return 0
  fi
  echo "Warm-up: ${warmup_seconds}s"
  start_fio "$warmup_seconds" "${phase_dir}/warmup-fio.json" "${phase_dir}/warmup-fio.stderr"
  wait_fio || fail "fio warm-up failed; see ${phase_dir}/warmup-fio.stderr"
  validate_fio_json "${phase_dir}/warmup-fio.json"
}

# run_collector runs collector and propagates any command failure.
run_collector() {
  local phase_dir=$1
  local -a command
  local status=0
  command=(
    sudo -n /usr/bin/time
    --format=$'user_seconds=%U\nsystem_seconds=%S\nelapsed_seconds=%e\nmax_rss_kib=%M'
    ./solis
  )
  if [[ -n "$config_path" ]]; then
    command+=(--config "$config_path")
  fi
  command+=(
    ebpf vm-block-latency
    --all-vms
    --duration "${duration_seconds}s"
    --interval "${interval_seconds}s"
    --json
    --output "${phase_dir}/ebpf-vm-block-latency.json"
  )
  "${command[@]}" >"${phase_dir}/collector.stdout" 2>"${phase_dir}/collector-resource.txt" || status=$?
  return "$status"
}

# validate_collector checks validate collector and fails rather than accepting incomplete evidence.
validate_collector() {
  local phase_dir=$1
  local report="${phase_dir}/ebpf-vm-block-latency.json"
  local privacy_status=0
  sudo -n jq empty "$report" || fail "collector output is not valid JSON: ${report}"
  if ! sudo -n jq -e --arg vm "$vm_name" '
    .availability.available == true
    and (.attribution_quality == "available" or .attribution_quality == "degraded")
    and .kernel_counters.map_full == 0
    and .unattributed.map_full == 0
    and .unattributed.dropped_events == 0
    and .unattributed.ring_buffer_lost == 0
    and ([.vms[] | select(.name == $vm) | .total_ops][0] // 0) > 0
    and all(.privacy[]; . == false)
  ' "$report" >/dev/null; then
    sudo -n jq --arg vm "$vm_name" '{
      availability,
      attribution_quality,
      target_vm: ([.vms[] | select(.name == $vm) | {name, total_ops, latency_p95_ms}][0] // null),
      kernel_counters,
      unattributed,
      privacy
    }' "$report" >&2 || true
    fail "collector safety or attribution validation failed: ${report}"
  fi
  sudo -n grep -Eiq 'request_pointer|0xffff|/proc/[0-9]+/(cmdline|environ)' "$report" || privacy_status=$?
  case "$privacy_status" in
    0) fail "collector report failed the privacy scan: ${report}" ;;
    1) ;;
    *) fail "collector report privacy scan could not complete (status ${privacy_status}): ${report}" ;;
  esac
}

# write_collector_summary writes write collector summary in the script's deterministic report format.
write_collector_summary() {
  local phase_dir=$1
  sudo -n jq --arg vm "$vm_name" '{
    available: .availability.available,
    status: .availability.status,
    collection_mode,
    attribution_method,
    attribution_quality,
    host_total_ops: .host_summary.total_ops,
    host_p95_ms: .host_summary.latency_p95_ms,
    attributed_ops: .attribution_summary.attributed_ops,
    unattributed_ops: .attribution_summary.unattributed_ops,
    attributed_percent: .attribution_summary.attributed_percent,
    unattributed_percent: .unattributed.unattributed_percent,
    lookup_miss: .unattributed.lookup_miss,
    incomplete_at_window_end: .unattributed.incomplete_at_window_end,
    map_full: .unattributed.map_full,
    dropped_events: .unattributed.dropped_events,
    ring_buffer_lost: .unattributed.ring_buffer_lost,
    target_vm: ([.vms[] | select(.name == $vm) | {
      name, total_ops, read_ops, write_ops, flush_ops, discard_ops,
      unknown_ops, latency_p95_ms, attribution_quality
    }][0] // null),
    privacy
  }' "${phase_dir}/ebpf-vm-block-latency.json" >"${phase_dir}/collector-summary.json"
}

# run_phase runs phase and propagates any command failure.
run_phase() {
  local mode=$1
  local phase_dir=$2
  local fio_status=0
  local collector_status=0
  mkdir -m 0700 "$phase_dir"
  check_remote_clean
  run_warmup "$phase_dir"

  echo "Measurement: ${mode} (${duration_seconds}s)"
  start_fio "$duration_seconds" "${phase_dir}/measurement-fio.json" "${phase_dir}/measurement-fio.stderr"
  if ! kill -0 "$workload_pid" 2>/dev/null; then
    fail "fio measurement stopped before ${mode} phase"
  fi
  if [[ "$mode" == "ebpf" ]]; then
    run_collector "$phase_dir" || collector_status=$?
  fi
  wait_fio || fio_status=$?
  remove_guest_fio_file || fail "could not remove fixed fio file after ${mode} phase"
  workload_vm=""
  ((fio_status == 0)) || fail "fio ${mode} phase failed; see ${phase_dir}/measurement-fio.stderr"
  validate_fio_json "${phase_dir}/measurement-fio.json"
  write_fio_metrics "${phase_dir}/measurement-fio.json" "${phase_dir}/fio-metrics.json"

  if [[ "$mode" == "ebpf" ]]; then
    ((collector_status == 0)) || fail "eBPF collector failed with status ${collector_status}; see ${phase_dir}/collector-resource.txt"
    validate_collector "$phase_dir"
    write_collector_summary "$phase_dir"
  fi
}

# write_run_summary writes write run summary in the script's deterministic report format.
write_run_summary() {
  local run_dir=$1
  local iteration=$2
  local user_seconds system_seconds elapsed_seconds max_rss_kib
  user_seconds="$(read_time_metric "${run_dir}/ebpf/collector-resource.txt" user_seconds)" ||
    fail "collector user CPU metric is missing"
  system_seconds="$(read_time_metric "${run_dir}/ebpf/collector-resource.txt" system_seconds)" ||
    fail "collector system CPU metric is missing"
  elapsed_seconds="$(read_time_metric "${run_dir}/ebpf/collector-resource.txt" elapsed_seconds)" ||
    fail "collector elapsed metric is missing"
  max_rss_kib="$(read_time_metric "${run_dir}/ebpf/collector-resource.txt" max_rss_kib)" ||
    fail "collector RSS metric is missing"

  jq -n \
    --argjson iteration "$iteration" \
    --arg order "$(phase_order "$iteration")" \
    --slurpfile baseline "${run_dir}/baseline/fio-metrics.json" \
    --slurpfile ebpf_fio "${run_dir}/ebpf/fio-metrics.json" \
    --slurpfile collector "${run_dir}/ebpf/collector-summary.json" \
    --argjson user_seconds "$user_seconds" \
    --argjson system_seconds "$system_seconds" \
    --argjson elapsed_seconds "$elapsed_seconds" \
    --argjson max_rss_kib "$max_rss_kib" \
    '{
      iteration: $iteration,
      phase_order: $order,
      baseline: {fio: $baseline[0]},
      ebpf_enabled: {
        fio: $ebpf_fio[0],
        collector_resources: {
          user_seconds: $user_seconds,
          system_seconds: $system_seconds,
          elapsed_seconds: $elapsed_seconds,
          cpu_core_percent: (
            if $elapsed_seconds > 0
            then (($user_seconds + $system_seconds) / $elapsed_seconds * 100)
            else 0 end
          ),
          max_rss_bytes: ($max_rss_kib * 1024)
        },
        collector: $collector[0]
      },
      comparison: {
        iops_change_percent: (
          if $baseline[0].iops > 0
          then (($ebpf_fio[0].iops - $baseline[0].iops) / $baseline[0].iops * 100)
          else 0 end
        ),
        iops_overhead_percent: (
          if $baseline[0].iops > 0
          then (($baseline[0].iops - $ebpf_fio[0].iops) / $baseline[0].iops * 100)
          else 0 end
        ),
        bandwidth_change_percent: (
          if $baseline[0].bandwidth_bytes_per_sec > 0
          then (($ebpf_fio[0].bandwidth_bytes_per_sec - $baseline[0].bandwidth_bytes_per_sec) / $baseline[0].bandwidth_bytes_per_sec * 100)
          else 0 end
        ),
        latency_mean_change_percent: (
          if $baseline[0].latency_mean_ns > 0
          then (($ebpf_fio[0].latency_mean_ns - $baseline[0].latency_mean_ns) / $baseline[0].latency_mean_ns * 100)
          else 0 end
        ),
        completion_latency_mean_change_percent: (
          if $baseline[0].completion_latency_mean_ns > 0
          then (($ebpf_fio[0].completion_latency_mean_ns - $baseline[0].completion_latency_mean_ns) / $baseline[0].completion_latency_mean_ns * 100)
          else 0 end
        ),
        completion_latency_p50_change_percent: (
          if $baseline[0].completion_latency_p50_ns > 0
          then (($ebpf_fio[0].completion_latency_p50_ns - $baseline[0].completion_latency_p50_ns) / $baseline[0].completion_latency_p50_ns * 100)
          else 0 end
        ),
        completion_latency_p95_change_percent: (
          if $baseline[0].completion_latency_p95_ns > 0
          then (($ebpf_fio[0].completion_latency_p95_ns - $baseline[0].completion_latency_p95_ns) / $baseline[0].completion_latency_p95_ns * 100)
          else 0 end
        ),
        completion_latency_p99_change_percent: (
          if $baseline[0].completion_latency_p99_ns > 0
          then (($ebpf_fio[0].completion_latency_p99_ns - $baseline[0].completion_latency_p99_ns) / $baseline[0].completion_latency_p99_ns * 100)
          else 0 end
        )
      },
      result: "PASS"
    }' >"${run_dir}/run-summary.json"
}

# write_control_summary writes write control summary in the script's deterministic report format.
write_control_summary() {
  local control_dir=$1
  local pair=$2
  jq -n \
    --argjson pair "$pair" \
    --slurpfile first "${control_dir}/first/fio-metrics.json" \
    --slurpfile second "${control_dir}/second/fio-metrics.json" '
    def percent_change($before; $after):
      if $before > 0 then (($after - $before) / $before * 100) else 0 end;
    {
      pair: $pair,
      phase_order: "baseline baseline",
      first: {fio: $first[0]},
      second: {fio: $second[0]},
      comparison: {
        latency_mean_change_percent: percent_change($first[0].latency_mean_ns; $second[0].latency_mean_ns),
        latency_mean_absolute_change_percent: (percent_change($first[0].latency_mean_ns; $second[0].latency_mean_ns) | fabs),
        completion_latency_mean_change_percent: percent_change($first[0].completion_latency_mean_ns; $second[0].completion_latency_mean_ns),
        completion_latency_mean_absolute_change_percent: (percent_change($first[0].completion_latency_mean_ns; $second[0].completion_latency_mean_ns) | fabs),
        completion_latency_p50_change_percent: percent_change($first[0].completion_latency_p50_ns; $second[0].completion_latency_p50_ns),
        completion_latency_p50_absolute_change_percent: (percent_change($first[0].completion_latency_p50_ns; $second[0].completion_latency_p50_ns) | fabs),
        completion_latency_p95_change_percent: percent_change($first[0].completion_latency_p95_ns; $second[0].completion_latency_p95_ns),
        completion_latency_p95_absolute_change_percent: (percent_change($first[0].completion_latency_p95_ns; $second[0].completion_latency_p95_ns) | fabs),
        completion_latency_p99_change_percent: percent_change($first[0].completion_latency_p99_ns; $second[0].completion_latency_p99_ns),
        completion_latency_p99_absolute_change_percent: (percent_change($first[0].completion_latency_p99_ns; $second[0].completion_latency_p99_ns) | fabs)
      },
      result: "PASS"
    }
  ' >"${control_dir}/control-summary.json"
}

print_plan
echo "Output root: ${output_root}"

for ((iteration = 1; iteration <= iterations; iteration++)); do
  run_dir="${output_root}/run-$(printf '%02d' "$iteration")"
  [[ ! -e "$run_dir" ]] || fail "benchmark run output already exists: ${run_dir}"
  mkdir -m 0700 "$run_dir"
  echo "=== Iteration ${iteration}/${iterations}: $(phase_order "$iteration") ==="
  phase_index=0
  for mode in $(phase_order "$iteration"); do
    run_phase "$mode" "${run_dir}/${mode}"
    phase_index=$((phase_index + 1))
    if ((phase_index < 2 && settle_seconds > 0)); then
      echo "Settling for ${settle_seconds}s"
      sleep "$settle_seconds"
    fi
  done
  write_run_summary "$run_dir" "$iteration"
  echo "Iteration ${iteration}: PASS"
  jq '{iteration, comparison, collector_resources: .ebpf_enabled.collector_resources, collector: .ebpf_enabled.collector}' \
    "${run_dir}/run-summary.json"
done

for ((control_pair = 1; control_pair <= control_pairs; control_pair++)); do
  control_dir="${output_root}/control-$(printf '%02d' "$control_pair")"
  [[ ! -e "$control_dir" ]] || fail "benchmark control output already exists: ${control_dir}"
  mkdir -m 0700 "$control_dir"
  echo "=== Control pair ${control_pair}/${control_pairs}: baseline baseline ==="
  run_phase baseline "${control_dir}/first"
  if ((settle_seconds > 0)); then
    echo "Settling for ${settle_seconds}s"
    sleep "$settle_seconds"
  fi
  run_phase baseline "${control_dir}/second"
  write_control_summary "$control_dir" "$control_pair"
  echo "Control pair ${control_pair}: PASS"
  jq '{pair, comparison}' "${control_dir}/control-summary.json"
done

jq -s '.' "${output_root}"/run-*/run-summary.json >"${output_root}/paired-runs.json"
if ((control_pairs > 0)); then
  jq -s '.' "${output_root}"/control-*/control-summary.json >"${output_root}/control-runs.json"
else
  printf '%s\n' '[]' >"${output_root}/control-runs.json"
fi

jq -n \
  --arg observed_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg vm "$vm_name" \
  --arg kernel_release "$(uname -r)" \
  --arg architecture "$(uname -m)" \
  --arg config_source "${config_path:-built-in defaults}" \
  --argjson duration_seconds "$duration_seconds" \
  --argjson interval_seconds "$interval_seconds" \
  --argjson warmup_seconds "$warmup_seconds" \
  --argjson settle_seconds "$settle_seconds" \
  --argjson rate_mib "$rate_mib" \
  --argjson rate_iops_per_job "$rate_iops_per_job" \
  --argjson requested_iterations "$iterations" \
  --argjson requested_control_pairs "$control_pairs" \
  --slurpfile build "${output_root}/solis-version.json" \
  --slurpfile runs "${output_root}/paired-runs.json" \
  --slurpfile controls "${output_root}/control-runs.json" \
  -f "$report_filter" >"${output_root}/benchmark-report.json"

bad_modes="$(find "$output_root" -type f -printf '%m %p\n' | awk '$1 != "600"')"
[[ -z "$bad_modes" ]] || fail "benchmark contains non-0600 files: ${bad_modes}"
bad_directory_modes="$(find "$output_root" -type d -printf '%m %p\n' | awk '$1 != "700"')"
[[ -z "$bad_directory_modes" ]] || fail "benchmark contains non-0700 directories: ${bad_directory_modes}"
privacy_status=0
sudo -n grep -ERiq 'request_pointer|0xffff|/proc/[0-9]+/(cmdline|environ)' "$output_root" || privacy_status=$?
case "$privacy_status" in
  0) fail "benchmark output failed the privacy scan" ;;
  1) ;;
  *) fail "benchmark privacy scan could not complete (status ${privacy_status})" ;;
esac

if [[ -n "$sudo_keepalive_pid" ]] && kill -0 "$sudo_keepalive_pid" 2>/dev/null; then
  kill "$sudo_keepalive_pid" 2>/dev/null || true
  wait "$sudo_keepalive_pid" 2>/dev/null || true
fi
sudo_keepalive_pid=""
trap - EXIT INT TERM
echo "=== Benchmark safety validation: PASS ==="
jq '{safety_assessment, performance_assessment}' "${output_root}/benchmark-report.json"
echo "Benchmark report: ${output_root}/benchmark-report.json"
