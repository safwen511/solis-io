#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd -- "${script_dir}/../.." && pwd)"
readonly fio_script="${script_dir}/run-fio-noise.sh"
readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)
readonly fio_guest_file="/home/flint/solis-noise.dat"

scenario_selection="all"
window_seconds=10
interval_seconds=2
warmup_seconds=10
fio_seconds=0
output_root=""
config_path=""
dry_run=false

workload_pids=()
workload_vms=()
sudo_keepalive_pid=""

# usage prints the accepted command syntax without changing host or guest state.
usage() {
  cat <<'EOF'
Usage: lab/scripts/validate-vm-attribution.sh [options]

Options:
  --scenario idle|suspect|victim|mixed|all
  --window-seconds N       Capture diagnosis and observe window length (default: 10)
  --interval-seconds N     Sampling interval (default: 2)
  --warmup-seconds N       Workload warm-up before capture (default: 10)
  --fio-seconds N          fio runtime; must cover both capture windows
  --output-dir DIR         Existing, writable, non-symlink directory
  --config FILE            Optional Solis JSON configuration
  --dry-run                Print the validated scenario plan without sudo/SSH
  --help

Scenarios:
  idle     a-web victim, automatic discovery, no generated workload
  suspect  a-web victim, automatic discovery, b-stress fio
  victim   a-stress victim, automatic discovery, a-stress fio
  mixed    a-stress victim, explicit b-stress suspect, fio on both VMs

The harness writes only beneath its output directory and uses fixed fio files
inside a-stress/b-stress. Those fixed guest test files are removed on cleanup.
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
    --scenario)
      (($# >= 2)) || fail "--scenario requires a value"
      scenario_selection=$2
      shift 2
      ;;
    --window-seconds)
      (($# >= 2)) || fail "--window-seconds requires a value"
      window_seconds=$2
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
    --fio-seconds)
      (($# >= 2)) || fail "--fio-seconds requires a value"
      fio_seconds=$2
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

case "$scenario_selection" in
  idle|suspect|victim|mixed|all) ;;
  *) fail "unsupported scenario: ${scenario_selection}" ;;
esac
positive_integer "$window_seconds" || fail "--window-seconds must be a positive integer"
positive_integer "$interval_seconds" || fail "--interval-seconds must be a positive integer"
nonnegative_integer "$warmup_seconds" || fail "--warmup-seconds must be a non-negative integer"
((interval_seconds <= window_seconds)) || fail "interval cannot exceed the window"
if ((fio_seconds == 0)); then
  fio_seconds=$((window_seconds * 2 + warmup_seconds + 10))
fi
positive_integer "$fio_seconds" || fail "--fio-seconds must be a positive integer"
readonly minimum_fio_seconds=$((window_seconds * 2 + warmup_seconds + 10))
((fio_seconds >= minimum_fio_seconds)) ||
  fail "--fio-seconds must be at least ${minimum_fio_seconds} to cover diagnosis and observe windows"

if [[ -n "$config_path" ]]; then
  [[ -f "$config_path" && -r "$config_path" ]] || fail "configuration is not readable: ${config_path}"
  [[ ! -L "$config_path" ]] || fail "configuration must not be a symbolic link: ${config_path}"
  config_path="$(cd -- "$(dirname -- "$config_path")" && pwd -P)/$(basename -- "$config_path")"
fi

scenarios=()
if [[ "$scenario_selection" == "all" ]]; then
  scenarios=(idle suspect victim mixed)
else
  scenarios=("$scenario_selection")
fi

# print_plan shows the complete workload and evidence plan before any remote mutation.
print_plan() {
  echo "Solis VM-attribution validation plan"
  echo "Window: ${window_seconds}s"
  echo "Interval: ${interval_seconds}s"
  echo "Workload warm-up: ${warmup_seconds}s"
  echo "fio runtime: ${fio_seconds}s"
  echo "fio mode: durable fdatasync every 1,024 writes"
  echo "Config: ${config_path:-built-in defaults}"
  echo "Scenarios: ${scenarios[*]}"
  for scenario in "${scenarios[@]}"; do
    case "$scenario" in
      idle) echo "- idle: victim=a-web, discovery=yes, workload=none" ;;
      suspect) echo "- suspect: victim=a-web, discovery=yes, workload=b-stress" ;;
      victim) echo "- victim: victim=a-stress, discovery=yes, workload=a-stress" ;;
      mixed) echo "- mixed: victim=a-stress, suspect=b-stress, workload=a-stress+b-stress" ;;
    esac
  done
}

if [[ "$dry_run" == true ]]; then
  print_plan
  exit 0
fi

cd "$repo_root"
umask 077

for command in awk find go grep jq sha256sum sort ssh stat sudo tail tee; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: ${command}"
done
[[ -x "$fio_script" ]] || fail "fio helper is not executable: ${fio_script}"

if [[ -z "$output_root" ]]; then
  output_root="$(mktemp -d /tmp/solis-attribution-validation-XXXXXXXX)"
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

needed_vms=()
for scenario in "${scenarios[@]}"; do
  case "$scenario" in
    suspect) needed_vms+=(b-stress) ;;
    victim) needed_vms+=(a-stress) ;;
    mixed) needed_vms+=(a-stress b-stress) ;;
  esac
done

# vm_ip returns the fixed lab inventory address for an allowlisted VM name.
vm_ip() {
  case "$1" in
    a-stress) printf '%s\n' "192.168.130.40" ;;
    b-stress) printf '%s\n' "192.168.140.40" ;;
    *) return 1 ;;
  esac
}

unique_needed_vms=()
for vm in "${needed_vms[@]}"; do
  duplicate=false
  for existing in "${unique_needed_vms[@]}"; do
    [[ "$existing" == "$vm" ]] && duplicate=true
  done
  [[ "$duplicate" == true ]] || unique_needed_vms+=("$vm")
done

for vm in "${unique_needed_vms[@]}"; do
  ip="$(vm_ip "$vm")"
  echo "=== Checking ${vm} (${ip}) ==="
  ssh "${ssh_options[@]}" "${ssh_user}@${ip}" true
  ssh "${ssh_options[@]}" "${ssh_user}@${ip}" \
    'command -v fio >/dev/null 2>&1 && command -v pgrep >/dev/null 2>&1 && command -v pkill >/dev/null 2>&1' ||
    fail "fio, pgrep, or pkill is unavailable on ${vm}"
  process_status=0
  ssh "${ssh_options[@]}" "${ssh_user}@${ip}" \
    "pgrep -f '[s]olis-noise' >/dev/null 2>&1" || process_status=$?
  case "$process_status" in
    0) fail "an existing solis-noise workload is running on ${vm}; stop it before validation" ;;
    1) ;;
    *) fail "could not check for an existing workload on ${vm} (ssh status ${process_status})" ;;
  esac

  file_status=0
  ssh "${ssh_options[@]}" "${ssh_user}@${ip}" \
    "if test -e '${fio_guest_file}'; then exit 21; fi" || file_status=$?
  case "$file_status" in
    0) ;;
    21) fail "the fixed fio test file already exists on ${vm}: ${fio_guest_file}" ;;
    *) fail "could not check for the fixed fio file on ${vm} (ssh status ${file_status})" ;;
  esac
done

# stop_remote_workload terminates only the named lab workload started on the selected guest.
stop_remote_workload() {
  local vm=$1
  local ip
  ip="$(vm_ip "$vm")" || return 0
  ssh "${ssh_options[@]}" "${ssh_user}@${ip}" \
    "pkill -TERM -f '[s]olis-noise' 2>/dev/null || true" >/dev/null 2>&1 || true
}

# remove_guest_fio_file removes only the fixed fio data path owned by this validation workflow.
remove_guest_fio_file() {
  local vm=$1
  local ip
  ip="$(vm_ip "$vm")" || return 0
  ssh "${ssh_options[@]}" "${ssh_user}@${ip}" \
    "rm -f -- '${fio_guest_file}'" >/dev/null 2>&1
}

# cleanup stops script-owned work and removes only paths allocated by this run.
cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  for pid in "${workload_pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
  done
  for vm in "${workload_vms[@]}"; do
    stop_remote_workload "$vm"
    remove_guest_fio_file "$vm" || true
  done
  if [[ -n "$sudo_keepalive_pid" ]] && kill -0 "$sudo_keepalive_pid" 2>/dev/null; then
    kill "$sudo_keepalive_pid" 2>/dev/null || true
    wait "$sudo_keepalive_pid" 2>/dev/null || true
  fi
  exit "$exit_code"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
  local vm=$1
  local log=$2
  "$fio_script" "$vm" "$fio_seconds" --durable >"$log" 2>&1 &
  workload_pids+=("$!")
  workload_vms+=("$vm")
}

# wait_for_workloads waits for workloads while preserving the workload's real exit status.
wait_for_workloads() {
  local status=0
  local pid
  for pid in "${workload_pids[@]}"; do
    wait "$pid" || status=$?
  done
  workload_pids=()
  return "$status"
}

# cleanup_workload_files performs the bounded cleanup workload files step for this lab workflow.
cleanup_workload_files() {
  local vm
  local status=0
  for vm in "${workload_vms[@]}"; do
    remove_guest_fio_file "$vm" || status=1
  done
  workload_vms=()
  return "$status"
}

# assert_common_capture checks common capture and fails rather than accepting incomplete evidence.
assert_common_capture() {
  local capture_dir=$1
  local scenario_dir=$2
  local mode
  mode="$(sudo -n stat -c '%a' "$capture_dir")"
  [[ "$mode" == "700" ]] || fail "capture directory mode is ${mode}, want 700"

  local bad_modes
  bad_modes="$(sudo -n find "$capture_dir" -maxdepth 1 -type f -printf '%m %f\n' | awk '$1 != "600"')"
  [[ -z "$bad_modes" ]] || fail "capture contains non-0600 files: ${bad_modes}"

  for json_file in manifest.json evidence-summary.json ebpf-vm-block-latency.json observe-snapshot.json; do
    sudo -n jq empty "${capture_dir}/${json_file}" ||
      fail "capture JSON is invalid: ${json_file}"
  done

  if ! sudo -n jq -r --arg directory "$capture_dir" \
    '.files[] | "\(.sha256)  \($directory)/\(.path)"' \
    "${capture_dir}/manifest.json" |
    sudo -n sha256sum -c - >"${scenario_dir}/manifest-checks.txt"; then
    fail "capture manifest checksum validation failed; see ${scenario_dir}/manifest-checks.txt"
  fi

  if sudo -n grep -ERin \
    'request_pointer|0xffff|/proc/[0-9]+/(cmdline|environ)' \
    "$capture_dir" >"${scenario_dir}/privacy-scan.txt"; then
    fail "privacy scan failed; see ${scenario_dir}/privacy-scan.txt"
  fi
  echo "Privacy scan: PASS" >"${scenario_dir}/privacy-scan.txt"

  if ! sudo -n jq -e '
    .ebpf_vm_attribution != null
    and .ebpf_vm_attribution.source_window == "noisy_neighbor_diagnosis_window"
    and ([.evidence_quality.sections[]
          | select(.section == "ebpf_latency" and .state == "unsupported")]
         | length == 0)
    and all(.privacy[]; . == false)
    and all(.ebpf_vm_attribution.privacy[]; . == false)
  ' "${capture_dir}/observe-snapshot.json" >/dev/null; then
    fail "observe snapshot failed common eBPF evidence or privacy assertions"
  fi
}

# print_attribution_failure performs the bounded print attribution failure step for this lab workflow.
print_attribution_failure() {
  local snapshot=$1
  local capture_dir
  capture_dir="$(dirname -- "$snapshot")"
  echo "Attribution assertion evidence:" >&2
  sudo -n jq '{
    selected_suspect,
    attribution: {
      available: .ebpf_vm_attribution.available,
      status: .ebpf_vm_attribution.status,
      quality: .ebpf_vm_attribution.quality,
      attributed_percent: .ebpf_vm_attribution.attributed_percent,
      victim_total_ops: .ebpf_vm_attribution.victim_total_ops,
      suspect_total_ops: .ebpf_vm_attribution.suspect_total_ops
    }
  }' "$snapshot" >&2 || true
  sudo -n jq '{kernel_counters, unattributed, attribution_summary}' \
    "${capture_dir}/ebpf-vm-block-latency.json" >&2 || true
}

# assert_scenario checks scenario and fails rather than accepting incomplete evidence.
assert_scenario() {
  local scenario=$1
  local snapshot=$2
  case "$scenario" in
    idle)
      return 0
      ;;
    suspect)
      if ! sudo -n jq -e '
        .selected_suspect == "b-stress"
        and .ebpf_vm_attribution.available == true
        and (.ebpf_vm_attribution.suspect_total_ops > .ebpf_vm_attribution.victim_total_ops)
        and ([.correlations[]
              | select(.name == "vm_ebpf_attribution_available" and .present == true)]
             | length == 1)
      ' "$snapshot" >/dev/null; then
        print_attribution_failure "$snapshot"
        fail "suspect scenario did not produce available b-stress VM-attribution evidence"
      fi
      ;;
    victim)
      if ! sudo -n jq -e '
        .victim.name == "a-stress"
        and .ebpf_vm_attribution.available == true
        and (.ebpf_vm_attribution.victim_total_ops > 0)
      ' "$snapshot" >/dev/null; then
        print_attribution_failure "$snapshot"
        fail "victim scenario did not attribute block operations to a-stress"
      fi
      ;;
    mixed)
      if ! sudo -n jq -e '
        .victim.name == "a-stress"
        and .selected_suspect == "b-stress"
        and .ebpf_vm_attribution.available == true
        and (.ebpf_vm_attribution.victim_total_ops > 0)
        and (.ebpf_vm_attribution.suspect_total_ops > 0)
      ' "$snapshot" >/dev/null; then
        print_attribution_failure "$snapshot"
        fail "mixed scenario did not attribute block operations to both stress VMs"
      fi
      ;;
  esac
}

# run_scenario runs scenario and propagates any command failure.
run_scenario() {
  local scenario=$1
  local scenario_dir="${output_root}/${scenario}"
  local capture_status=0
  local workload_status=0
  local capture_dir
  local -a capture_command
  [[ ! -e "$scenario_dir" ]] || fail "scenario output already exists: ${scenario_dir}"
  mkdir -m 0700 "$scenario_dir"

  local victim
  local suspect=""
  local discovery=true
  case "$scenario" in
    idle)
      victim=a-web
      ;;
    suspect)
      victim=a-web
      start_fio b-stress "${scenario_dir}/b-stress-fio.txt"
      ;;
    victim)
      victim=a-stress
      start_fio a-stress "${scenario_dir}/a-stress-fio.txt"
      ;;
    mixed)
      victim=a-stress
      suspect=b-stress
      discovery=false
      start_fio a-stress "${scenario_dir}/a-stress-fio.txt"
      start_fio b-stress "${scenario_dir}/b-stress-fio.txt"
      ;;
  esac

  if ((${#workload_pids[@]} > 0)); then
    if ((warmup_seconds > 0)); then
      echo "Warming workload for ${warmup_seconds}s"
      sleep "$warmup_seconds"
    fi
    for pid in "${workload_pids[@]}"; do
      kill -0 "$pid" 2>/dev/null || fail "${scenario} workload stopped before capture"
    done
  fi

  capture_command=(sudo -n ./solis)
  if [[ -n "$config_path" ]]; then
    capture_command+=(--config "$config_path")
  fi
  capture_command+=(capture noisy-neighbor --victim "$victim")
  if [[ "$discovery" == true ]]; then
    capture_command+=(--discover-suspects)
  else
    capture_command+=(--suspect "$suspect")
  fi
  capture_command+=(
    --duration "${window_seconds}s"
    --interval "${interval_seconds}s"
    --include-ebpf-latency
    --output-dir "$scenario_dir"
  )

  echo "=== Scenario: ${scenario} ==="
  "${capture_command[@]}" 2>&1 | tee "${scenario_dir}/capture-command.txt" || capture_status=$?
  wait_for_workloads || workload_status=$?
  cleanup_workload_files || fail "could not remove fixed guest fio test file"
  ((capture_status == 0)) || fail "${scenario} capture failed with status ${capture_status}"
  ((workload_status == 0)) || fail "${scenario} workload failed with status ${workload_status}"

  capture_dir="$(sudo -n find "$scenario_dir" -mindepth 1 -maxdepth 1 -type d -name 'capture-*' | sort | tail -n 1)"
  [[ -n "$capture_dir" ]] || fail "${scenario} capture directory was not found"
  assert_common_capture "$capture_dir" "$scenario_dir"
  assert_scenario "$scenario" "${capture_dir}/observe-snapshot.json"

  sudo -n jq --arg scenario "$scenario" --arg capture_directory "$capture_dir" '{
    scenario: $scenario,
    capture_directory: $capture_directory,
    selected_suspect,
    attribution_available: .ebpf_vm_attribution.available,
    attribution_quality: .ebpf_vm_attribution.quality,
    attributed_percent: .ebpf_vm_attribution.attributed_percent,
    unattributed_percent: .ebpf_vm_attribution.unattributed_percent,
    victim_total_ops: .ebpf_vm_attribution.victim_total_ops,
    suspect_total_ops: .ebpf_vm_attribution.suspect_total_ops,
    host_p95_ms: .ebpf_vm_attribution.host_p95_ms,
    result: "PASS"
  }' "${capture_dir}/observe-snapshot.json" >"${scenario_dir}/validation-summary.json"

  echo "Scenario ${scenario}: PASS"
  cat "${scenario_dir}/validation-summary.json"
}

print_plan
echo "Output root: ${output_root}"
for scenario in "${scenarios[@]}"; do
  run_scenario "$scenario"
done

jq -s \
  --arg scenario_selection "$scenario_selection" \
  --arg window_duration "${window_seconds}s" \
  --arg interval "${interval_seconds}s" \
  --arg workload_warmup "${warmup_seconds}s" \
  --arg fio_runtime "${fio_seconds}s" \
  --arg fio_mode "durable_fdatasync_1024" \
  --arg config_source "${config_path:-built-in defaults}" \
  '{
    schema_version: "1",
    scenario_selection: $scenario_selection,
    window_duration: $window_duration,
    interval: $interval,
    workload_warmup: $workload_warmup,
    fio_runtime: $fio_runtime,
    fio_mode: $fio_mode,
    config_source: $config_source,
    scenarios: .,
    result: "PASS"
  }' \
  "${output_root}"/*/validation-summary.json >"${output_root}/validation-report.json"

if [[ -n "$sudo_keepalive_pid" ]] && kill -0 "$sudo_keepalive_pid" 2>/dev/null; then
  kill "$sudo_keepalive_pid" 2>/dev/null || true
  wait "$sudo_keepalive_pid" 2>/dev/null || true
fi
sudo_keepalive_pid=""
trap - EXIT INT TERM
echo "=== Validation complete: PASS ==="
echo "Validation report: ${output_root}/validation-report.json"
