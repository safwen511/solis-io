#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd -- "${script_dir}/../.." && pwd)"
readonly client_script="${script_dir}/run-client-workload.sh"
readonly fio_script="${script_dir}/run-fio-noise.sh"
readonly phase_filter="${script_dir}/live-impact-phases.jq"
readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)
readonly client_ip="192.168.130.10"
readonly stress_ip="192.168.140.40"
readonly client_guest_program="/opt/solis-workload/solis_client.py"
readonly fio_guest_file="/home/flint/solis-noise.dat"

baseline_seconds=30
pressure_seconds=60
recovery_seconds=30
capture_warmup_seconds=10
window_seconds=20
interval_seconds=2
request_rate=30
concurrency=20
request_timeout=5
output_root=""
config_path=""
dry_run=false

client_pid=""
fio_pid=""
client_owned=false
fio_owned=false
sudo_keepalive_pid=""

usage() {
  cat <<'EOF'
Usage: lab/scripts/validate-live-app-impact.sh [options]

Options:
  --baseline-seconds N       Normal traffic before pressure (default: 30)
  --pressure-seconds N       b-stress fio duration (default: 60)
  --recovery-seconds N       Normal traffic after pressure (default: 30)
  --capture-warmup-seconds N fio warm-up before Solis capture (default: 10)
  --window-seconds N         Solis observation window (default: 20)
  --interval-seconds N       Solis sampling interval (default: 2)
  --rate N                   a-client scheduled requests/second (default: 30)
  --concurrency N            a-client maximum in-flight requests (default: 20)
  --timeout N                a-client request timeout seconds (default: 5)
  --output-dir DIR           Existing empty non-symlink directory, mode 0700
  --config FILE              Optional Solis JSON configuration
  --dry-run                  Print the plan without build, sudo, SSH, or traffic
  --help

The fixed lab scenario is:
  a-client -> a-web /write -> PostgreSQL on a-db
  b-stress -> durable fio storage pressure

The harness retains aggregate request timing/status counters only. It does not
retain HTTP bodies, SQL text, table data, secrets, or raw kernel pointers.
EOF
}

fail() {
  echo "Error: $*" >&2
  exit 1
}

positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

nonnegative_integer() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

bounded_decimal() {
  local value=$1
  local minimum=$2
  local maximum=$3
  [[ "$value" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] &&
    awk -v value="$value" -v minimum="$minimum" -v maximum="$maximum" \
      'BEGIN { exit !(value >= minimum && value <= maximum) }'
}

while (($# > 0)); do
  case "$1" in
    --baseline-seconds)
      (($# >= 2)) || fail "--baseline-seconds requires a value"
      baseline_seconds=$2
      shift 2
      ;;
    --pressure-seconds)
      (($# >= 2)) || fail "--pressure-seconds requires a value"
      pressure_seconds=$2
      shift 2
      ;;
    --recovery-seconds)
      (($# >= 2)) || fail "--recovery-seconds requires a value"
      recovery_seconds=$2
      shift 2
      ;;
    --capture-warmup-seconds)
      (($# >= 2)) || fail "--capture-warmup-seconds requires a value"
      capture_warmup_seconds=$2
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
    --rate)
      (($# >= 2)) || fail "--rate requires a value"
      request_rate=$2
      shift 2
      ;;
    --concurrency)
      (($# >= 2)) || fail "--concurrency requires a value"
      concurrency=$2
      shift 2
      ;;
    --timeout)
      (($# >= 2)) || fail "--timeout requires a value"
      request_timeout=$2
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

positive_integer "$baseline_seconds" || fail "--baseline-seconds must be a positive integer"
positive_integer "$pressure_seconds" || fail "--pressure-seconds must be a positive integer"
positive_integer "$recovery_seconds" || fail "--recovery-seconds must be a positive integer"
nonnegative_integer "$capture_warmup_seconds" || fail "--capture-warmup-seconds must be a non-negative integer"
positive_integer "$window_seconds" || fail "--window-seconds must be a positive integer"
positive_integer "$interval_seconds" || fail "--interval-seconds must be a positive integer"
positive_integer "$concurrency" || fail "--concurrency must be a positive integer"
((concurrency <= 100)) || fail "--concurrency must not exceed 100"
bounded_decimal "$request_rate" 0.1 200 || fail "--rate must be from 0.1 through 200"
bounded_decimal "$request_timeout" 0.1 30 || fail "--timeout must be from 0.1 through 30"
((interval_seconds <= window_seconds)) || fail "interval cannot exceed the Solis window"

readonly minimum_pressure_seconds=$((capture_warmup_seconds + window_seconds * 2 + 10))
((pressure_seconds >= minimum_pressure_seconds)) ||
  fail "--pressure-seconds must be at least ${minimum_pressure_seconds} to cover warm-up and capture windows"
readonly client_duration_seconds=$((baseline_seconds + pressure_seconds + recovery_seconds))
readonly pressure_start_offset=$baseline_seconds
readonly recovery_start_offset=$((baseline_seconds + pressure_seconds))

if [[ -n "$config_path" ]]; then
  [[ -f "$config_path" && -r "$config_path" ]] || fail "configuration is not readable: ${config_path}"
  [[ ! -L "$config_path" ]] || fail "configuration must not be a symbolic link: ${config_path}"
  config_path="$(cd -- "$(dirname -- "$config_path")" && pwd -P)/$(basename -- "$config_path")"
fi

print_plan() {
  echo "Solis live application-impact validation plan"
  echo "Application path: a-client -> a-web /write -> a-db"
  echo "Noisy neighbor: b-stress durable fio"
  echo "Baseline: ${baseline_seconds}s"
  echo "Pressure: ${pressure_seconds}s"
  echo "Recovery: ${recovery_seconds}s"
  echo "a-client traffic: ${request_rate} requests/s, concurrency ${concurrency}, timeout ${request_timeout}s"
  echo "Capture warm-up: ${capture_warmup_seconds}s"
  echo "Solis window/interval: ${window_seconds}s / ${interval_seconds}s"
  echo "Total client duration: ${client_duration_seconds}s"
  echo "Config: ${config_path:-built-in defaults}"
}

if [[ "$dry_run" == true ]]; then
  print_plan
  exit 0
fi

cd "$repo_root"
umask 077
export LC_ALL=C

for command in awk date find go grep jq mktemp sed sha256sum sleep sort ssh stat sudo tail uname; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: ${command}"
done
[[ -x "$client_script" ]] || fail "client workload helper is not executable: ${client_script}"
[[ -x "$fio_script" ]] || fail "fio helper is not executable: ${fio_script}"
[[ -r "$phase_filter" ]] || fail "application phase filter is not readable: ${phase_filter}"

if [[ -z "$output_root" ]]; then
  output_root="$(mktemp -d /tmp/solis-live-impact-XXXXXXXX)"
else
  [[ -d "$output_root" ]] || fail "output directory must already exist: ${output_root}"
  [[ ! -L "$output_root" ]] || fail "output directory must not be a symbolic link: ${output_root}"
  [[ -w "$output_root" ]] || fail "output directory is not writable: ${output_root}"
  output_root="$(cd -- "$output_root" && pwd -P)"
  [[ -z "$(find "$output_root" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
    fail "output directory must be empty: ${output_root}"
fi
output_mode="$(stat -c '%a' "$output_root")"
[[ "$output_mode" == "700" ]] || fail "output directory mode is ${output_mode}; mode 700 is required"

stop_remote_client() {
  ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" \
    "pkill -TERM -x 'solis-client' 2>/dev/null || true" >/dev/null 2>&1 || true
}

stop_remote_fio() {
  ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
    "pkill -TERM -x 'fio' 2>/dev/null || true" >/dev/null 2>&1 || true
}

remove_guest_fio_file() {
  ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
    "rm -f -- '${fio_guest_file}'" >/dev/null 2>&1
}

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if [[ -n "$client_pid" ]] && kill -0 "$client_pid" 2>/dev/null; then
    kill "$client_pid" 2>/dev/null || true
    wait "$client_pid" 2>/dev/null || true
  fi
  if [[ -n "$fio_pid" ]] && kill -0 "$fio_pid" 2>/dev/null; then
    kill "$fio_pid" 2>/dev/null || true
    wait "$fio_pid" 2>/dev/null || true
  fi
  [[ "$client_owned" == false ]] || stop_remote_client
  if [[ "$fio_owned" == true ]]; then
    stop_remote_fio
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

check_no_process() {
  local ip=$1
  local process_name=$2
  local label=$3
  local status=0
  ssh "${ssh_options[@]}" "${ssh_user}@${ip}" \
    "pgrep -x '${process_name}' >/dev/null 2>&1" || status=$?
  case "$status" in
    0) fail "an existing ${label} process is running; stop it before validation" ;;
    1) ;;
    *) fail "could not check for ${label} (ssh status ${status})" ;;
  esac
}

wait_for_process() {
  local ip=$1
  local process_name=$2
  local label=$3
  local local_pid=$4
  local attempt
  for attempt in {1..50}; do
    kill -0 "$local_pid" 2>/dev/null || fail "${label} stopped during startup"
    if ssh "${ssh_options[@]}" "${ssh_user}@${ip}" \
      "pgrep -x '${process_name}' >/dev/null 2>&1"; then
      return 0
    fi
    sleep 0.2
  done
  fail "${label} did not expose its fixed process identity within 10 seconds; redeploy the current lab workload if needed"
}

echo "=== Checking a-client (${client_ip}) ==="
ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" true
ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" \
  "test -x '${client_guest_program}' && command -v python3 >/dev/null 2>&1 && command -v pgrep >/dev/null 2>&1 && command -v pkill >/dev/null 2>&1" ||
  fail "a-client workload is not deployed; run ./lab/scripts/deploy-client-workload.sh"
check_no_process "$client_ip" 'solis-client' "Solis client workload"

echo "=== Checking b-stress (${stress_ip}) ==="
ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" true
ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
  'command -v fio >/dev/null 2>&1 && command -v pgrep >/dev/null 2>&1 && command -v pkill >/dev/null 2>&1' ||
  fail "fio, pgrep, or pkill is unavailable on b-stress"
check_no_process "$stress_ip" 'fio' "fio workload"
file_status=0
ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
  "if test -e '${fio_guest_file}'; then exit 21; fi" || file_status=$?
case "$file_status" in
  0) ;;
  21) fail "the fixed fio test file already exists on b-stress: ${fio_guest_file}" ;;
  *) fail "could not check for the fixed fio file on b-stress (ssh status ${file_status})" ;;
esac

echo "=== Building Solis ==="
go build -o solis ./cmd/solis
[[ -x ./solis ]] || fail "Solis binary was not built"
./solis version --json >"${output_root}/solis-version.json"

echo "=== Authenticating sudo ==="
sudo -v
(
  while kill -0 "$$" 2>/dev/null; do
    sudo -n true || exit 1
    sleep 60
  done
) &
sudo_keepalive_pid=$!

print_plan
echo "Output root: ${output_root}"

echo "=== Starting baseline application traffic ==="
"$client_script" \
  --duration "$client_duration_seconds" \
  --rate "$request_rate" \
  --concurrency "$concurrency" \
  --timeout "$request_timeout" \
  >"${output_root}/a-client-traffic.json" \
  2>"${output_root}/a-client-traffic.stderr" &
client_pid=$!
client_owned=true
wait_for_process "$client_ip" 'solis-client' "a-client workload" "$client_pid"

sleep "$baseline_seconds"
kill -0 "$client_pid" 2>/dev/null || fail "a-client workload stopped during baseline"

echo "=== Starting b-stress pressure ==="
"$fio_script" b-stress "$pressure_seconds" --durable \
  >"${output_root}/b-stress-fio.txt" 2>&1 &
fio_pid=$!
fio_owned=true
wait_for_process "$stress_ip" 'fio' "b-stress workload" "$fio_pid"

if ((capture_warmup_seconds > 0)); then
  sleep "$capture_warmup_seconds"
fi
kill -0 "$client_pid" 2>/dev/null || fail "a-client workload stopped before capture"
kill -0 "$fio_pid" 2>/dev/null || fail "b-stress workload stopped before capture"

capture_command=(sudo -n ./solis)
if [[ -n "$config_path" ]]; then
  capture_command+=(--config "$config_path")
fi
capture_command+=(
  capture noisy-neighbor
  --victim a-web
  --discover-suspects
  --duration "${window_seconds}s"
  --interval "${interval_seconds}s"
  --include-ebpf-latency
  --output-dir "$output_root"
)

echo "=== Capturing overlapping Solis evidence ==="
capture_status=0
"${capture_command[@]}" >"${output_root}/capture-command.txt" 2>&1 || capture_status=$?
((capture_status == 0)) || {
  sed -n '1,240p' "${output_root}/capture-command.txt" >&2
  fail "Solis capture failed with status ${capture_status}"
}

echo "=== Waiting for pressure and recovery completion ==="
fio_status=0
wait "$fio_pid" || fio_status=$?
fio_pid=""
((fio_status == 0)) || fail "b-stress workload failed; see ${output_root}/b-stress-fio.txt"
remove_guest_fio_file || fail "could not remove the fixed b-stress fio file"
fio_owned=false

client_status=0
wait "$client_pid" || client_status=$?
client_pid=""
((client_status == 0)) || fail "a-client workload failed; see ${output_root}/a-client-traffic.stderr"
client_owned=false

jq empty "${output_root}/a-client-traffic.json" || fail "a-client report is invalid JSON"
if ! jq -e '
  .summary.failed_requests == 0
  and .summary.client_saturated == 0
  and .summary.completed_requests == .summary.scheduled_requests
  and .summary.successful_requests == .summary.completed_requests
  and all(.privacy[]; . == false)
' "${output_root}/a-client-traffic.json" >/dev/null; then
  jq '{summary, privacy}' "${output_root}/a-client-traffic.json" >&2 || true
  fail "a-client traffic had failures, saturation, incomplete work, or a privacy violation"
fi

jq \
  --argjson baseline_end "$pressure_start_offset" \
  --argjson pressure_end "$recovery_start_offset" \
  --argjson recovery_end "$client_duration_seconds" \
  -f "$phase_filter" \
  "${output_root}/a-client-traffic.json" >"${output_root}/application-impact.json"

if ! jq -e '
  (.phases | length) == 3
  and all(.phases[];
    .scheduled_requests > 0
    and .completed_requests == .scheduled_requests
    and .successful_requests == .completed_requests
    and .failed_requests == 0
    and .client_saturated == 0
  )
' "${output_root}/application-impact.json" >/dev/null; then
  jq '{phases}' "${output_root}/application-impact.json" >&2 || true
  fail "baseline, pressure, or recovery phase was incomplete"
fi

capture_dir="$(sudo -n find "$output_root" -mindepth 1 -maxdepth 1 -type d -name 'capture-*' | sort | tail -n 1)"
[[ -n "$capture_dir" ]] || fail "capture directory was not found"

capture_mode="$(sudo -n stat -c '%a' "$capture_dir")"
[[ "$capture_mode" == "700" ]] || fail "capture directory mode is ${capture_mode}; want 700"
bad_capture_modes="$(sudo -n find "$capture_dir" -maxdepth 1 -type f -printf '%m %f\n' | awk '$1 != "600"')"
[[ -z "$bad_capture_modes" ]] || fail "capture contains non-0600 files: ${bad_capture_modes}"

for json_file in manifest.json evidence-summary.json ebpf-vm-block-latency.json observe-snapshot.json; do
  sudo -n jq empty "${capture_dir}/${json_file}" || fail "capture JSON is invalid: ${json_file}"
done

if ! sudo -n jq -r --arg directory "$capture_dir" \
  '.files[] | "\(.sha256)  \($directory)/\(.path)"' \
  "${capture_dir}/manifest.json" |
  sudo -n sha256sum -c - >"${output_root}/manifest-checks.txt"; then
  fail "capture manifest checksum validation failed"
fi

if ! sudo -n jq -e '
  .selected_suspect.name == "b-stress"
  and .ebpf_vm_attribution.available == true
  and (.ebpf_vm_attribution.quality == "available" or .ebpf_vm_attribution.quality == "degraded")
  and .ebpf_vm_attribution.suspect_total_ops > .ebpf_vm_attribution.victim_total_ops
  and all(.safety[]; . == false)
' "${capture_dir}/evidence-summary.json" >/dev/null; then
  sudo -n jq '{selected_suspect, ebpf_vm_attribution, safety}' \
    "${capture_dir}/evidence-summary.json" >&2 || true
  fail "capture did not provide usable dominant b-stress attribution evidence"
fi

sudo -n jq '{
  selected_suspect: .selected_suspect.name,
  verdict,
  ebpf_vm_attribution,
  safety
}' "${capture_dir}/evidence-summary.json" >"${output_root}/solis-evidence-summary.json"

sudo -n jq '{
  availability,
  collection_mode,
  attribution_method,
  attribution_quality,
  attribution_summary,
  unattributed_percent: .unattributed.unattributed_percent,
  host_p95_ms: .host_summary.latency_p95_ms,
  selected_vms: [
    .vms[]
    | select(.name == "a-client" or .name == "a-web" or .name == "a-db" or .name == "b-stress")
    | {name, total_ops, latency_p50_ms, latency_p95_ms, latency_p99_ms}
  ],
  privacy
}' "${capture_dir}/ebpf-vm-block-latency.json" >"${output_root}/ebpf-attribution-summary.json"

jq -n \
  --arg observed_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg capture_directory "$capture_dir" \
  --arg config_source "${config_path:-built-in defaults}" \
  --arg kernel_release "$(uname -r)" \
  --arg architecture "$(uname -m)" \
  --argjson baseline_seconds "$baseline_seconds" \
  --argjson pressure_seconds "$pressure_seconds" \
  --argjson recovery_seconds "$recovery_seconds" \
  --argjson capture_warmup_seconds "$capture_warmup_seconds" \
  --argjson window_seconds "$window_seconds" \
  --argjson interval_seconds "$interval_seconds" \
  --argjson request_rate "$request_rate" \
  --argjson concurrency "$concurrency" \
  --argjson request_timeout "$request_timeout" \
  --slurpfile build "${output_root}/solis-version.json" \
  --slurpfile client "${output_root}/a-client-traffic.json" \
  --slurpfile application "${output_root}/application-impact.json" \
  --slurpfile solis "${output_root}/solis-evidence-summary.json" \
  --slurpfile ebpf "${output_root}/ebpf-attribution-summary.json" '
  {
    schema_version: "1",
    observed_at_utc: $observed_at_utc,
    scenario: "a-client_to_a-web_to_a-db_with_b-stress_storage_pressure",
    capture_directory: $capture_directory,
    host: {kernel_release: $kernel_release, architecture: $architecture},
    build: $build[0],
    config_source: $config_source,
    timeline: {
      baseline_seconds: $baseline_seconds,
      pressure_seconds: $pressure_seconds,
      recovery_seconds: $recovery_seconds,
      capture_warmup_seconds: $capture_warmup_seconds,
      solis_window_seconds: $window_seconds,
      solis_interval_seconds: $interval_seconds
    },
    application_workload: {
      requested_rate_per_second: $request_rate,
      max_concurrency: $concurrency,
      request_timeout_seconds: $request_timeout,
      target: $client[0].target,
      phases: $application[0].phases,
      comparison: $application[0].comparison
    },
    solis_evidence: $solis[0],
    ebpf_attribution: $ebpf[0],
    interpretation: [
      "The pressure-window application measurements are time-aligned with the generated b-stress workload and overlapping Solis capture.",
      "Dominant VM-attributed storage operations and application latency change are correlation evidence from a controlled lab scenario, not a universal causality proof.",
      "Application request bodies and response bodies were not retained; the client report contains aggregate timing, status, and error counters only."
    ],
    privacy: {
      process_arguments_collected: false,
      environment_collected: false,
      guest_files_collected: false,
      query_text_collected: false,
      table_data_collected: false,
      request_body_collected: false,
      response_body_collected: false,
      secrets_collected: false
    },
    result: "PASS"
  }
' >"${output_root}/live-impact-report.json"

jq empty "${output_root}/live-impact-report.json" || fail "combined live-impact report is invalid JSON"
if ! jq -e '
  .result == "PASS"
  and .solis_evidence.selected_suspect == "b-stress"
  and .solis_evidence.ebpf_vm_attribution.available == true
  and (.solis_evidence.ebpf_vm_attribution.quality == "available"
       or .solis_evidence.ebpf_vm_attribution.quality == "degraded")
  and .solis_evidence.ebpf_vm_attribution.suspect_total_ops
      > .solis_evidence.ebpf_vm_attribution.victim_total_ops
  and all(.privacy[]; . == false)
' "${output_root}/live-impact-report.json" >/dev/null; then
  fail "combined live-impact report failed its final evidence or privacy assertion"
fi

privacy_status=0
sudo -n grep -ERiq 'request_pointer|0xffff|/proc/[0-9]+/(cmdline|environ)' "$output_root" || privacy_status=$?
case "$privacy_status" in
  0) fail "live-impact output failed the privacy scan" ;;
  1) ;;
  *) fail "live-impact privacy scan could not complete (status ${privacy_status})" ;;
esac
echo "Privacy scan: PASS" >"${output_root}/privacy-scan.txt"

bad_modes="$(sudo -n find "$output_root" -type f -printf '%m %p\n' | awk '$1 != "600"')"
[[ -z "$bad_modes" ]] || fail "live-impact output contains non-0600 files: ${bad_modes}"
bad_directory_modes="$(sudo -n find "$output_root" -type d -printf '%m %p\n' | awk '$1 != "700"')"
[[ -z "$bad_directory_modes" ]] || fail "live-impact output contains non-0700 directories: ${bad_directory_modes}"

if [[ -n "$sudo_keepalive_pid" ]] && kill -0 "$sudo_keepalive_pid" 2>/dev/null; then
  kill "$sudo_keepalive_pid" 2>/dev/null || true
  wait "$sudo_keepalive_pid" 2>/dev/null || true
fi
sudo_keepalive_pid=""
trap - EXIT INT TERM

echo "=== Live application-impact validation: PASS ==="
jq '{
  application: .application_workload,
  selected_suspect: .solis_evidence.selected_suspect,
  verdict: .solis_evidence.verdict,
  ebpf_vm_attribution: .solis_evidence.ebpf_vm_attribution,
  result
}' "${output_root}/live-impact-report.json"
echo "Validation report: ${output_root}/live-impact-report.json"
