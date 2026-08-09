#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd -- "${script_dir}/../.." && pwd)"

readonly VICTIM="${VICTIM:-a-web}"
readonly STRESS_VM_IP="${STRESS_VM_IP:-192.168.140.40}"
readonly REPORT_DIR="${REPORT_DIR:-lab/reports/workload/20260808T174825Z}"
readonly OUTPUT_DIR="${OUTPUT_DIR:-lab/reports/captures}"
readonly DURATION="${DURATION:-10s}"
readonly INTERVAL="${INTERVAL:-2s}"
readonly FIO_RUNTIME="${FIO_RUNTIME:-60}"
readonly FIO_SIZE="${FIO_SIZE:-256M}"
readonly FIO_FILE="/home/flint/solis-mvp-demo.dat"
readonly fio_log="/tmp/solis-mvp-demo-fio.txt"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)

fio_ssh_pid=""
remote_workload_started=false
guest_cleanup_done=false

fail() {
  echo "Error: $*" >&2
  exit 1
}

print_fio_log() {
  if [[ -f "$fio_log" ]]; then
    echo "=== fio output ===" >&2
    sed -n '1,240p' "$fio_log" >&2
  fi
}

stop_remote_fio() {
  if [[ "$remote_workload_started" != true ]]; then
    return
  fi

  ssh "${ssh_options[@]}" "$STRESS_VM_IP" \
    "pkill -TERM -f '[s]olis-mvp-demo' 2>/dev/null || true" \
    >/dev/null 2>&1 || true
}

cleanup_guest_file() {
  if [[ "$remote_workload_started" != true || "$guest_cleanup_done" == true ]]; then
    return
  fi

  echo "=== Cleaning up guest fio file ==="
  if ! ssh "${ssh_options[@]}" "$STRESS_VM_IP" \
    'rm -f /home/flint/solis-mvp-demo.dat && { sudo fstrim -av || true; }'; then
    echo "Warning: could not confirm guest fio file cleanup." >&2
    return 1
  fi
  guest_cleanup_done=true
}

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM

  if [[ -n "$fio_ssh_pid" ]] && kill -0 "$fio_ssh_pid" 2>/dev/null; then
    echo "Stopping the background lab fio workload..." >&2
    stop_remote_fio
    wait "$fio_ssh_pid" 2>/dev/null || true
  fi
  fio_ssh_pid=""
  cleanup_guest_file || true
  exit "$exit_code"
}

handle_signal() {
  local signal_name=$1
  echo "MVP demo interrupted by ${signal_name}." >&2
  case "$signal_name" in
    INT) exit 130 ;;
    TERM) exit 143 ;;
  esac
}

newest_capture_directory() {
  local directory
  local latest=""
  local latest_mtime=-1
  local mtime

  shopt -s nullglob
  for directory in "$OUTPUT_DIR"/capture-*; do
    [[ -d "$directory" ]] || continue
    mtime="$(stat -c %Y "$directory")"
    if (( mtime > latest_mtime )) ||
       { (( mtime == latest_mtime )) && [[ "$directory" > "$latest" ]]; }; then
      latest="$directory"
      latest_mtime=$mtime
    fi
  done
  shopt -u nullglob

  [[ -n "$latest" ]] || return 1
  printf '%s\n' "$latest"
}

trap cleanup EXIT
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM

cd "$repo_root"

[[ -n "$VICTIM" ]] || fail "VICTIM must not be empty."
[[ "$STRESS_VM_IP" =~ ^[A-Za-z0-9._:-]+$ ]] || fail "STRESS_VM_IP contains unsupported characters."
[[ -n "$REPORT_DIR" ]] || fail "REPORT_DIR must not be empty."
[[ -n "$OUTPUT_DIR" ]] || fail "OUTPUT_DIR must not be empty."
[[ -n "$DURATION" ]] || fail "DURATION must not be empty."
[[ -n "$INTERVAL" ]] || fail "INTERVAL must not be empty."
[[ "$FIO_RUNTIME" =~ ^[1-9][0-9]*$ ]] || fail "FIO_RUNTIME must be a positive integer."
[[ "$FIO_SIZE" =~ ^[1-9][0-9]*[KMGTP]?$ ]] || fail "FIO_SIZE must be a positive fio size such as 256M."

command -v ssh >/dev/null 2>&1 || fail "ssh is required."
command -v sudo >/dev/null 2>&1 || fail "sudo is required for QEMU procfs and eBPF access."
[[ -d "$REPORT_DIR" ]] || fail "Report directory not found: $REPORT_DIR"

if [[ ! -x ./solis ]]; then
  command -v go >/dev/null 2>&1 || fail "./solis is missing and go is not available to build it."
  echo "=== Building Solis I/O ==="
  go build -o solis ./cmd/solis
fi
[[ -x ./solis ]] || fail "Solis binary is not executable: ./solis"

echo "=== Checking local sudo access ==="
sudo -v

echo "=== Checking SSH access to stress VM ${STRESS_VM_IP} ==="
ssh "${ssh_options[@]}" "$STRESS_VM_IP" true

echo "=== Checking fio inside stress VM ==="
ssh "${ssh_options[@]}" "$STRESS_VM_IP" \
  'command -v fio >/dev/null 2>&1' || fail "fio is not installed in stress VM ${STRESS_VM_IP}."

mkdir -p "$OUTPUT_DIR"

echo "=== Starting fio write pressure in stress VM ==="
echo "fio log: $fio_log"
ssh "${ssh_options[@]}" "$STRESS_VM_IP" \
  fio --name=solis-mvp-demo \
  --ioengine=libaio \
  "--filename=${FIO_FILE}" \
  "--size=${FIO_SIZE}" \
  --rw=randwrite \
  --bs=4k \
  --iodepth=32 \
  --numjobs=4 \
  --direct=1 \
  --time_based \
  "--runtime=${FIO_RUNTIME}" \
  --group_reporting \
  >"$fio_log" 2>&1 &
fio_ssh_pid=$!
remote_workload_started=true

sleep 3

echo "=== Confirming fio is running ==="
if ! kill -0 "$fio_ssh_pid" 2>/dev/null ||
   ! ssh "${ssh_options[@]}" "$STRESS_VM_IP" \
     "pgrep -f '[s]olis-mvp-demo' >/dev/null"; then
  print_fio_log
  fail "fio is not running in stress VM ${STRESS_VM_IP}."
fi

echo "=== Capturing noisy-neighbor evidence ==="
sudo ./solis capture noisy-neighbor \
  --report-dir "$REPORT_DIR" \
  --victim "$VICTIM" \
  --discover-suspects \
  --duration "$DURATION" \
  --interval "$INTERVAL" \
  --include-ebpf-latency \
  --output-dir "$OUTPUT_DIR"

echo "=== Waiting for fio to finish ==="
fio_status=0
wait "$fio_ssh_pid" || fio_status=$?
fio_ssh_pid=""

cleanup_guest_file || fail "Could not remove ${FIO_FILE} from stress VM ${STRESS_VM_IP}."

echo "=== fio summary ==="
grep -E "write: IOPS|WRITE:|util=" "$fio_log" || true

if (( fio_status != 0 )); then
  print_fio_log
  fail "fio workload failed with exit status ${fio_status}."
fi

capture_directory="$(newest_capture_directory)" || fail "No capture directory was found under ${OUTPUT_DIR}."
incident_report="${capture_directory}/incident-report.md"
[[ -f "$incident_report" ]] || fail "Incident report not found: $incident_report"

echo
echo "Capture directory: $capture_directory"
echo "Incident report: $incident_report"

echo "=== Incident report preview ==="
grep -E "Victim VM:|Selected suspect:|Verdict:|Recommended operator action" "$incident_report" || true
