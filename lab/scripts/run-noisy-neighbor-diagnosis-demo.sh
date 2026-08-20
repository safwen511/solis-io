#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd -- "${script_dir}/../.." && pwd)"
readonly fio_script="lab/scripts/run-fio-noise.sh"
readonly workload_report="lab/reports/workload/20260808T174825Z"
readonly diagnosis_dir="lab/reports/diagnosis"
readonly fio_log="/tmp/solis-fio-diagnose-demo.txt"

fio_pid=""
latest_report=""

# cleanup_fio performs the bounded cleanup fio step for this lab workflow.
cleanup_fio() {
  if [[ -z "$fio_pid" ]]; then
    return
  fi

  if kill -0 "$fio_pid" 2>/dev/null; then
    echo "Stopping background fio workload..." >&2
    kill "$fio_pid" 2>/dev/null || true
  fi
  wait "$fio_pid" 2>/dev/null || true
  fio_pid=""
}

# handle_signal records interruption, invokes bounded cleanup, and preserves a failing exit status.
handle_signal() {
  local exit_code=$1
  echo "Demo interrupted." >&2
  exit "$exit_code"
}

# require_file fails unless the required regular input file already exists.
require_file() {
  local path=$1
  if [[ ! -f "$path" ]]; then
    echo "Required file not found: $path" >&2
    exit 1
  fi
}

trap cleanup_fio EXIT
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

cd "$repo_root"

echo "=== Building Solis I/O ==="
go build -o solis ./cmd/solis

require_file "./solis"
require_file "$fio_script"
if [[ ! -d "$workload_report" ]]; then
  echo "Required report directory not found: $workload_report" >&2
  exit 1
fi

if [[ ! -x "./solis" ]]; then
  echo "Built Solis binary is not executable: ./solis" >&2
  exit 1
fi
if [[ ! -x "$fio_script" ]]; then
  echo "fio workload script is not executable: $fio_script" >&2
  exit 1
fi

echo
echo "=== Starting b-stress fio noise for 20 seconds ==="
./lab/scripts/run-fio-noise.sh b-stress 20 </dev/null > /tmp/solis-fio-diagnose-demo.txt 2>&1 &
fio_pid=$!

echo "fio PID: $fio_pid"
echo "fio log: $fio_log"
sleep 3

echo
echo "=== Running noisy-neighbor diagnosis while fio is active ==="
diagnosis_output="$(
  sudo ./solis diagnose noisy-neighbor \
    --report-dir lab/reports/workload/20260808T174825Z \
    --victim tenant-a \
    --suspect b-stress \
    --duration 10s \
    --interval 2s \
    --output-dir lab/reports/diagnosis
)"
printf '%s\n' "$diagnosis_output"

while IFS= read -r line; do
  if [[ "$line" == diagnosis\ written\ to\ * ]]; then
    latest_report="${line#"diagnosis written to "}"
  fi
done <<< "$diagnosis_output"

echo
echo "=== Waiting for fio noise to finish ==="
fio_status=0
wait "$fio_pid" || fio_status=$?
fio_pid=""

echo
echo "=== fio summary ==="
if ! grep -E "write: IOPS|WRITE:|util=" /tmp/solis-fio-diagnose-demo.txt; then
  echo "No fio summary lines were found in $fio_log" >&2
fi

if (( fio_status != 0 )); then
  echo "fio workload failed with exit status $fio_status; see $fio_log" >&2
  exit "$fio_status"
fi

if [[ -z "$latest_report" || ! -f "$latest_report" ]]; then
  echo "Could not determine the generated diagnosis report path." >&2
  exit 1
fi

echo
echo "Latest diagnosis report: $latest_report"
