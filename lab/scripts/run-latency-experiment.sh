#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 tenant-a|tenant-b a-stress|b-stress" >&2
}

if [[ $# -ne 2 ]]; then
  usage
  exit 2
fi

readonly tenant_name=$1
readonly stress_vm=$2

case "$tenant_name" in
  tenant-a|tenant-b) ;;
  *)
    usage
    exit 2
    ;;
esac

case "$stress_vm" in
  a-stress|b-stress) ;;
  *)
    usage
    exit 2
    ;;
esac

readonly requests="${SOLIS_HTTP_REQUESTS:-1000}"
readonly concurrency="${SOLIS_HTTP_CONCURRENCY:-20}"
readonly noise_seconds="${SOLIS_FIO_SECONDS:-60}"

if [[ ! "$requests" =~ ^[1-9][0-9]*$ ]] ||
   [[ ! "$concurrency" =~ ^[1-9][0-9]*$ ]] ||
   [[ ! "$noise_seconds" =~ ^[1-9][0-9]*$ ]] ||
   (( concurrency > requests )); then
  echo "Experiment request, concurrency, and duration settings must be valid positive integers." >&2
  exit 2
fi

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly project_dir="$(cd -- "${script_dir}/../.." && pwd)"
readonly timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
readonly report_dir="${project_dir}/lab/reports/workload/${timestamp}"
readonly http_load_script="${script_dir}/run-http-load.sh"
readonly fio_noise_script="${script_dir}/run-fio-noise.sh"

mkdir -p "$report_dir"

echo "=== Baseline HTTP load ==="
"$http_load_script" "$tenant_name" "$requests" "$concurrency" |
  tee "${report_dir}/baseline.txt"

echo
echo "=== Starting noisy-neighbor fio workload ==="
"$fio_noise_script" "$stress_vm" "$noise_seconds" \
  > "${report_dir}/fio-noise.txt" 2>&1 &
noise_pid=$!

wait_for_noise() {
  if kill -0 "$noise_pid" 2>/dev/null; then
    wait "$noise_pid" || true
  fi
}
trap wait_for_noise EXIT

sleep 2

echo "=== HTTP load during fio noise ==="
"$http_load_script" "$tenant_name" "$requests" "$concurrency" |
  tee "${report_dir}/during-noise.txt"

echo
echo "=== Waiting for fio noise to finish ==="
wait "$noise_pid"
trap - EXIT

echo
echo "=== Post-noise HTTP load ==="
"$http_load_script" "$tenant_name" "$requests" "$concurrency" |
  tee "${report_dir}/post-noise.txt"

echo
echo "Report directory: $report_dir"
