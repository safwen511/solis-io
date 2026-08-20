#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script="${script_dir}/manage-steady-traffic.sh"
readonly template="${script_dir}/../guest-configs/client/solis-steady-traffic.service.template"

plan="$($script deploy --tenant all --rate 2 --dry-run)"
for expected in \
  "a-client (192.168.130.10) -> a-web (192.168.130.20) -> a-db (192.168.130.30)" \
  "b-client (192.168.140.10) -> b-web (192.168.140.20) -> b-db (192.168.140.30)" \
  "Retention: keep 2 hours; timer every 15 minutes" \
  "No payloads are retained"
do
  grep -Fq "$expected" <<<"$plan"
done

grep -Fq 'steady_service_template=' "$script"
grep -Fq 'Environment=SOLIS_RATE_RPS=@REQUEST_RATE@' "$template"

if "$script" deploy --rate 200 --dry-run >/dev/null 2>&1; then
  echo "unsafe request rate was accepted" >&2
  exit 1
fi
if "$script" start --rate 2 --dry-run >/dev/null 2>&1; then
  echo "start unexpectedly accepted a deployment-only rate" >&2
  exit 1
fi

status="$($script status --dry-run)"
grep -Fq "Rate: unchanged from the installed service configuration" <<<"$status"
! grep -Fq "Rate: 2 requests/second" <<<"$status"

echo "Solis steady-traffic plan tests: PASS"
