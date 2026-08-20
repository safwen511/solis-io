#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script="${script_dir}/manage-active-lab.sh"
readonly template="${script_dir}/../guest-configs/stress/solis-moderate-pressure.service.template"

setup="$($script setup --dry-run)"
for expected in \
  "Application rate: 5 requests/second per tenant" \
  "Pressure ceiling: 1600 IOPS total, approximately 6.25 MiB/s" \
  "fixed 1073741824-byte file" \
  "pressure installed but inactive"
do
  grep -Fq "$expected" <<<"$setup"
done

pressure="$($script pressure --dry-run)"
grep -Fq "moderate pressure active" <<<"$pressure"
grep -Fq "Application rate: unchanged from the installed client service configuration" <<<"$pressure"
! grep -Fq "Application rate: 5 requests/second" <<<"$pressure"

normal="$($script normal --dry-run)"
grep -Fq "pressure inactive" <<<"$normal"

grep -Fq 'readonly pressure_directory="/var/lib/solis-moderate-pressure"' "$script"
grep -Fq 'pressure_service_template=' "$script"
grep -Fq 'ReadWritePaths=@PRESSURE_DIRECTORY@' "$template"
if grep -Fq 'ReadWritePaths=@PRESSURE_FILE@' "$template"; then
  echo "pressure service bind-mounts the exact fio file" >&2
  exit 1
fi
grep -Fq 'remove_legacy_pressure_file' "$script"

for invalid in \
  "setup --pressure-iops 99 --dry-run" \
  "setup --pressure-iops 1601 --dry-run" \
  "setup --client-rate 21 --dry-run" \
  "pressure --client-rate 5 --dry-run"
do
  read -r -a arguments <<<"$invalid"
  if "$script" "${arguments[@]}" >/dev/null 2>&1; then
    echo "invalid active-lab arguments were accepted: ${invalid}" >&2
    exit 1
  fi
done

echo "Solis active-lab plan tests: PASS"
