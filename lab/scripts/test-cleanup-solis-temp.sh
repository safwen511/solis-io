#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly cleanup_script="${script_dir}/cleanup-solis-temp.sh"
readonly suffix="${BASHPID}"
readonly test_root="/tmp/solis-cleanup-test-root-${suffix}"
readonly cache_path="${test_root}/solis-cleanup-${suffix}-go-cache"
readonly evidence_path="${test_root}/solis-live-impact-cleanup-${suffix}"
readonly blocked_path="${test_root}/solis-bundle-validation-cleanup-${suffix}"
readonly unrelated_path="${test_root}/unrelated-cleanup-${suffix}"

cleanup() {
  if [[ -d "$test_root" && ! -L "$test_root" ]]; then
    find -P "$test_root" -xdev -depth -delete
  fi
}
trap cleanup EXIT

mkdir -m 0700 -- "$test_root"
mkdir -m 0700 -- "$cache_path" "$evidence_path" "$unrelated_path"
printf 'cache\n' >"${cache_path}/data"
printf 'evidence\n' >"${evidence_path}/data"
printf 'unrelated\n' >"${unrelated_path}/data"

dry_run="$(SOLIS_CLEANUP_TEST_ROOT="$test_root" "$cleanup_script" --kind cache)"
grep -Fq "WOULD_DELETE" <<<"$dry_run"
grep -Fq "$cache_path" <<<"$dry_run"
! grep -Fq "$evidence_path" <<<"$dry_run"
! grep -Fq "$unrelated_path" <<<"$dry_run"
[[ -d "$cache_path" ]]

SOLIS_CLEANUP_TEST_ROOT="$test_root" "$cleanup_script" --kind cache --apply >/dev/null
[[ ! -e "$cache_path" ]]
[[ -d "$evidence_path" ]]
[[ -d "$unrelated_path" ]]

if [[ "$(id -u)" != "0" ]]; then
  mkdir -m 0700 -- "$blocked_path"
  printf 'blocked\n' >"${blocked_path}/data"
  chmod 0500 "$blocked_path"
  if SOLIS_CLEANUP_TEST_ROOT="$test_root" "$cleanup_script" --kind evidence --apply >/dev/null 2>&1; then
    echo "cleanup unexpectedly accepted a non-writable evidence directory" >&2
    exit 1
  fi
  [[ -d "$evidence_path" ]]
  [[ -d "$blocked_path" ]]
  chmod 0700 "$blocked_path"
fi

SOLIS_CLEANUP_TEST_ROOT="$test_root" "$cleanup_script" --kind evidence --apply >/dev/null
[[ ! -e "$evidence_path" ]]
[[ ! -e "$blocked_path" ]]
[[ -d "$unrelated_path" ]]

echo "Solis temporary-artifact cleanup tests: PASS"
