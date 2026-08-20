#!/usr/bin/env bash
set -euo pipefail

# usage prints the accepted command syntax without changing host or guest state.
usage() {
  cat <<'EOF'
Usage: cleanup-solis-temp.sh [--kind cache|evidence|all] [--older-than-days N] [--apply]

Lists only allowlisted, current-user-owned Solis artifacts directly under
/tmp. The default is a dry-run of Solis Go build caches. Nothing is removed
unless --apply is present. Symlinks are always skipped.
EOF
}

kind="cache"
older_than_days=0
apply=false

while (($# > 0)); do
  case "$1" in
    --kind)
      (($# >= 2)) || { usage >&2; exit 2; }
      kind=$2
      shift 2
      ;;
    --older-than-days)
      (($# >= 2)) || { usage >&2; exit 2; }
      older_than_days=$2
      shift 2
      ;;
    --apply)
      apply=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

case "$kind" in
  cache|evidence|all) ;;
  *) echo "--kind must be cache, evidence, or all" >&2; exit 2 ;;
esac
if [[ ! "$older_than_days" =~ ^[0-9]+$ ]]; then
  echo "--older-than-days must be a non-negative integer" >&2
  exit 2
fi

readonly current_uid="$(id -u)"
cleanup_root="/tmp"
test_mode=false
# The test suite uses a uniquely named private directory so an apply test can
# never share the real /tmp candidate namespace. This is deliberately not a
# command-line option.
if [[ -n "${SOLIS_CLEANUP_TEST_ROOT:-}" ]]; then
  case "$SOLIS_CLEANUP_TEST_ROOT" in
    /tmp/solis-cleanup-test-root-*) cleanup_root=$SOLIS_CLEANUP_TEST_ROOT; test_mode=true ;;
    *) echo "Refusing unsafe cleanup test root" >&2; exit 1 ;;
  esac
  [[ -d "$cleanup_root" && ! -L "$cleanup_root" ]] || {
    echo "Cleanup test root must be an existing non-symlink directory" >&2
    exit 1
  }
  [[ "$(stat -c '%u' -- "$cleanup_root")" == "$current_uid" ]] || {
    echo "Cleanup test root must be owned by the current user" >&2
    exit 1
  }
fi
readonly cleanup_root
readonly test_mode
if [[ "$current_uid" == "0" && "$test_mode" == false ]]; then
  echo "Refusing to clean temporary artifacts as root; run this helper as the user that created them." >&2
  exit 1
fi
readonly now_epoch="$(date +%s)"
readonly minimum_age_seconds=$((older_than_days * 86400))

# artifact_kind classifies an artifact only after it matches an allowlisted Solis path pattern.
artifact_kind() {
  local name=$1
  case "$name" in
    solis-go-cache|solis-*-go-cache)
      printf '%s\n' cache
      ;;
    solis-attribution-validation-*|solis-ebpf-overhead-*|solis-overhead-*|\
    solis-live-impact-*|solis-live-app-*|solis-live-final-*|\
    solis-bundle-validation-*|solis-observe-integration-*|\
    solis-map-layout-check-*|solis-benchmark-filter-*|\
    solis-v0*-release-*|solis-release-*|solis-output-test|\
    solis-*-fio.txt|solis-v*-ebpf-doctor.txt|\
    solis-benchmark-plan-*.txt|a-client-smoke-*.json)
      printf '%s\n' evidence
      ;;
    *)
      return 1
      ;;
  esac
}

# matches_kind reports whether an artifact belongs to the requested allowlisted cleanup class.
matches_kind() {
  local artifact=$1
  [[ "$kind" == all || "$kind" == "$artifact" ]]
}

# eligible_age reports whether an artifact is older than the requested retention boundary.
eligible_age() {
  local path=$1
  local modified
  modified="$(stat -c '%Y' -- "$path")"
  ((now_epoch - modified >= minimum_age_seconds))
}

# safe_delete deletes only an artifact that passed the script's path, kind, and age checks.
safe_delete() {
  local path=$1
  [[ "$(dirname -- "$path")" == "$cleanup_root" ]] || {
    echo "Refusing path outside ${cleanup_root}: ${path}" >&2
    return 1
  }
  [[ ! -L "$path" ]] || {
    echo "Refusing symbolic link: ${path}" >&2
    return 1
  }
  if [[ -d "$path" ]]; then
    find -P "$path" -xdev -depth -delete
  else
    rm -f -- "$path"
  fi
}

# preflight_delete validates every deletion candidate before any artifact is removed.
preflight_delete() {
  local path=$1
  [[ ! -L "$path" ]] || return 1
  if [[ ! -d "$path" ]]; then
    [[ -w "$(dirname -- "$path")" ]]
    return
  fi
  local blocked=""
  blocked="$(find -P "$path" -xdev -type d \( ! -readable -o ! -writable -o ! -executable \) -print -quit)" || return 1
  [[ -z "$blocked" ]] || {
    echo "Refusing unreadable or non-writable directory: ${blocked}" >&2
    return 1
  }
}

declare -a candidates=()
while IFS= read -r -d '' path; do
  name="$(basename -- "$path")"
  artifact="$(artifact_kind "$name" 2>/dev/null || true)"
  [[ -n "$artifact" ]] || continue
  matches_kind "$artifact" || continue
  [[ ! -L "$path" ]] || {
    printf 'SKIP symlink\t%s\n' "$path" >&2
    continue
  }
  owner_uid="$(stat -c '%u' -- "$path")"
  [[ "$owner_uid" == "$current_uid" ]] || {
    printf 'SKIP not-owned\t%s\n' "$path" >&2
    continue
  }
  eligible_age "$path" || continue
  candidates+=("$path")
done < <(find -P "$cleanup_root" -xdev -mindepth 1 -maxdepth 1 -print0)

total_bytes=0
for path in "${candidates[@]}"; do
  bytes="$(du -sb -- "$path" 2>/dev/null | awk '{print $1}')"
  bytes="${bytes:-0}"
  total_bytes=$((total_bytes + bytes))
  printf '%s\t%s bytes\t%s\n' "$([[ "$apply" == true ]] && printf DELETE || printf WOULD_DELETE)" "$bytes" "$path"
done

printf 'Matched artifacts: %d\n' "${#candidates[@]}"
printf 'Matched bytes: %d\n' "$total_bytes"

if [[ "$apply" != true ]]; then
  echo "Dry run only. Re-run with --apply to remove exactly this allowlisted class."
  exit 0
fi

# Validate the whole batch before the first mutation. This prevents an
# unreadable nested directory in one artifact from causing a partial cleanup
# of earlier candidates.
for path in "${candidates[@]}"; do
  preflight_delete "$path" || {
    echo "Cleanup preflight failed; nothing was removed." >&2
    exit 1
  }
done
for path in "${candidates[@]}"; do
  safe_delete "$path"
done
echo "Cleanup complete."
