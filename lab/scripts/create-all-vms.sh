#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly config_file="${script_dir}/../config/vms.csv"
readonly create_vm_script="${script_dir}/create-vm.sh"

force_args=()
if [[ "${1:-}" == "--force" ]]; then
  force_args=(--force)
  shift
fi

if [[ $# -ne 0 ]]; then
  echo "Usage: $0 [--force]" >&2
  exit 2
fi

if [[ ! -r "$config_file" ]]; then
  echo "VM configuration not found: $config_file" >&2
  exit 1
fi

total=$(awk 'NR > 1 && NF {count++} END {print count + 0}' "$config_file")
current=0

while IFS=, read -r name tenant network ip memory_mb vcpus disk_gb role; do
  role=${role%$'\r'}
  [[ -z "$name" ]] && continue
  ((current += 1))
  echo "[$current/$total] Creating $name ($tenant, $role)..."
  "$create_vm_script" "${force_args[@]}" \
    "$name" "$tenant" "$network" "$ip" \
    "$memory_mb" "$vcpus" "$disk_gb" "$role"
done < <(tail -n +2 "$config_file")

echo "Processed $current VM definitions."
