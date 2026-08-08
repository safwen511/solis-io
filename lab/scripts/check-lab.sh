#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly config_file="${script_dir}/../config/vms.csv"
readonly networks=(tenant-a-net tenant-b-net)

echo '=== Libvirt domains ==='
virsh list --all

for network in "${networks[@]}"; do
  echo
  echo "=== DHCP leases: $network ==="
  virsh net-dhcp-leases "$network"
done

echo
echo '=== VM interface addresses ==='
while IFS=, read -r name _; do
  [[ -z "$name" ]] && continue
  echo
  echo "--- $name ---"
  if virsh dominfo "$name" >/dev/null 2>&1; then
    virsh domifaddr "$name" --source lease || true
  else
    echo 'VM is not defined.'
  fi
done < <(tail -n +2 "$config_file")
