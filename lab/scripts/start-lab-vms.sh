#!/usr/bin/env bash
set -euo pipefail

# usage prints the accepted startup syntax without changing libvirt or guest state.
usage() {
  cat <<'EOF'
Usage: start-lab-vms.sh [--wait-seconds N] [--dry-run]

Starts the two fixed tenant networks and every VM declared in lab/config/vms.csv,
then waits for BatchMode SSH as SOLIS_SSH_USER (default: flint). The VMs must
already be defined; use create-all-vms.sh for first-time creation.
EOF
}

# fail reports one bounded startup error and exits unsuccessfully.
fail() {
  echo "Error: $*" >&2
  exit 1
}

wait_seconds=180
dry_run=false
wait_set=false
while (($# > 0)); do
  case "$1" in
    --wait-seconds)
      [[ "$wait_set" == false && $# -ge 2 ]] || { usage >&2; exit 2; }
      wait_seconds=$2
      wait_set=true
      shift 2
      ;;
    --dry-run)
      dry_run=true
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

[[ "$wait_seconds" =~ ^[1-9][0-9]*$ ]] && ((wait_seconds <= 900)) ||
  fail "--wait-seconds must be an integer from 1 through 900"

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly config_file="${script_dir}/../config/vms.csv"
readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-n -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=accept-new)
readonly networks=(tenant-a-net tenant-b-net)

[[ -r "$config_file" ]] || fail "VM inventory is unavailable: ${config_file}"
[[ "$ssh_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "SOLIS_SSH_USER is not a safe user name"

echo "Solis lab startup plan"
echo "Inventory: ${config_file}"
echo "SSH user: ${ssh_user}"
echo "SSH wait ceiling: ${wait_seconds}s per VM"
echo "Networks: ${networks[*]}"
awk -F, 'NR > 1 && NF { printf "- %s (%s, %s)\n", $1, $4, $8 }' "$config_file"
[[ "$dry_run" == false ]] || exit 0

# start_network makes one already-defined lab network active without redefining it.
start_network() {
  local network=$1
  virsh net-info "$network" >/dev/null 2>&1 ||
    fail "network ${network} is not defined; follow the README reconstruction steps"
  if [[ "$(virsh net-info "$network" | awk -F: '/^Active:/ {gsub(/^[[:space:]]+/, "", $2); print $2}')" != "yes" ]]; then
    virsh net-start "$network" >/dev/null
  fi
}

# start_vm starts one already-defined VM unless it is already running.
start_vm() {
  local name=$1
  virsh dominfo "$name" >/dev/null 2>&1 ||
    fail "VM ${name} is not defined; run ./lab/scripts/create-all-vms.sh first"
  if [[ "$(virsh domstate "$name" | tr -d '\r')" != "running" ]]; then
    virsh start "$name" >/dev/null
  fi
}

# wait_for_ssh waits only for fixed inventory addresses and never executes a guest payload.
wait_for_ssh() {
  local name=$1 ip=$2
  local deadline=$((SECONDS + wait_seconds))
  until ssh "${ssh_options[@]}" "${ssh_user}@${ip}" true >/dev/null 2>&1; do
    ((SECONDS < deadline)) || fail "SSH did not become ready for ${name} (${ip})"
    sleep 2
  done
  echo "SSH ready: ${name} (${ip})"
}

for network in "${networks[@]}"; do
  start_network "$network"
done

while IFS=, read -r name _ _ ip _; do
  [[ -n "$name" ]] || continue
  start_vm "$name"
  wait_for_ssh "$name" "$ip"
done < <(tail -n +2 "$config_file")

echo "All declared Solis lab VMs are running and reachable over SSH."
