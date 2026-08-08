#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 a-stress|b-stress seconds" >&2
}

if [[ $# -ne 2 ]]; then
  usage
  exit 2
fi

readonly vm_name=$1
readonly seconds=$2

case "$vm_name" in
  a-stress)
    readonly stress_ip="192.168.130.40"
    ;;
  b-stress)
    readonly stress_ip="192.168.140.40"
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ ! "$seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "Seconds must be a positive integer." >&2
  exit 2
fi

readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)

echo "=== fio noise: ${vm_name} (${seconds} seconds) ==="
ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
  fio --name=solis-noise \
  --filename=/home/flint/solis-noise.dat \
  --size=2G \
  --rw=randwrite \
  --bs=4k \
  --iodepth=32 \
  --numjobs=4 \
  --direct=1 \
  --time_based \
  "--runtime=${seconds}" \
  --group_reporting
