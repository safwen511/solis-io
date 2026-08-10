#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 a-stress|b-stress seconds [--durable]" >&2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage
  exit 2
fi

readonly vm_name=$1
readonly seconds=$2
durable=false
if [[ $# -eq 3 ]]; then
  [[ "$3" == "--durable" ]] || {
    usage
    exit 2
  }
  durable=true
fi

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
fio_sync_options=()
if [[ "$durable" == true ]]; then
  fio_sync_options+=(--fdatasync=1024)
fi

echo "=== fio noise: ${vm_name} (${seconds} seconds, durable=${durable}) ==="
ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
  fio --name=solis-noise --ioengine=libaio \
  --filename=/home/flint/solis-noise.dat \
  --size=2G \
  --rw=randwrite \
  --bs=4k \
  --iodepth=32 \
  --numjobs=4 \
  --direct=1 \
  --time_based \
  "--runtime=${seconds}" \
  "${fio_sync_options[@]}" \
  --group_reporting
