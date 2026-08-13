#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 a-stress|b-stress seconds [--durable] [--json] [--rate-iops N]" >&2
}

if [[ $# -lt 2 ]]; then
  usage
  exit 2
fi

readonly vm_name=$1
readonly seconds=$2
shift 2

durable=false
json_output=false
rate_iops=""
durable_set=false
json_set=false
rate_set=false

while (($# > 0)); do
  case "$1" in
    --durable)
      [[ "$durable_set" == false ]] || {
        echo "--durable specified more than once." >&2
        exit 2
      }
      durable=true
      durable_set=true
      shift
      ;;
    --json)
      [[ "$json_set" == false ]] || {
        echo "--json specified more than once." >&2
        exit 2
      }
      json_output=true
      json_set=true
      shift
      ;;
    --rate-iops)
      [[ "$rate_set" == false ]] || {
        echo "--rate-iops specified more than once." >&2
        exit 2
      }
      (($# >= 2)) || {
        echo "--rate-iops requires a value." >&2
        exit 2
      }
      rate_iops=$2
      rate_set=true
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

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
if [[ -n "$rate_iops" && ! "$rate_iops" =~ ^[1-9][0-9]*$ ]]; then
  echo "Rate IOPS must be a positive integer." >&2
  exit 2
fi

readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)
fio_sync_options=()
if [[ "$durable" == true ]]; then
  fio_sync_options+=(--fdatasync=1024)
fi
fio_rate_options=()
if [[ -n "$rate_iops" ]]; then
  fio_rate_options+=("--rate_iops=${rate_iops}")
fi
fio_output_options=()
if [[ "$json_output" == true ]]; then
  fio_output_options+=(--output-format=json)
fi

if [[ "$json_output" == true ]]; then
  echo "=== fio noise: ${vm_name} (${seconds} seconds, durable=${durable}, rate_iops_per_job=${rate_iops:-unlimited}) ===" >&2
else
  echo "=== fio noise: ${vm_name} (${seconds} seconds, durable=${durable}, rate_iops_per_job=${rate_iops:-unlimited}) ==="
fi
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
  "${fio_rate_options[@]}" \
  "${fio_output_options[@]}" \
  --group_reporting
