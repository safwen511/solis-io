#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 tenant-a|tenant-b requests concurrency" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 2
fi

readonly tenant_name=$1
readonly requests=$2
readonly concurrency=$3

case "$tenant_name" in
  tenant-a)
    readonly client_ip="192.168.130.10"
    readonly web_ip="192.168.130.20"
    ;;
  tenant-b)
    readonly client_ip="192.168.140.10"
    readonly web_ip="192.168.140.20"
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ ! "$requests" =~ ^[1-9][0-9]*$ ]] ||
   [[ ! "$concurrency" =~ ^[1-9][0-9]*$ ]] ||
   (( concurrency > requests )); then
  echo "Requests and concurrency must be positive integers, with concurrency no greater than requests." >&2
  exit 2
fi

readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)

echo "=== HTTP load: ${tenant_name} (${requests} requests, concurrency ${concurrency}) ==="
ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" \
  "LC_ALL=C ab -n '${requests}' -c '${concurrency}' 'http://${web_ip}/write'" |
  grep -E '^(Requests per second|Time per request|Transfer rate|Failed requests):'
