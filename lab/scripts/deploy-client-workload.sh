#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0" >&2
}

if (($# != 0)); then
  usage
  exit 2
fi

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly project_dir="$(cd -- "${script_dir}/../.." && pwd)"
readonly client_file="${project_dir}/lab/workloads/client/solis_client.py"
readonly client_ip="192.168.130.10"
readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)

if [[ ! -r "$client_file" ]]; then
  echo "Client workload is missing: ${client_file}" >&2
  exit 1
fi

echo "=== Deploying bounded tenant-A traffic generator to a-client (${client_ip}) ==="
ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" \
  'command -v python3 >/dev/null 2>&1' || {
  echo "python3 is unavailable on a-client; refusing deployment" >&2
  exit 1
}
scp "${ssh_options[@]}" "$client_file" "${ssh_user}@${client_ip}:/tmp/solis_client.py"
ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" \
  "sudo -n install -d -m 0755 /opt/solis-workload && sudo -n install -m 0755 /tmp/solis_client.py /opt/solis-workload/solis_client.py && rm -f -- /tmp/solis_client.py"
ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" \
  '/usr/bin/python3 /opt/solis-workload/solis_client.py --help >/dev/null'

echo "Deployment complete. The workload is manual and bounded; no service was enabled."
echo "Run: ./lab/scripts/run-client-workload.sh --duration 60 --rate 30 --concurrency 20"
