#!/usr/bin/env bash
set -euo pipefail

# usage prints the accepted command syntax without changing host or guest state.
usage() {
  cat >&2 <<'EOF'
Usage: run-client-workload.sh [options]

Options:
  --duration N      Duration in seconds (default: 60; range: 1-3600)
  --rate N          Scheduled requests/second (default: 30; range: 0.1-200)
  --concurrency N   Maximum requests in flight (default: 20; range: 1-100)
  --timeout N       Per-request timeout seconds (default: 5; range: 0.1-30)
EOF
}

duration=60
rate=30
concurrency=20
timeout=5
duration_set=false
rate_set=false
concurrency_set=false
timeout_set=false

while (($# > 0)); do
  case "$1" in
    --duration)
      [[ "$duration_set" == false && $# -ge 2 ]] || { usage; exit 2; }
      duration=$2
      duration_set=true
      shift 2
      ;;
    --rate)
      [[ "$rate_set" == false && $# -ge 2 ]] || { usage; exit 2; }
      rate=$2
      rate_set=true
      shift 2
      ;;
    --concurrency)
      [[ "$concurrency_set" == false && $# -ge 2 ]] || { usage; exit 2; }
      concurrency=$2
      concurrency_set=true
      shift 2
      ;;
    --timeout)
      [[ "$timeout_set" == false && $# -ge 2 ]] || { usage; exit 2; }
      timeout=$2
      timeout_set=true
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ ! "$duration" =~ ^[1-9][0-9]*$ ]] || ((duration > 3600)); then
  echo "--duration must be an integer from 1 through 3600" >&2
  exit 2
fi
if [[ ! "$concurrency" =~ ^[1-9][0-9]*$ ]] || ((concurrency > 100)); then
  echo "--concurrency must be an integer from 1 through 100" >&2
  exit 2
fi
if [[ ! "$rate" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] ||
   ! awk -v value="$rate" 'BEGIN { exit !(value >= 0.1 && value <= 200) }'; then
  echo "--rate must be numeric from 0.1 through 200" >&2
  exit 2
fi
if [[ ! "$timeout" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] ||
   ! awk -v value="$timeout" 'BEGIN { exit !(value >= 0.1 && value <= 30) }'; then
  echo "--timeout must be numeric from 0.1 through 30" >&2
  exit 2
fi

readonly client_ip="192.168.130.10"
readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)

echo "=== a-client normal traffic: ${duration}s at ${rate} requests/s, concurrency ${concurrency} ===" >&2
ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" \
  'test -x /opt/solis-workload/solis_client.py' || {
  echo "a-client workload is not deployed; run ./lab/scripts/deploy-client-workload.sh" >&2
  exit 1
}
ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" \
  /usr/bin/python3 /opt/solis-workload/solis_client.py \
  --duration "$duration" \
  --rate "$rate" \
  --concurrency "$concurrency" \
  --timeout "$timeout"
