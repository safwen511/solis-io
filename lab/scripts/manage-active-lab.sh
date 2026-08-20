#!/usr/bin/env bash
set -euo pipefail

# usage prints the accepted command syntax without changing host or guest state.
usage() {
  cat <<'EOF'
Usage: manage-active-lab.sh setup|normal|pressure|status|stop|remove [options]

Commands:
  setup       Deploy 5 rps/client application traffic and install pressure unit
  normal      Run both tenant applications; stop pressure and delete its file
  pressure    Run both applications plus moderate b-stress storage pressure
  status      Show both client services and the pressure service/file size
  stop        Stop application traffic and pressure; delete the pressure file
  remove      Remove the client and pressure services and pressure file

Options:
  --client-rate N     Requests/second per tenant during setup (default: 5; 0.1-20)
  --pressure-iops N   IOPS per fio job during setup (default: 800; 100-1600)
  --dry-run           Print the bounded plan without SSH or remote changes

The pressure profile uses two 4 KiB direct-write jobs and a fixed 1 GiB file.
At the default rate this is approximately 1,600 IOPS / 6.25 MiB/s total.
EOF
}

# fail writes one bounded error message and terminates the script unsuccessfully.
fail() {
  echo "Error: $*" >&2
  exit 1
}

[[ $# -ge 1 ]] || { usage >&2; exit 2; }
action=$1
shift
case "$action" in
  setup|normal|pressure|status|stop|remove) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

client_rate=5
pressure_iops=800
client_rate_set=false
pressure_iops_set=false
dry_run=false
while (($# > 0)); do
  case "$1" in
    --client-rate)
      [[ "$client_rate_set" == false && $# -ge 2 ]] || { usage >&2; exit 2; }
      client_rate=$2
      client_rate_set=true
      shift 2
      ;;
    --pressure-iops)
      [[ "$pressure_iops_set" == false && $# -ge 2 ]] || { usage >&2; exit 2; }
      pressure_iops=$2
      pressure_iops_set=true
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
    *) usage >&2; exit 2 ;;
  esac
done

if [[ ! "$client_rate" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] ||
   ! awk -v value="$client_rate" 'BEGIN { exit !(value >= 0.1 && value <= 20) }'; then
  fail "--client-rate must be numeric from 0.1 through 20"
fi
if [[ ! "$pressure_iops" =~ ^[1-9][0-9]*$ ]] ||
   ((pressure_iops < 100 || pressure_iops > 1600)); then
  fail "--pressure-iops must be an integer from 100 through 1600"
fi
[[ "$action" == setup || "$client_rate_set" == false ]] || fail "--client-rate is valid only with setup"
[[ "$action" == setup || "$pressure_iops_set" == false ]] || fail "--pressure-iops is valid only with setup"

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly steady_manager="${script_dir}/manage-steady-traffic.sh"
readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly stress_ip="192.168.140.40"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)
readonly pressure_service="solis-moderate-pressure.service"
readonly pressure_directory="/var/lib/solis-moderate-pressure"
readonly pressure_file="${pressure_directory}/pressure.dat"
readonly legacy_pressure_file="/home/${ssh_user}/solis-moderate-pressure.dat"
readonly pressure_size_bytes=1073741824
readonly pressure_jobs=2
readonly pressure_block_kib=4
readonly total_iops=$((pressure_iops * pressure_jobs))
readonly total_mib_per_second="$(awk -v iops="$total_iops" -v kib="$pressure_block_kib" 'BEGIN { printf "%.2f", iops * kib / 1024 }')"

[[ -x "$steady_manager" ]] || fail "steady traffic manager is unavailable: ${steady_manager}"
[[ "$ssh_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "SOLIS_SSH_USER is not a safe service user name"

# print_plan shows the complete workload and evidence plan before any remote mutation.
print_plan() {
  echo "Solis active lab scenario"
  echo "Action: ${action}"
  echo "Applications: a-client -> a-web -> a-db and b-client -> b-web -> b-db"
  if [[ "$action" == setup ]]; then
    echo "Application rate: ${client_rate} requests/second per tenant"
  else
    echo "Application rate: unchanged from the installed client service configuration"
  fi
  echo "Pressure target: b-stress (${stress_ip})"
  echo "Pressure ceiling: ${total_iops} IOPS total, approximately ${total_mib_per_second} MiB/s"
  echo "Pressure storage: fixed ${pressure_size_bytes}-byte file, removed by normal/stop/remove"
  echo "Retention: application rows older than 2 hours, checked every 15 minutes"
  case "$action" in
    setup) echo "Result: application traffic active; pressure installed but inactive" ;;
    normal) echo "Result: application traffic active; pressure inactive" ;;
    pressure) echo "Result: application traffic active; moderate pressure active" ;;
    stop) echo "Result: all generated traffic inactive" ;;
    remove) echo "Result: lab traffic services and pressure file removed" ;;
    status) echo "Result: read-only service and file status" ;;
  esac
}

print_plan
[[ "$dry_run" == false ]] || exit 0

# require_pressure_host verifies that the fixed pressure guest is reachable before remote changes.
require_pressure_host() {
  ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
    'command -v fio >/dev/null 2>&1 && sudo -n true' ||
    fail "b-stress is unreachable or lacks fio/passwordless lab sudo; start b-stress, wait for SSH, then retry"
}

# remote_pressure performs the bounded remote pressure step for this lab workflow.
remote_pressure() {
  local operation=$1
  ssh "${ssh_options[@]}" "${ssh_user}@${stress_ip}" \
    "sudo -n env SERVICE_USER='${ssh_user}' SERVICE_NAME='${pressure_service}' PRESSURE_DIRECTORY='${pressure_directory}' PRESSURE_FILE='${pressure_file}' LEGACY_PRESSURE_FILE='${legacy_pressure_file}' PRESSURE_BYTES='${pressure_size_bytes}' PRESSURE_IOPS='${pressure_iops}' OPERATION='${operation}' bash -s" <<'REMOTE_PRESSURE'
set -euo pipefail
service_group="$(id -gn "$SERVICE_USER")"

# safe_pressure_path accepts only the fixed pressure file owned by this lab scenario.
safe_pressure_path() {
  [[ ! -L "$PRESSURE_DIRECTORY" ]] || { echo "refusing symlink pressure directory" >&2; exit 1; }
  if [[ -e "$PRESSURE_DIRECTORY" ]]; then
    [[ -d "$PRESSURE_DIRECTORY" ]] || { echo "refusing non-directory pressure path" >&2; exit 1; }
    [[ "$(stat -c '%U' -- "$PRESSURE_DIRECTORY")" == "$SERVICE_USER" ]] || {
      echo "refusing pressure directory owned by another user" >&2
      exit 1
    }
  fi
  [[ ! -L "$PRESSURE_FILE" ]] || { echo "refusing symlink pressure file" >&2; exit 1; }
  if [[ -e "$PRESSURE_FILE" ]]; then
    [[ -f "$PRESSURE_FILE" ]] || { echo "refusing non-regular pressure file" >&2; exit 1; }
    [[ "$(stat -c '%U' -- "$PRESSURE_FILE")" == "$SERVICE_USER" ]] || {
      echo "refusing pressure file owned by another user" >&2
      exit 1
    }
  fi
}

# remove_legacy_pressure_file removes only the deprecated pressure file after stopping its owning service.
remove_legacy_pressure_file() {
  [[ ! -L "$LEGACY_PRESSURE_FILE" ]] || { echo "refusing symlink legacy pressure file" >&2; exit 1; }
  if [[ -e "$LEGACY_PRESSURE_FILE" ]]; then
    [[ -f "$LEGACY_PRESSURE_FILE" ]] || { echo "refusing non-regular legacy pressure file" >&2; exit 1; }
    [[ "$(stat -c '%U' -- "$LEGACY_PRESSURE_FILE")" == "$SERVICE_USER" ]] || {
      echo "refusing legacy pressure file owned by another user" >&2
      exit 1
    }
    rm -f -- "$LEGACY_PRESSURE_FILE"
  fi
}

# stop_and_remove_file stops the pressure service before removing its fixed data file.
stop_and_remove_file() {
  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  safe_pressure_path
  rm -f -- "$PRESSURE_FILE"
}

# ensure_pressure_directory verifies the fixed pressure file's parent instead of creating arbitrary directories.
ensure_pressure_directory() {
  safe_pressure_path
  install -d -o "$SERVICE_USER" -g "$service_group" -m 0700 "$PRESSURE_DIRECTORY"
}

case "$OPERATION" in
  setup)
    command -v fio >/dev/null 2>&1 || { echo "fio is unavailable" >&2; exit 1; }
    stop_and_remove_file
    remove_legacy_pressure_file
    ensure_pressure_directory
    cat >"/etc/systemd/system/${SERVICE_NAME}" <<EOF
[Unit]
Description=Solis bounded moderate storage pressure
After=local-fs.target

[Service]
Type=simple
User=${SERVICE_USER}
ExecStart=/usr/bin/fio --name=solis-moderate --ioengine=libaio --filename=${PRESSURE_FILE} --size=${PRESSURE_BYTES} --rw=randwrite --bs=4k --iodepth=16 --numjobs=2 --direct=1 --time_based --runtime=3600 --fdatasync=1024 --rate_iops=${PRESSURE_IOPS} --group_reporting
Restart=always
RestartSec=3
Nice=5
NoNewPrivileges=true
PrivateDevices=false
PrivateTmp=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ReadWritePaths=${PRESSURE_DIRECTORY}
TimeoutStopSec=20s

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    ;;
  start)
    systemctl cat "$SERVICE_NAME" >/dev/null
    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    ensure_pressure_directory
    rm -f -- "$PRESSURE_FILE"
    systemctl enable --now "$SERVICE_NAME"
    ;;
  normal|stop)
    stop_and_remove_file
    remove_legacy_pressure_file
    ;;
  status)
    systemctl show "$SERVICE_NAME" --property=LoadState,UnitFileState,ActiveState,SubState --no-pager
    safe_pressure_path
    if [[ -f "$PRESSURE_FILE" ]]; then
      stat -c 'PressureFileBytes=%s' -- "$PRESSURE_FILE"
    else
      echo 'PressureFileBytes=0'
    fi
    ;;
  remove)
    stop_and_remove_file
    remove_legacy_pressure_file
    rm -f -- "/etc/systemd/system/${SERVICE_NAME}"
    rmdir -- "$PRESSURE_DIRECTORY" 2>/dev/null || true
    systemctl daemon-reload
    ;;
  *) exit 2 ;;
esac
REMOTE_PRESSURE
}

case "$action" in
  setup)
    # Preflight the pressure VM before deploying clients so setup cannot leave
    # a newly modified application tier when its required pressure tier is
    # unavailable.
    require_pressure_host
    "$steady_manager" deploy --tenant all --rate "$client_rate"
    remote_pressure setup
    ;;
  normal)
    "$steady_manager" start --tenant all
    remote_pressure normal
    ;;
  pressure)
    require_pressure_host
    "$steady_manager" start --tenant all
    remote_pressure start
    ;;
  status)
    "$steady_manager" status --tenant all
    echo "=== b-stress moderate pressure ==="
    remote_pressure status
    ;;
  stop)
    "$steady_manager" stop --tenant all
    remote_pressure stop
    ;;
  remove)
    "$steady_manager" remove --tenant all
    remote_pressure remove
    ;;
esac

echo "Active lab action complete."
