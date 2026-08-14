#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: manage-steady-traffic.sh deploy|start|stop|status|remove [options]

Options:
  --tenant a|b|all    Tenant client(s) to manage (default: all)
  --rate N            Requests/second per client for deploy (default: 2; 0.1-20)
  --dry-run           Print the fixed plan without SSH or remote changes

Deploy enables a low-rate systemd service on a-client and/or b-client. The
matching database retention timer must already be installed and active by
deploy-tenant-workload.sh; otherwise deploy/start refuses to proceed.
EOF
}

fail() {
  echo "Error: $*" >&2
  exit 1
}

[[ $# -ge 1 ]] || { usage >&2; exit 2; }
command=$1
shift

case "$command" in
  deploy|start|stop|status|remove) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

tenant=all
rate=2
dry_run=false
tenant_set=false
rate_set=false
while (($# > 0)); do
  case "$1" in
    --tenant)
      [[ "$tenant_set" == false && $# -ge 2 ]] || { usage >&2; exit 2; }
      tenant=$2
      tenant_set=true
      shift 2
      ;;
    --rate)
      [[ "$rate_set" == false && $# -ge 2 ]] || { usage >&2; exit 2; }
      rate=$2
      rate_set=true
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

case "$tenant" in a|b|all) ;; *) fail "--tenant must be a, b, or all" ;; esac
if [[ ! "$rate" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] ||
   ! awk -v value="$rate" 'BEGIN { exit !(value >= 0.1 && value <= 20) }'; then
  fail "--rate must be numeric from 0.1 through 20"
fi
[[ "$command" == deploy || "$rate_set" == false ]] || fail "--rate is valid only with deploy"

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly project_dir="$(cd -- "${script_dir}/../.." && pwd)"
readonly steady_client="${project_dir}/lab/workloads/client/solis_steady_client.py"
readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)
readonly service_name="solis-steady-traffic.service"

[[ "$ssh_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "SOLIS_SSH_USER is not a safe service user name"
[[ -r "$steady_client" ]] || fail "steady client program is missing: ${steady_client}"

if [[ "$tenant" == all ]]; then
  tenants=(a b)
else
  tenants=("$tenant")
fi

tenant_values() {
  case "$1" in
    a) printf '%s\n' "tenant-a|192.168.130.10|192.168.130.20|192.168.130.30|a-client|a-web|a-db" ;;
    b) printf '%s\n' "tenant-b|192.168.140.10|192.168.140.20|192.168.140.30|b-client|b-web|b-db" ;;
  esac
}

show_plan() {
  echo "Solis steady lab traffic plan"
  echo "Action: ${command}"
  if [[ "$command" == deploy ]]; then
    echo "Rate: ${rate} requests/second per client"
  else
    echo "Rate: unchanged from the installed service configuration"
  fi
  echo "Retention: keep 2 hours; timer every 15 minutes"
  for short_tenant in "${tenants[@]}"; do
    IFS='|' read -r tenant_name client_ip web_ip db_ip client_vm web_vm db_vm <<<"$(tenant_values "$short_tenant")"
    echo "- ${tenant_name}: ${client_vm} (${client_ip}) -> ${web_vm} (${web_ip}) -> ${db_vm} (${db_ip})"
  done
  echo "Traffic service: ${service_name} (enabled only by deploy/start)"
  echo "No payloads are retained; journal output is one bounded aggregate every 5 minutes."
}

show_plan
[[ "$dry_run" == false ]] || exit 0

require_retention() {
  local db_ip=$1
  local db_vm=$2
  ssh "${ssh_options[@]}" "${ssh_user}@${db_ip}" \
    "sudo -n systemctl is-enabled --quiet solis-workload-retention.timer && sudo -n systemctl is-active --quiet solis-workload-retention.timer" ||
    fail "${db_vm} retention timer is not active; rerun ./lab/scripts/deploy-tenant-workload.sh for its tenant"
}

deploy_client() {
  local tenant_name=$1 client_ip=$2 web_ip=$3 db_ip=$4 client_vm=$5 web_vm=$6 db_vm=$7
  require_retention "$db_ip" "$db_vm"
  ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" 'command -v python3 >/dev/null 2>&1' ||
    fail "python3 is unavailable on ${client_vm}"
  scp "${ssh_options[@]}" "$steady_client" "${ssh_user}@${client_ip}:/tmp/solis_steady_client.py"
  ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" \
    "sudo -n env SERVICE_USER='${ssh_user}' TENANT_NAME='${tenant_name}' TARGET_HOST='${web_ip}' TARGET_VM='${web_vm}' DATABASE_VM='${db_vm}' REQUEST_RATE='${rate}' bash -s" <<'REMOTE_DEPLOY'
set -euo pipefail
install -d -m 0755 /opt/solis-workload
install -m 0755 /tmp/solis_steady_client.py /opt/solis-workload/solis_steady_client.py
rm -f -- /tmp/solis_steady_client.py

cat > /etc/systemd/system/solis-steady-traffic.service <<EOF
[Unit]
Description=Solis low-rate steady tenant traffic
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Environment=SOLIS_TENANT=${TENANT_NAME}
Environment=SOLIS_TARGET_HOST=${TARGET_HOST}
Environment=SOLIS_TARGET_VM=${TARGET_VM}
Environment=SOLIS_DATABASE_VM=${DATABASE_VM}
Environment=SOLIS_RATE_RPS=${REQUEST_RATE}
Environment=SOLIS_MAX_CONCURRENCY=4
Environment=SOLIS_TIMEOUT_SECONDS=3
Environment=SOLIS_LOG_INTERVAL_SECONDS=300
ExecStart=/usr/bin/python3 /opt/solis-workload/solis_steady_client.py
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now solis-steady-traffic.service
REMOTE_DEPLOY
}

manage_client() {
  local action=$1 client_ip=$2 client_vm=$3
  case "$action" in
    start)
      ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" "sudo -n systemctl enable --now '${service_name}'" || fail "could not start traffic on ${client_vm}"
      ;;
    stop)
      ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" "sudo -n systemctl disable --now '${service_name}'" || fail "could not stop traffic on ${client_vm}"
      ;;
    status)
      echo "${client_vm}:"
      ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" "sudo -n systemctl show '${service_name}' --property=LoadState,UnitFileState,ActiveState,SubState --no-pager"
      ;;
    remove)
      ssh "${ssh_options[@]}" "${ssh_user}@${client_ip}" \
        "sudo -n systemctl disable --now '${service_name}' 2>/dev/null || true; sudo -n rm -f -- '/etc/systemd/system/${service_name}' '/opt/solis-workload/solis_steady_client.py'; sudo -n systemctl daemon-reload"
      ;;
  esac
}

for short_tenant in "${tenants[@]}"; do
  IFS='|' read -r tenant_name client_ip web_ip db_ip client_vm web_vm db_vm <<<"$(tenant_values "$short_tenant")"
  echo "=== ${command}: ${client_vm} ==="
  case "$command" in
    deploy) deploy_client "$tenant_name" "$client_ip" "$web_ip" "$db_ip" "$client_vm" "$web_vm" "$db_vm" ;;
    start)
      require_retention "$db_ip" "$db_vm"
      manage_client start "$client_ip" "$client_vm"
      ;;
    stop|status|remove) manage_client "$command" "$client_ip" "$client_vm" ;;
  esac
done

echo "Steady traffic action complete."
