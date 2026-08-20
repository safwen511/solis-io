#!/usr/bin/env bash
set -euo pipefail

# usage prints the accepted command syntax without changing host or guest state.
usage() {
  echo "Usage: $0 tenant-a|tenant-b" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

readonly tenant_name=$1
case "$tenant_name" in
  tenant-a)
    readonly client_ip="192.168.130.10"
    readonly web_ip="192.168.130.20"
    readonly db_ip="192.168.130.30"
    readonly tenant_subnet="192.168.130.0/24"
    ;;
  tenant-b)
    readonly client_ip="192.168.140.10"
    readonly web_ip="192.168.140.20"
    readonly db_ip="192.168.140.30"
    readonly tenant_subnet="192.168.140.0/24"
    ;;
  *)
    usage
    exit 2
    ;;
esac

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly project_dir="$(cd -- "${script_dir}/../.." && pwd)"
readonly webapp_file="${project_dir}/lab/workloads/webapp/solis_webapp.py"
readonly schema_file="${project_dir}/lab/workloads/db/schema.sql"
readonly retention_file="${project_dir}/lab/workloads/db/retention.sql"
readonly guest_config_dir="${project_dir}/lab/guest-configs"
readonly pg_hba_template="${guest_config_dir}/postgresql/pg-hba-solis.conf.template"
readonly postgresql_listen_file="${guest_config_dir}/postgresql/postgresql-listen.sql"
readonly retention_service_file="${guest_config_dir}/postgresql/solis-workload-retention.service"
readonly retention_timer_file="${guest_config_dir}/postgresql/solis-workload-retention.timer"
readonly web_service_template="${guest_config_dir}/web/solis-workload.service.template"
readonly nginx_config_file="${guest_config_dir}/web/nginx-solis-workload.conf"
readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)

readonly required_files=(
  "$webapp_file"
  "$schema_file"
  "$retention_file"
  "$pg_hba_template"
  "$postgresql_listen_file"
  "$retention_service_file"
  "$retention_timer_file"
  "$web_service_template"
  "$nginx_config_file"
)
for required_file in "${required_files[@]}"; do
  [[ -r "$required_file" ]] || {
    echo "Required workload or guest configuration is missing: ${required_file}" >&2
    exit 1
  }
done

echo "=== Tenant topology ==="
echo "Tenant: $tenant_name"
echo "Client: $client_ip"
echo "Web:    $web_ip"
echo "DB:     $db_ip"

echo
echo "=== Configuring PostgreSQL on ${db_ip} ==="
scp "${ssh_options[@]}" "$schema_file" "${ssh_user}@${db_ip}:/tmp/solis-schema.sql"
scp "${ssh_options[@]}" "$retention_file" "${ssh_user}@${db_ip}:/tmp/solis-retention.sql"
scp "${ssh_options[@]}" "$pg_hba_template" "${ssh_user}@${db_ip}:/tmp/solis-pg-hba.conf.template"
scp "${ssh_options[@]}" "$postgresql_listen_file" "${ssh_user}@${db_ip}:/tmp/solis-postgresql-listen.sql"
scp "${ssh_options[@]}" "$retention_service_file" "${ssh_user}@${db_ip}:/tmp/solis-workload-retention.service"
scp "${ssh_options[@]}" "$retention_timer_file" "${ssh_user}@${db_ip}:/tmp/solis-workload-retention.timer"
ssh "${ssh_options[@]}" "${ssh_user}@${db_ip}" \
  "sudo -n env TENANT_SUBNET='${tenant_subnet}' bash -s" <<'REMOTE_DB_SETUP'
set -euo pipefail
trap 'rm -f -- /tmp/solis-schema.sql /tmp/solis-retention.sql /tmp/solis-pg-hba.conf.template /tmp/solis-postgresql-listen.sql /tmp/solis-workload-retention.service /tmp/solis-workload-retention.timer' EXIT

if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname = 'solis'" | grep -qx 1; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE USER solis WITH PASSWORD 'solispass'"
fi

if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname = 'solisapp'" | grep -qx 1; then
  sudo -u postgres createdb --owner=solis solisapp
fi

sudo -u postgres psql -v ON_ERROR_STOP=1 -d solisapp -f /tmp/solis-schema.sql
sudo -u postgres psql -v ON_ERROR_STOP=1 -d solisapp <<'SQL'
GRANT SELECT, INSERT ON TABLE request_log TO solis;
GRANT USAGE, SELECT ON SEQUENCE request_log_id_seq TO solis;
SQL

sudo -u postgres psql --no-psqlrc -f /tmp/solis-postgresql-listen.sql

hba_file=$(sudo -u postgres psql -tAc "SHOW hba_file")
hba_rule="$(sed "s|@TENANT_SUBNET@|${TENANT_SUBNET}|g" /tmp/solis-pg-hba.conf.template)"
[[ -n "$hba_rule" && "$hba_rule" != *"@TENANT_SUBNET@"* && "$hba_rule" != *$'\n'* ]] || {
  echo "invalid rendered PostgreSQL access rule" >&2
  exit 1
}
if ! grep -Fqx "$hba_rule" "$hba_file"; then
  printf '%s\n' "$hba_rule" >> "$hba_file"
fi

systemctl restart postgresql

install -d -m 0755 /opt/solis-workload
install -m 0644 /tmp/solis-retention.sql /opt/solis-workload/request_log_retention.sql
install -m 0644 /tmp/solis-workload-retention.service /etc/systemd/system/solis-workload-retention.service
install -m 0644 /tmp/solis-workload-retention.timer /etc/systemd/system/solis-workload-retention.timer

systemctl daemon-reload
systemctl enable --now solis-workload-retention.timer
systemctl start solis-workload-retention.service
REMOTE_DB_SETUP

echo
echo "=== Configuring workload service on ${web_ip} ==="
scp "${ssh_options[@]}" "$webapp_file" "${ssh_user}@${web_ip}:/tmp/solis_webapp.py"
scp "${ssh_options[@]}" "$web_service_template" "${ssh_user}@${web_ip}:/tmp/solis-workload.service.template"
scp "${ssh_options[@]}" "$nginx_config_file" "${ssh_user}@${web_ip}:/tmp/solis-nginx.conf"
ssh "${ssh_options[@]}" "${ssh_user}@${web_ip}" \
  "sudo -n env TENANT_NAME='${tenant_name}' DB_HOST='${db_ip}' bash -s" <<'REMOTE_WEB_SETUP'
set -euo pipefail
trap 'rm -f -- /tmp/solis_webapp.py /tmp/solis-workload.service.template /tmp/solis-workload.service /tmp/solis-nginx.conf' EXIT

install -d -m 0755 /opt/solis-workload
install -m 0755 /tmp/solis_webapp.py /opt/solis-workload/solis_webapp.py

sed \
  -e "s|@TENANT_NAME@|${TENANT_NAME}|g" \
  -e "s|@DB_HOST@|${DB_HOST}|g" \
  /tmp/solis-workload.service.template > /tmp/solis-workload.service
if grep -Eq '@[A-Z_]+@' /tmp/solis-workload.service; then
  echo "unresolved placeholder in workload service" >&2
  exit 1
fi

install -m 0644 /tmp/solis-workload.service /etc/systemd/system/solis-workload.service
install -m 0644 /tmp/solis-nginx.conf /etc/nginx/sites-available/solis-workload

ln -sfn /etc/nginx/sites-available/solis-workload /etc/nginx/sites-enabled/solis-workload
rm -f /etc/nginx/sites-enabled/default

systemctl daemon-reload
systemctl enable --now solis-workload.service
nginx -t
systemctl restart nginx
REMOTE_WEB_SETUP

echo
echo "=== Deployment complete ==="
echo "Health URL: http://${web_ip}/health"
