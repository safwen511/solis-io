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
readonly ssh_user="${SOLIS_SSH_USER:-flint}"
readonly ssh_options=(-o BatchMode=yes -o ConnectTimeout=10)

if [[ ! -r "$webapp_file" || ! -r "$schema_file" || ! -r "$retention_file" ]]; then
  echo "Workload application or schema file is missing under ${project_dir}/lab/workloads" >&2
  exit 1
fi

echo "=== Tenant topology ==="
echo "Tenant: $tenant_name"
echo "Client: $client_ip"
echo "Web:    $web_ip"
echo "DB:     $db_ip"

echo
echo "=== Configuring PostgreSQL on ${db_ip} ==="
scp "${ssh_options[@]}" "$schema_file" "${ssh_user}@${db_ip}:/tmp/solis-schema.sql"
scp "${ssh_options[@]}" "$retention_file" "${ssh_user}@${db_ip}:/tmp/solis-retention.sql"
ssh "${ssh_options[@]}" "${ssh_user}@${db_ip}" \
  "sudo -n env TENANT_SUBNET='${tenant_subnet}' bash -s" <<'REMOTE_DB_SETUP'
set -euo pipefail
trap 'rm -f -- /tmp/solis-schema.sql /tmp/solis-retention.sql' EXIT

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

sudo -u postgres psql -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET listen_addresses = '*'"

hba_file=$(sudo -u postgres psql -tAc "SHOW hba_file")
hba_rule="host solisapp solis ${TENANT_SUBNET} scram-sha-256"
if ! grep -Fqx "$hba_rule" "$hba_file"; then
  printf '%s\n' "$hba_rule" >> "$hba_file"
fi

systemctl restart postgresql

install -d -m 0755 /opt/solis-workload
install -m 0644 /tmp/solis-retention.sql /opt/solis-workload/request_log_retention.sql

cat > /etc/systemd/system/solis-workload-retention.service <<'EOF'
[Unit]
Description=Bound Solis lab request-log retention
After=postgresql.service

[Service]
Type=oneshot
User=postgres
Group=postgres
ExecStart=/usr/bin/psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname=solisapp --file=/opt/solis-workload/request_log_retention.sql
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
EOF

cat > /etc/systemd/system/solis-workload-retention.timer <<'EOF'
[Unit]
Description=Run bounded Solis lab request-log retention

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now solis-workload-retention.timer
systemctl start solis-workload-retention.service
REMOTE_DB_SETUP

echo
echo "=== Configuring workload service on ${web_ip} ==="
scp "${ssh_options[@]}" "$webapp_file" "${ssh_user}@${web_ip}:/tmp/solis_webapp.py"
ssh "${ssh_options[@]}" "${ssh_user}@${web_ip}" \
  "sudo -n env TENANT_NAME='${tenant_name}' DB_HOST='${db_ip}' bash -s" <<'REMOTE_WEB_SETUP'
set -euo pipefail

install -d -m 0755 /opt/solis-workload
install -m 0755 /tmp/solis_webapp.py /opt/solis-workload/solis_webapp.py
rm -f /tmp/solis_webapp.py

cat > /etc/systemd/system/solis-workload.service <<EOF
[Unit]
Description=Solis tenant workload service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=www-data
Group=www-data
Environment=SOLIS_TENANT=${TENANT_NAME}
Environment=SOLIS_DB_HOST=${DB_HOST}
Environment=SOLIS_DB_PORT=5432
Environment=SOLIS_DB_NAME=solisapp
Environment=SOLIS_DB_USER=solis
Environment=SOLIS_DB_PASSWORD=solispass
Environment=SOLIS_WEB_PORT=8080
ExecStart=/usr/bin/python3 /opt/solis-workload/solis_webapp.py
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/nginx/sites-available/solis-workload <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

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
