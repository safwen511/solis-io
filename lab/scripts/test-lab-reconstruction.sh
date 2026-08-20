#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly project_dir="$(cd -- "${script_dir}/../.." && pwd)"
readonly start_script="${script_dir}/start-lab-vms.sh"
readonly deploy_script="${script_dir}/deploy-tenant-workload.sh"
readonly guest_config_dir="${project_dir}/lab/guest-configs"

plan="$($start_script --wait-seconds 60 --dry-run)"
for expected in \
  "Networks: tenant-a-net tenant-b-net" \
  "a-client (192.168.130.10, client)" \
  "a-web (192.168.130.20, web)" \
  "a-db (192.168.130.30, db)" \
  "a-stress (192.168.130.40, stress)" \
  "b-client (192.168.140.10, client)" \
  "b-web (192.168.140.20, web)" \
  "b-db (192.168.140.30, db)" \
  "b-stress (192.168.140.40, stress)"
do
  grep -Fq "$expected" <<<"$plan"
done

if "$start_script" --wait-seconds 0 --dry-run >/dev/null 2>&1; then
  echo "invalid SSH wait ceiling was accepted" >&2
  exit 1
fi
grep -Fq 'readonly ssh_options=(-n ' "$start_script"

for required in \
  web/nginx-solis-workload.conf \
  web/solis-workload.service.template \
  postgresql/pg-hba-solis.conf.template \
  postgresql/postgresql-listen.sql \
  postgresql/solis-workload-retention.service \
  postgresql/solis-workload-retention.timer \
  client/solis-steady-traffic.service.template \
  stress/solis-moderate-pressure.service.template
do
  [[ -r "${guest_config_dir}/${required}" ]]
done

grep -Fq 'web_service_template=' "$deploy_script"
grep -Fq 'nginx_config_file=' "$deploy_script"
grep -Fq 'pg_hba_template=' "$deploy_script"
grep -Fq 'retention_timer_file=' "$deploy_script"

echo "Solis lab reconstruction tests: PASS"
