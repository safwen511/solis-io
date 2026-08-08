#!/usr/bin/env bash
set -euo pipefail

readonly BASE_IMAGE="/var/lib/libvirt/images/solis-io/base/ubuntu-24.04-base.qcow2"
readonly STORAGE_ROOT="/var/lib/libvirt/images/solis-io"

usage() {
  echo "Usage: $0 [--force] name tenant network ip memory_mb vcpus disk_gb role" >&2
}

force=false
if [[ "${1:-}" == "--force" ]]; then
  force=true
  shift
fi

if [[ $# -ne 8 ]]; then
  usage
  exit 2
fi

name=$1
tenant=$2
network=$3
ip=$4
memory_mb=$5
vcpus=$6
disk_gb=$7
role=$8

case "$role" in
  client)
    packages=(qemu-guest-agent curl apache2-utils iputils-ping)
    ;;
  web)
    packages=(qemu-guest-agent nginx curl python3 python3-psycopg2)
    ;;
  db)
    packages=(qemu-guest-agent postgresql postgresql-client curl)
    ;;
  stress)
    packages=(qemu-guest-agent fio curl iputils-ping)
    ;;
  *)
    echo "Unsupported role: $role" >&2
    exit 2
    ;;
esac

for value in "$name" "$tenant" "$network"; do
  if [[ ! "$value" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
    echo "Invalid name, tenant, or network value: $value" >&2
    exit 2
  fi
done

if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] ||
   [[ ! "$memory_mb" =~ ^[0-9]+$ ]] ||
   [[ ! "$vcpus" =~ ^[0-9]+$ ]] ||
   [[ ! "$disk_gb" =~ ^[0-9]+$ ]]; then
  echo "Invalid IP address or numeric VM setting" >&2
  exit 2
fi

domain_exists=false
if virsh dominfo "$name" >/dev/null 2>&1; then
  if [[ "$force" != true ]]; then
    echo "VM $name already exists; skipping (use --force to replace it)."
    exit 0
  fi
  domain_exists=true
fi

if [[ ! -f "$BASE_IMAGE" ]]; then
  echo "Base image not found: $BASE_IMAGE" >&2
  exit 1
fi

if [[ -z "${SSH_PUBLIC_KEY_FILE:-}" ]]; then
  if [[ -n "${SUDO_USER:-}" ]]; then
    SSH_PUBLIC_KEY_FILE="/home/${SUDO_USER}/.ssh/id_ed25519.pub"
  else
    SSH_PUBLIC_KEY_FILE="${HOME}/.ssh/id_ed25519.pub"
  fi
fi
readonly SSH_PUBLIC_KEY_FILE
if [[ ! -f "$SSH_PUBLIC_KEY_FILE" ]]; then
  echo "SSH public key not found: $SSH_PUBLIC_KEY_FILE" >&2
  exit 1
fi

readonly vm_dir="${STORAGE_ROOT}/${tenant}/${name}"
readonly disk_path="${vm_dir}/${name}.qcow2"
readonly meta_data_path="${vm_dir}/meta-data"
readonly user_data_path="${vm_dir}/user-data"
readonly seed_path="${vm_dir}/${name}-seed.iso"

if [[ -e "$disk_path" || -e "$seed_path" ]]; then
  if [[ "$force" != true ]]; then
    echo "VM artifacts already exist in $vm_dir; refusing to overwrite them." >&2
    exit 1
  fi
fi

IFS=. read -r ip_a ip_b ip_c ip_d <<< "$ip"
for octet in "$ip_a" "$ip_b" "$ip_c" "$ip_d"; do
  if (( 10#$octet > 255 )); then
    echo "Invalid IPv4 address: $ip" >&2
    exit 2
  fi
done
printf -v mac_address '52:54:00:%02x:%02x:%02x' \
  "$((10#$ip_b))" "$((10#$ip_c))" "$((10#$ip_d))"

if [[ "$domain_exists" == true ]]; then
  echo "Replacing existing VM $name."
  if [[ "$(virsh domstate "$name" | tr -d '\r')" != "shut off" ]]; then
    virsh destroy "$name"
  fi
  virsh undefine "$name" --nvram 2>/dev/null || virsh undefine "$name"
fi

mkdir -p "$vm_dir"
if [[ "$force" == true ]]; then
  rm -f -- "$disk_path" "$seed_path" "$meta_data_path" "$user_data_path"
fi

qemu-img create \
  -f qcow2 \
  -F qcow2 \
  -b "$BASE_IMAGE" \
  "$disk_path" \
  "${disk_gb}G"

cat > "$meta_data_path" <<EOF
instance-id: ${name}-$(date +%s)
local-hostname: ${name}
EOF

ssh_public_key=$(<"$SSH_PUBLIC_KEY_FILE")
{
  echo '#cloud-config'
  echo "hostname: ${name}"
  echo 'manage_etc_hosts: true'
  echo 'users:'
  echo '  - name: flint'
  echo '    groups: [sudo]'
  echo '    shell: /bin/bash'
  echo '    sudo: ALL=(ALL) NOPASSWD:ALL'
  echo '    ssh_authorized_keys:'
  echo '      - >-'
  printf '        %s\n' "$ssh_public_key"
  echo 'ssh_pwauth: false'
  echo 'disable_root: true'
  echo 'package_update: true'
  echo 'packages:'
  printf '  - %s\n' "${packages[@]}"
  echo 'runcmd:'
  echo '  - [systemctl, enable, --now, qemu-guest-agent]'
} > "$user_data_path"

cloud-localds "$seed_path" "$user_data_path" "$meta_data_path"

reservation_xml="<host mac='${mac_address}' name='${name}' ip='${ip}'/>"
if [[ "$force" == true ]]; then
  virsh net-update "$network" delete ip-dhcp-host "$reservation_xml" \
    --live --config >/dev/null 2>&1 || true
fi
virsh net-update "$network" add-last ip-dhcp-host "$reservation_xml" \
  --live --config

chown -R libvirt-qemu:kvm "$vm_dir"

virt-install \
  --name "$name" \
  --memory "$memory_mb" \
  --vcpus "$vcpus" \
  --cpu host-passthrough \
  --os-variant ubuntu24.04 \
  --disk "path=${disk_path},format=qcow2,bus=virtio" \
  --disk "path=${seed_path},device=cdrom" \
  --network "network=${network},model=virtio,mac=${mac_address}" \
  --graphics none \
  --console pty,target_type=serial \
  --import \
  --noautoconsole

echo "Created VM $name ($role) at $ip on $network."
