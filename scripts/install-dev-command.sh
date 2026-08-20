#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd -- "${script_dir}/.." && pwd)"
readonly binary_path="${repo_root}/solis"
readonly config_template="${repo_root}/lab/config/solis.json"
readonly target_path="/usr/local/bin/solis"
readonly system_config_directory="/etc/solis"
readonly system_config_path="${system_config_directory}/config.json"
readonly config_package="github.com/safwen511/solis-io/internal/config"

# usage prints the accepted command syntax without changing host or guest state.
usage() {
  cat <<'EOF'
Usage: scripts/install-dev-command.sh [--replace]

Build the current checkout and install a root-owned /usr/local/bin/solis binary
plus /etc/solis/config.json. The installed development binary uses that config
by default, so `solis` and `sudo solis` work from any directory. It installs no
daemon or service.

Use --replace only when intentionally updating an existing regular Solis binary
and configuration installed by an earlier run.
EOF
}

# fail writes one bounded error message and terminates the script unsuccessfully.
fail() {
  echo "Error: $*" >&2
  exit 1
}

replace=false
(( $# <= 1 )) || fail "too many arguments"
if (($# > 0)); then
  case "$1" in
    --replace)
      replace=true
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
fi

for command in go install jq mktemp mv rm sudo; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: ${command}"
done
[[ -f "$config_template" && ! -L "$config_template" ]] || fail "lab configuration is missing or unsafe: ${config_template}"
[[ -d /usr/local/bin && ! -L /usr/local/bin ]] || fail "/usr/local/bin must be an existing non-symlink directory"

build_temporary="$(mktemp "${repo_root}/.solis.build.XXXXXXXX")"
config_temporary="$(mktemp /tmp/solis-config.XXXXXXXX)"
binary_install_temporary=""
config_install_temporary=""

# cleanup stops script-owned work and removes only paths allocated by this run.
cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  [[ -z "$build_temporary" ]] || rm -f -- "$build_temporary"
  [[ -z "$config_temporary" ]] || rm -f -- "$config_temporary"
  if [[ -n "$binary_install_temporary" ]]; then
    sudo rm -f -- "$binary_install_temporary" 2>/dev/null || true
  fi
  if [[ -n "$config_install_temporary" ]]; then
    sudo rm -f -- "$config_install_temporary" 2>/dev/null || true
  fi
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -e "$binary_path" || -L "$binary_path" ]]; then
  [[ -f "$binary_path" && ! -L "$binary_path" ]] || fail "local binary target is not a regular file: ${binary_path}"
fi

echo "=== Building current Solis checkout ==="
(
	cd "$repo_root"
	go build -ldflags "-X ${config_package}.InstalledDefaultPath=${system_config_path}" -o "$build_temporary" ./cmd/solis
)
chmod 0755 "$build_temporary"

jq \
	--arg inventory "${repo_root}/lab/config/vms.csv" \
	--arg captures "${repo_root}/lab/reports/captures" \
	--arg reports "${repo_root}/lab/reports/workload/20260808T174825Z" \
	'.inventory_csv = $inventory
	 | .capture_output_root = $captures
	 | .default_report_dir = $reports' \
	"$config_template" >"$config_temporary"
chmod 0644 "$config_temporary"

echo "=== Installing ${target_path} and ${system_config_path} ==="
sudo -v
if sudo test -L "$target_path"; then
  fail "refusing symbolic-link target: ${target_path}"
fi
if sudo test -e "$target_path" && ! sudo test -f "$target_path"; then
	fail "refusing non-regular target: ${target_path}"
fi
if sudo test -f "$target_path" && [[ "$replace" != true ]]; then
	fail "target already exists; inspect it and rerun with --replace to update: ${target_path}"
fi
if sudo test -L "$system_config_directory"; then
	fail "refusing symbolic-link configuration directory: ${system_config_directory}"
fi
if sudo test -e "$system_config_directory" && ! sudo test -d "$system_config_directory"; then
	fail "refusing non-directory configuration path: ${system_config_directory}"
fi
if ! sudo test -d "$system_config_directory"; then
	sudo install -d -o root -g root -m 0755 "$system_config_directory"
fi
if sudo test -L "$system_config_path"; then
	fail "refusing symbolic-link configuration target: ${system_config_path}"
fi
if sudo test -e "$system_config_path" && ! sudo test -f "$system_config_path"; then
	fail "refusing non-regular configuration target: ${system_config_path}"
fi
if sudo test -f "$system_config_path" && [[ "$replace" != true ]]; then
	fail "configuration already exists; inspect it and rerun with --replace to update: ${system_config_path}"
fi

binary_install_temporary="$(sudo mktemp /usr/local/bin/.solis.install.XXXXXXXX)"
config_install_temporary="$(sudo mktemp "${system_config_directory}/.config.install.XXXXXXXX")"
sudo install -o root -g root -m 0755 "$build_temporary" "$binary_install_temporary"
sudo install -o root -g root -m 0644 "$config_temporary" "$config_install_temporary"
sudo mv -T -- "$config_install_temporary" "$system_config_path"
config_install_temporary=""
sudo mv -T -- "$binary_install_temporary" "$target_path"
binary_install_temporary=""

mv -T -- "$build_temporary" "$binary_path"
build_temporary=""

echo "Installed: ${target_path}"
echo "Checkout: ${repo_root}"
echo "Config:   ${system_config_path}"
echo "Run from any directory: solis"
echo "Run with VM-attributed eBPF: sudo solis"
