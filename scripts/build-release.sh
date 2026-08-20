#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd -- "${script_dir}/.." && pwd)"
readonly object_relative_path="internal/ebpf/bpf/generated/vm_block_latency_bpfel.o"
readonly install_relative_path="docs/INSTALL.md"
readonly notice_relative_path="NOTICE"
readonly requirements_relative_path="REQUIREMENTS.md"
readonly version_package="github.com/safwen511/solis-io/internal/version"

output_dir="${repo_root}/dist"

# usage prints the accepted command syntax without changing host or guest state.
usage() {
  cat <<'EOF'
Usage: scripts/build-release.sh [--output-dir DIR]

Build a deterministic Solis Linux/amd64 release from a clean exact Git tag.
The tag must match vMAJOR.MINOR.PATCH-experimental. The output directory may
be created, but existing release artifacts are never overwritten.
EOF
}

# fail writes one bounded error message and terminates the script unsuccessfully.
fail() {
  echo "Error: $*" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --output-dir)
      (($# >= 2)) || fail "--output-dir requires a value"
      output_dir=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

cd "$repo_root"
umask 077
export LC_ALL=C

for command in awk chmod cp date find git go gzip jq mkdir mktemp mv od rm sha256sum stat tar touch tr; do
  command -v "$command" >/dev/null 2>&1 || fail "required release command is missing: ${command}"
done
tar --version | grep -q 'GNU tar' || fail "the deterministic archive workflow requires GNU tar"
date --version >/dev/null 2>&1 || fail "the deterministic archive workflow requires GNU date"

[[ -z "$(git status --porcelain --untracked-files=normal)" ]] ||
  fail "release builds require a clean Git worktree"

version="$(git describe --tags --exact-match --match 'v[0-9]*-experimental' HEAD 2>/dev/null)" ||
  fail "HEAD must have an exact experimental release tag"
[[ "$version" =~ ^v[0-9]+[.][0-9]+[.][0-9]+-experimental$ ]] ||
  fail "release tag has unsupported format: ${version}"

readonly version
readonly commit="$(git rev-parse --verify HEAD^{commit})"
readonly source_date_epoch="$(git show -s --format=%ct HEAD)"
[[ "$source_date_epoch" =~ ^[1-9][0-9]*$ ]] || fail "Git commit timestamp is invalid"
readonly build_time="$(date -u --date="@${source_date_epoch}" +%Y-%m-%dT%H:%M:%SZ)"
readonly go_version="$(go env GOVERSION)"
readonly platform="linux/amd64"
readonly package_name="solis-${version}-${platform//\//-}"
readonly archive_name="${package_name}.tar.gz"
readonly checksum_name="${archive_name}.sha256"

if [[ -e "$output_dir" ]]; then
  [[ -d "$output_dir" ]] || fail "output path is not a directory: ${output_dir}"
  [[ ! -L "$output_dir" ]] || fail "output directory must not be a symbolic link: ${output_dir}"
else
  mkdir -m 0755 -- "$output_dir"
fi
output_dir="$(cd -- "$output_dir" && pwd -P)"

readonly archive_path="${output_dir}/${archive_name}"
readonly checksum_path="${output_dir}/${checksum_name}"
[[ ! -e "$archive_path" && ! -L "$archive_path" ]] || fail "release archive already exists: ${archive_path}"
[[ ! -e "$checksum_path" && ! -L "$checksum_path" ]] || fail "release checksum already exists: ${checksum_path}"

[[ -f "$object_relative_path" && ! -L "$object_relative_path" ]] ||
  fail "authentic embedded eBPF object is missing or unsafe: ${object_relative_path}"
readonly object_size="$(stat -c '%s' "$object_relative_path")"
((object_size > 0)) || fail "authentic embedded eBPF object is empty"
readonly object_magic="$(od -An -tx1 -N4 "$object_relative_path" | tr -d '[:space:]')"
[[ "$object_magic" == "7f454c46" ]] || fail "embedded eBPF object is not an ELF file"
readonly object_sha256="$(sha256sum "$object_relative_path" | awk '{print $1}')"

[[ -f "$install_relative_path" && ! -L "$install_relative_path" ]] ||
  fail "release install documentation is missing or unsafe: ${install_relative_path}"
[[ -f "$notice_relative_path" && ! -L "$notice_relative_path" ]] ||
  fail "release notice is missing or unsafe: ${notice_relative_path}"
[[ -f "$requirements_relative_path" && ! -L "$requirements_relative_path" ]] ||
  fail "release requirements are missing or unsafe: ${requirements_relative_path}"

echo "=== Verifying authentic embedded eBPF object ==="
GOWORK=off go test -mod=readonly ./internal/ebpf \
  -run '^TestGeneratedVMBlockMapKeyLayoutsMatchGoTypes$' \
  -count=1

readonly temporary_root="$(mktemp -d "${output_dir}/.solis-release-${version}-XXXXXXXX")"
archive_temporary=""
checksum_temporary=""

# cleanup stops script-owned work and removes only paths allocated by this run.
cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  rm -rf -- "$temporary_root"
  [[ -z "$archive_temporary" ]] || rm -f -- "$archive_temporary"
  [[ -z "$checksum_temporary" ]] || rm -f -- "$checksum_temporary"
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

readonly package_dir="${temporary_root}/${package_name}"
mkdir -m 0755 -- "$package_dir"

readonly ldflags="-s -w -buildid= -X ${version_package}.Version=${version} -X ${version_package}.GitCommit=${commit} -X ${version_package}.BuildTime=${build_time} -X ${version_package}.GoVersion=${go_version} -X ${version_package}.Platform=${platform}"

echo "=== Building ${package_name} ==="
CGO_ENABLED=0 \
GOOS=linux \
GOARCH=amd64 \
SOURCE_DATE_EPOCH="$source_date_epoch" \
GOWORK=off \
go build \
  -mod=readonly \
  -trimpath \
  -buildvcs=false \
  -ldflags "$ldflags" \
  -o "${package_dir}/solis" \
  ./cmd/solis
chmod 0755 "${package_dir}/solis"

"${package_dir}/solis" version --json >"${temporary_root}/version.json"
jq -e \
  --arg version "$version" \
  --arg commit "$commit" \
  --arg build_time "$build_time" \
  --arg go_version "$go_version" \
  --arg platform "$platform" '
  .version == $version
  and .git_commit == $commit
  and .build_time == $build_time
  and .go_version == $go_version
  and .platform == $platform
' "${temporary_root}/version.json" >/dev/null || fail "release binary build metadata is incorrect"

readonly binary_sha256="$(sha256sum "${package_dir}/solis" | awk '{print $1}')"
readonly binary_size="$(stat -c '%s' "${package_dir}/solis")"

cp -- "$install_relative_path" "${package_dir}/INSTALL.md"
chmod 0644 "${package_dir}/INSTALL.md"
cp -- "$notice_relative_path" "${package_dir}/NOTICE"
chmod 0644 "${package_dir}/NOTICE"
cp -- "$requirements_relative_path" "${package_dir}/REQUIREMENTS.md"
chmod 0644 "${package_dir}/REQUIREMENTS.md"

jq -n \
  --arg version "$version" \
  --arg git_commit "$commit" \
  --arg build_time "$build_time" \
  --argjson source_date_epoch "$source_date_epoch" \
  --arg go_version "$go_version" \
  --arg platform "$platform" \
  --arg object_path "$object_relative_path" \
  --arg object_sha256 "$object_sha256" \
  --argjson object_size "$object_size" \
  --arg binary_sha256 "$binary_sha256" \
  --argjson binary_size "$binary_size" '
  {
    schema_version: "1",
    version: $version,
    git_commit: $git_commit,
    build_time: $build_time,
    source_date_epoch: $source_date_epoch,
    go_version: $go_version,
    platform: $platform,
    binary: {
      path: "solis",
      sha256: $binary_sha256,
      size_bytes: $binary_size,
      cgo_enabled: false
    },
    embedded_ebpf_object: {
      source_path: $object_path,
      sha256: $object_sha256,
      size_bytes: $object_size,
      format: "ELF 64-bit little-endian eBPF"
    },
    reproducibility: {
      clean_exact_tag_required: true,
      trimpath: true,
      vcs_stamping_disabled: true,
      linker_build_id_empty: true,
      archive_metadata_normalized_to_source_date_epoch: true,
      caveat: "Byte-identical rebuilds require the same Go toolchain, module inputs, committed eBPF object, and release script."
    }
  }
' >"${package_dir}/RELEASE-METADATA.json"
chmod 0644 "${package_dir}/RELEASE-METADATA.json"

(
  cd "$package_dir"
  sha256sum solis INSTALL.md NOTICE REQUIREMENTS.md RELEASE-METADATA.json >SHA256SUMS
)
chmod 0644 "${package_dir}/SHA256SUMS"

find "$package_dir" -exec touch -h --date="@${source_date_epoch}" {} +

archive_temporary="$(mktemp "${output_dir}/.${archive_name}.XXXXXXXX")"
echo "=== Creating deterministic archive ==="
tar \
  --sort=name \
  --format=ustar \
  --mtime="@${source_date_epoch}" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -C "$temporary_root" \
  -cf - \
  "$package_name" |
  gzip -n -9 >"$archive_temporary"
chmod 0644 "$archive_temporary"

checksum_temporary="$(mktemp "${output_dir}/.${checksum_name}.XXXXXXXX")"
(
  cd "$output_dir"
  sha256sum "$(basename -- "$archive_temporary")" |
    awk -v archive="$archive_name" '{print $1 "  " archive}'
) >"$checksum_temporary"
chmod 0644 "$checksum_temporary"

mv -- "$archive_temporary" "$archive_path"
archive_temporary=""
mv -- "$checksum_temporary" "$checksum_path"
checksum_temporary=""

(
  cd "$output_dir"
  sha256sum -c "$checksum_name"
)

echo "Release archive: ${archive_path}"
echo "Release checksum: ${checksum_path}"
echo "Version: ${version}"
echo "Git commit: ${commit}"
echo "Build time: ${build_time}"
echo "Go version: ${go_version}"
echo "Platform: ${platform}"
