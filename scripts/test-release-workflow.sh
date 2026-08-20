#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd -- "${script_dir}/.." && pwd)"
readonly fixture_version="v9.9.9-experimental"
readonly fixture_package="solis-${fixture_version}-linux-amd64"
readonly fixture_archive="${fixture_package}.tar.gz"

# fail writes one bounded error message and terminates the script unsuccessfully.
fail() {
  echo "Error: $*" >&2
  exit 1
}

for command in awk cmp find git go grep jq mktemp rm sha256sum sort stat tar; do
  command -v "$command" >/dev/null 2>&1 || fail "required release-test command is missing: ${command}"
done

test_root="$(mktemp -d /tmp/solis-release-workflow-test-XXXXXXXX)"
# cleanup stops script-owned work and removes only paths allocated by this run.
cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  rm -rf -- "$test_root"
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 0755 -- \
  "${test_root}/repo" \
  "${test_root}/output-one" \
  "${test_root}/output-two" \
  "${test_root}/extracted"

tar \
  --exclude='./.git' \
  --exclude='./dist' \
  --exclude='./solis' \
  --exclude='./lab/reports/captures' \
  --exclude='__pycache__' \
  -C "$repo_root" \
  -cf - \
  . |
  tar -C "${test_root}/repo" -xf -

cd "${test_root}/repo"
git init -q
git config user.name 'Solis Release Test'
git config user.email 'release-test@example.invalid'
git add -A
GIT_AUTHOR_DATE='2026-08-13T12:00:00Z' \
GIT_COMMITTER_DATE='2026-08-13T12:00:00Z' \
git commit -q -m 'release workflow fixture'

untagged_status=0
GOCACHE="${test_root}/go-cache" \
  ./scripts/build-release.sh --output-dir "${test_root}/untagged" \
  >"${test_root}/untagged.stdout" 2>"${test_root}/untagged.stderr" || untagged_status=$?
((untagged_status != 0)) || fail "release builder accepted an untagged commit"
grep -F 'HEAD must have an exact experimental release tag' "${test_root}/untagged.stderr" >/dev/null ||
  fail "untagged release failure was not clear"

git tag -a "$fixture_version" -m 'release workflow fixture'

GOCACHE="${test_root}/go-cache" \
  ./scripts/build-release.sh --output-dir "${test_root}/output-one" \
  >"${test_root}/build-one.log"
GOCACHE="${test_root}/go-cache" \
  ./scripts/build-release.sh --output-dir "${test_root}/output-two" \
  >"${test_root}/build-two.log"

readonly archive_one="${test_root}/output-one/${fixture_archive}"
readonly archive_two="${test_root}/output-two/${fixture_archive}"
readonly checksum_one="${archive_one}.sha256"
readonly checksum_two="${archive_two}.sha256"

[[ -f "$archive_one" && -f "$archive_two" ]] || fail "release archives were not produced"
[[ -f "$checksum_one" && -f "$checksum_two" ]] || fail "release checksums were not produced"
cmp -s "$archive_one" "$archive_two" || fail "repeated release archives are not byte-identical"
cmp -s "$checksum_one" "$checksum_two" || fail "repeated release checksums are not byte-identical"

(
  cd "${test_root}/output-one"
  sha256sum -c "${fixture_archive}.sha256" >/dev/null
)

tar -xzf "$archive_one" -C "${test_root}/extracted"
readonly extracted_package="${test_root}/extracted/${fixture_package}"
[[ -d "$extracted_package" ]] || fail "release package root is missing"

readonly entries="$(find "$extracted_package" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)"
readonly expected_entries=$'INSTALL.md\nLICENSE\nNOTICE\nRELEASE-METADATA.json\nREQUIREMENTS.md\nSHA256SUMS\nsolis'
[[ "$entries" == "$expected_entries" ]] || fail "release package has unexpected entries"

[[ "$(stat -c '%a' "${extracted_package}/solis")" == "755" ]] || fail "release binary mode is not 0755"
for file in INSTALL.md LICENSE NOTICE RELEASE-METADATA.json REQUIREMENTS.md SHA256SUMS; do
  [[ "$(stat -c '%a' "${extracted_package}/${file}")" == "644" ]] ||
    fail "release metadata mode is not 0644: ${file}"
done

(
  cd "$extracted_package"
  sha256sum -c SHA256SUMS >/dev/null
)

readonly commit="$(git rev-parse HEAD)"
readonly object_sha256="$(sha256sum internal/ebpf/bpf/generated/vm_block_latency_bpfel.o | awk '{print $1}')"
"${extracted_package}/solis" version --json >"${test_root}/version.json"
jq -e \
  --arg version "$fixture_version" \
  --arg commit "$commit" '
  .version == $version
  and .git_commit == $commit
  and .build_time == "2026-08-13T12:00:00Z"
  and (.go_version | startswith("go"))
  and .platform == "linux/amd64"
' "${test_root}/version.json" >/dev/null || fail "release binary identity is incorrect"

jq -e \
  --arg version "$fixture_version" \
  --arg commit "$commit" \
  --arg object_sha256 "$object_sha256" '
  .version == $version
  and .git_commit == $commit
  and .platform == "linux/amd64"
  and .license == "GPL-3.0-only"
  and .binary.cgo_enabled == false
  and .embedded_ebpf_object.sha256 == $object_sha256
  and .reproducibility.clean_exact_tag_required == true
  and .reproducibility.trimpath == true
  and .reproducibility.linker_build_id_empty == true
' "${extracted_package}/RELEASE-METADATA.json" >/dev/null ||
  fail "release metadata is incorrect"

echo "release workflow tests: PASS"
