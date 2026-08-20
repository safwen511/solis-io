#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
package_dir="$(cd -- "${script_dir}/.." && pwd)"
generated_dir="${script_dir}/generated"
compiler="${BPF2GO_CC:-clang}"

# Fail before generation when the pinned compiler or packaged headers are absent.
if ! command -v "${compiler}" >/dev/null 2>&1; then
  echo "missing eBPF generator compiler: ${compiler}" >&2
  echo "use build/ebpf/Dockerfile or install the generator toolchain outside target hosts" >&2
  exit 1
fi

project_header_dir="${script_dir}/include"
libbpf_include_root="/usr/include"
libbpf_header_dir="/usr/include/bpf"
helpers_header="${libbpf_header_dir}/bpf_helpers.h"
helper_defs_header="${libbpf_header_dir}/bpf_helper_defs.h"
tracing_header="${libbpf_header_dir}/bpf_tracing.h"
core_read_header="${libbpf_header_dir}/bpf_core_read.h"

required_headers=(
  "${project_header_dir}/vmlinux_min.h"
  "${helpers_header}"
  "${helper_defs_header}"
  "${tracing_header}"
  "${core_read_header}"
)

missing_headers=()
for required_header in "${required_headers[@]}"; do
  if [[ ! -f "${required_header}" ]]; then
    missing_headers+=("${required_header}")
  fi
done

# Report every missing dependency in one preflight result for reproducible fixes.
if (( ${#missing_headers[@]} > 0 )); then
  for missing_header in "${missing_headers[@]}"; do
    echo "missing eBPF generator header: ${missing_header}" >&2
  done
  echo "eBPF generator include preflight:" >&2
  echo "  project headers: ${project_header_dir}" >&2
  echo "  packaged include root: ${libbpf_include_root}" >&2
  echo "  packaged libbpf headers: ${libbpf_header_dir}" >&2
  echo "  required helpers header: ${helpers_header}" >&2
  echo "  required helper definitions: ${helper_defs_header}" >&2
  echo "  required tracing header: ${tracing_header}" >&2
  echo "  required CO-RE read header: ${core_read_header}" >&2
  echo "  compiler: $(command -v "${compiler}")" >&2
  echo "use build/ebpf/Dockerfile, which installs the libbpf-dev package" >&2
  exit 1
fi

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/solis-vmblock-bpf.XXXXXX")"
trap 'rm -rf -- "${temporary_dir}"' EXIT

# Generate into an isolated directory so an interrupted build cannot replace
# the authentic embedded object with a partial file.
(
  cd -- "${package_dir}"
  GOPACKAGE=ebpf go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 \
    -cc "${compiler}" \
    -no-strip \
    -target bpfel \
    -output-dir "${temporary_dir}" \
    vmblock "${script_dir}/vm_block_latency.bpf.c" -- \
    -O2 -g \
    -I"${project_header_dir}" \
    -I"${libbpf_include_root}"
)

object_path="${temporary_dir}/vmblock_bpfel.o"
if [[ ! -s "${object_path}" ]]; then
  echo "bpf2go did not produce ${object_path}" >&2
  exit 1
fi

# Replace the embedded artifact only after bpf2go produced a non-empty ELF.
mkdir -p -- "${generated_dir}"
install -m 0644 "${object_path}" "${generated_dir}/vm_block_latency_bpfel.o"
echo "generated ${generated_dir}/vm_block_latency_bpfel.o"
