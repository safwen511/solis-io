#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
package_dir="$(cd -- "${script_dir}/.." && pwd)"
generated_dir="${script_dir}/generated"
compiler="${BPF2GO_CC:-clang}"

if ! command -v "${compiler}" >/dev/null 2>&1; then
  echo "missing eBPF generator compiler: ${compiler}" >&2
  echo "use build/ebpf/Dockerfile or install the generator toolchain outside target hosts" >&2
  exit 1
fi

module_dir="$(go list -m -f '{{.Dir}}' github.com/cilium/ebpf)"
header_dir="${module_dir}/examples/headers"
temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/solis-vmblock-bpf.XXXXXX")"
trap 'rm -rf -- "${temporary_dir}"' EXIT

(
  cd -- "${package_dir}"
  GOPACKAGE=ebpf go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 \
    -cc "${compiler}" \
    -no-strip \
    -target bpfel \
    -output-dir "${temporary_dir}" \
    vmblock "${script_dir}/vm_block_latency.bpf.c" -- \
    -O2 -g \
    -I"${script_dir}/include" \
    -I"${header_dir}"
)

object_path="${temporary_dir}/vmblock_bpfel.o"
if [[ ! -s "${object_path}" ]]; then
  echo "bpf2go did not produce ${object_path}" >&2
  exit 1
fi

mkdir -p -- "${generated_dir}"
install -m 0644 "${object_path}" "${generated_dir}/vm_block_latency_bpfel.o"
echo "generated ${generated_dir}/vm_block_latency_bpfel.o"
