package ebpf

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
)

var ErrVMBlockObjectUnavailable = errors.New("embedded typed-BTF host request-latency object is unavailable")

const vmBlockBPFObjectPath = "bpf/generated/vm_block_latency_bpfel.o"

// The generated directory always contains its README, allowing normal builds
// before the authentic ELF object is generated. No placeholder object is
// embedded and no successful load is fabricated.
//
//go:embed bpf/generated/*
var vmBlockBPFArtifacts embed.FS

// embeddedVMBlockObject builds embedded VM block object and returns an error when validation or
// source access fails.
func embeddedVMBlockObject() ([]byte, error) {
	data, err := vmBlockBPFArtifacts.ReadFile(vmBlockBPFObjectPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrVMBlockObjectUnavailable
		}
		return nil, fmt.Errorf("read embedded VM block request-latency object: %w", err)
	}
	if len(data) == 0 {
		return nil, ErrVMBlockObjectUnavailable
	}
	return data, nil
}

// runtimeVMBlockKernelSource builds the runtime vm block kernel source workflow.
func runtimeVMBlockKernelSource() VMBlockKernelSource {
	return newCiliumVMBlockKernelSource()
}
