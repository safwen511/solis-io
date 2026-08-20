package storagevm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/safwen511/solis-io/internal/ebpf"
	"github.com/safwen511/solis-io/internal/qemuio"
)

const (
	defaultCgroupRoot   = "/sys/fs/cgroup"
	defaultSysDevRoot   = "/sys/dev/block"
	defaultSysClassRoot = "/sys/class/block"
)

type fileReader interface {
	ReadFile(string) ([]byte, error)
	Inode(string) (uint64, error)
}

type osFileReader struct{}

// ReadFile reads file from its configured source.
func (osFileReader) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// Inode returns the filesystem inode used as the stable cgroup identity.
func (osFileReader) Inode(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return 0, errors.New("inode unavailable")
	}
	return stat.Ino, nil
}

type virshBlockSource interface {
	ReadBlockStats(context.Context, string, string) ([]byte, error)
}

type execVirshBlockSource struct{}

// ReadBlockStats reads block stats from its configured source.
func (execVirshBlockSource) ReadBlockStats(ctx context.Context, vm, uri string) ([]byte, error) {
	args := []string{}
	if strings.TrimSpace(uri) != "" {
		args = append(args, "-c", strings.TrimSpace(uri))
	}
	args = append(args, "domstats", vm, "--block")
	output, err := exec.CommandContext(ctx, "virsh", args...).CombinedOutput()
	if err != nil {
		message := strings.Join(strings.Fields(string(output)), " ")
		if len(message) > 512 {
			message = message[:512] + "..."
		}
		if message == "" {
			return nil, fmt.Errorf("virsh domstats %s --block: %w", vm, err)
		}
		return nil, fmt.Errorf("virsh domstats %s --block: %w: %s", vm, err, message)
	}
	return output, nil
}

type qemuIOSource interface {
	Read(string) (qemuio.Counters, error)
}

type procQEMUIOSource struct{}

// Read reads bounded source data and propagates access failures.
func (procQEMUIOSource) Read(pid string) (qemuio.Counters, error) {
	return qemuio.ReadProcessIO(pid)
}

type qemuIdentitySource interface {
	Validate(ebpf.VMBlockCgroupMapping) (ebpf.QEMUProcessIdentity, error)
}

type procQEMUIdentitySource struct{}

// Validate reports whether the receiver satisfies its required invariants.
func (procQEMUIdentitySource) Validate(mapping ebpf.VMBlockCgroupMapping) (ebpf.QEMUProcessIdentity, error) {
	return ebpf.ValidateMappedQEMUProcess(mapping)
}

type windowWaiter interface {
	Wait(context.Context, time.Duration, time.Duration) error
}

type timerWindowWaiter struct{}

// Wait completes wait and returns any failure to its caller.
func (timerWindowWaiter) Wait(ctx context.Context, duration, interval time.Duration) error {
	remaining := duration
	for remaining > 0 {
		step := interval
		if step > remaining {
			step = remaining
		}
		timer := time.NewTimer(step)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			remaining -= step
		}
	}
	return nil
}

type deviceResolver interface {
	Resolve(string) HostDevice
}

type sysfsDeviceResolver struct {
	sysDevRoot   string
	sysClassRoot string
}

var physicalLikeDeviceName = regexp.MustCompile(`^(?:nvme[0-9]+n[0-9]+|sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+)$`)

// Resolve resolves source identities from validated inputs and reports unsupported layouts.
func (resolver sysfsDeviceResolver) Resolve(deviceID string) HostDevice {
	device := HostDevice{DeviceID: deviceID, LayerKind: "unknown"}
	target, err := filepath.EvalSymlinks(filepath.Join(resolver.sysDevRoot, deviceID))
	if err != nil {
		return device
	}
	name := filepath.Base(target)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return device
	}
	device.DeviceName = name
	device.SourcePath = filepath.Join("/dev", name)
	if strings.HasPrefix(name, "dm-") {
		uuid, err := os.ReadFile(filepath.Join(resolver.sysClassRoot, name, "dm", "uuid"))
		if err != nil {
			return device
		}
		switch {
		case strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(uuid))), "CRYPT-"):
			device.LayerKind = "dmcrypt"
		case strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(uuid))), "LVM-"):
			device.LayerKind = "lvm"
		}
		return device
	}
	if _, err := os.Stat(filepath.Join(resolver.sysClassRoot, name)); err == nil && physicalLikeDeviceName.MatchString(name) {
		device.LayerKind = "physical"
	}
	return device
}
