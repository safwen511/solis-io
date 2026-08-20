package qemuio

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const defaultProcPath = "/proc"

var procIOFields = []string{
	"rchar",
	"wchar",
	"syscr",
	"syscw",
	"read_bytes",
	"write_bytes",
	"cancelled_write_bytes",
}

// Parse reads Linux /proc/<pid>/io content.
func Parse(r io.Reader) (Counters, error) {
	values := make(map[string]uint64, len(procIOFields))
	found := make(map[string]bool, len(procIOFields))
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if !isProcIOField(name) {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil {
			return Counters{}, fmt.Errorf("parse proc io field %s: %w", name, err)
		}
		values[name] = value
		found[name] = true
	}
	if err := scanner.Err(); err != nil {
		return Counters{}, fmt.Errorf("scan proc io: %w", err)
	}

	var missing []string
	for _, name := range procIOFields {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Counters{}, fmt.Errorf("missing proc io fields: %s", strings.Join(missing, ", "))
	}

	return Counters{
		RChar:               values["rchar"],
		WChar:               values["wchar"],
		Syscr:               values["syscr"],
		Syscw:               values["syscw"],
		ReadBytes:           values["read_bytes"],
		WriteBytes:          values["write_bytes"],
		CancelledWriteBytes: values["cancelled_write_bytes"],
	}, nil
}

// isProcIOField reports whether proc io field.
func isProcIOField(name string) bool {
	for _, candidate := range procIOFields {
		if name == candidate {
			return true
		}
	}
	return false
}

// readProcessIO reads process io from its configured source.
func readProcessIO(pid string) (Counters, error) {
	return readProcessIOFrom(pid, defaultProcPath)
}

// ReadProcessIO reads one QEMU process's cumulative procfs I/O counters.
func ReadProcessIO(pid string) (Counters, error) {
	return readProcessIO(pid)
}

// IsPermissionDenied reports whether a procfs read failed due to permissions.
func IsPermissionDenied(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "permission denied reading ")
}

// readProcessIOFrom reads process io from from its configured source.
func readProcessIOFrom(pid, procPath string) (Counters, error) {
	pid = strings.TrimSpace(pid)
	if pid == "" || pid == "-" {
		return Counters{}, fmt.Errorf("QEMU PID unavailable")
	}

	path := filepath.Join(procPath, pid, "io")
	file, err := os.Open(path)
	if err != nil {
		return Counters{}, formatProcessIOReadError(path, err)
	}
	defer file.Close()

	counters, err := Parse(file)
	if err != nil {
		return Counters{}, fmt.Errorf("read %s: %w", path, err)
	}
	return counters, nil
}

// formatProcessIOReadError formats process io read error using the stable output contract.
func formatProcessIOReadError(path string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("permission denied reading %s; try running with sudo", path)
	}
	if pathErr, ok := err.(*os.PathError); ok {
		err = pathErr.Err
	}
	return fmt.Errorf("read %s: %w", path, err)
}
