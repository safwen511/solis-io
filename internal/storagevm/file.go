package storagevm

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteJSONFile atomically replaces one regular output file with a private
// JSON report. Existing symlink targets are rejected and never followed.
func WriteJSONFile(path string, report VMStorageStatsReport) (err error) {
	path = filepath.Clean(path)
	parent := filepath.Dir(path)
	if parent != "." {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}
	if err := rejectUnsafeOutputTarget(path); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(parent, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary output in %q: %w", parent, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary output %q: %w", temporaryPath, err)
	}
	if err := WriteJSON(temporary, report); err != nil {
		return fmt.Errorf("write temporary output %q: %w", temporaryPath, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary output %q: %w", temporaryPath, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary output %q: %w", temporaryPath, err)
	}

	// Recheck immediately before rename. Rename replaces a regular target or a
	// racing symlink itself; it never follows the symlink to its destination.
	if err := rejectUnsafeOutputTarget(path); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("finalize output %q: %w", path, err)
	}
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("sync output directory %q: %w", parent, err)
	}
	return nil
}

func rejectUnsafeOutputTarget(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect output %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output %q is a symbolic link; refusing to follow it", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("output %q is not a regular file", path)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
