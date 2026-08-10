//go:build linux

package output

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const privateOutputMode = 0o600

func writePrivateAtomicFile(path string, render func(io.Writer) error) (err error) {
	if path == "" {
		return errors.New("output path is empty")
	}
	absolutePath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolve output path %q: %w", path, err)
	}
	parent := filepath.Dir(absolutePath)
	base := filepath.Base(absolutePath)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return fmt.Errorf("output path %q does not name a file", path)
	}

	// Parent directories must already exist. The no-follow openat walk pins the
	// destination directory before any target check or temporary-file write,
	// avoiding a check-then-MkdirAll symlink race in sudo-facing commands.
	parentFD, err := openDirectoryNoSymlinks(parent)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := unix.Close(parentFD); closeErr != nil && err == nil {
			err = fmt.Errorf("close output directory %q: %w", parent, closeErr)
		}
	}()

	if err := rejectUnsafeOutputTargetAt(parentFD, absolutePath, base); err != nil {
		return err
	}
	temporaryName, temporaryFD, err := createPrivateTemporaryAt(parentFD)
	if err != nil {
		return fmt.Errorf("create temporary output in %q: %w", parent, err)
	}
	temporaryPath := filepath.Join(parent, temporaryName)
	temporary := os.NewFile(uintptr(temporaryFD), temporaryPath)
	if temporary == nil {
		_ = unix.Close(temporaryFD)
		_ = unix.Unlinkat(parentFD, temporaryName, 0)
		return fmt.Errorf("create temporary output handle in %q", parent)
	}
	temporaryExists := true
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		}
		if temporaryExists {
			_ = unix.Unlinkat(parentFD, temporaryName, 0)
		}
	}()

	if err := temporary.Chmod(privateOutputMode); err != nil {
		return fmt.Errorf("secure temporary output %q: %w", temporaryPath, err)
	}
	if err := render(temporary); err != nil {
		return fmt.Errorf("write temporary output %q: %w", temporaryPath, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary output %q: %w", temporaryPath, err)
	}
	if err := temporary.Close(); err != nil {
		temporary = nil
		return fmt.Errorf("close temporary output %q: %w", temporaryPath, err)
	}
	temporary = nil

	// Recheck the entry immediately before rename. renameat replaces a racing
	// symlink itself and never follows it; directory and other non-regular
	// entries are rejected when observed.
	if err := rejectUnsafeOutputTargetAt(parentFD, absolutePath, base); err != nil {
		return err
	}
	if err := unix.Renameat(parentFD, temporaryName, parentFD, base); err != nil {
		return fmt.Errorf("finalize output %q: %w", absolutePath, err)
	}
	temporaryExists = false
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("sync output directory %q: %w", parent, err)
	}
	return nil
}

func openDirectoryNoSymlinks(parent string) (int, error) {
	currentFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open filesystem root for output %q: %w", parent, err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(parent, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(currentFD, component, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			_ = unix.Close(currentFD)
			if errors.Is(err, unix.ENOENT) {
				return -1, fmt.Errorf("%w: output parent component %q does not exist", ErrParentDirectoryMissing, component)
			}
			return -1, fmt.Errorf("inspect output parent component %q: %w", component, err)
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			_ = unix.Close(currentFD)
			return -1, fmt.Errorf("output parent component %q is a symbolic link; refusing to follow it", component)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(currentFD)
			return -1, fmt.Errorf("output parent component %q is not a directory", component)
		}
		nextFD, err := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			_ = unix.Close(currentFD)
			if errors.Is(err, unix.ENOENT) {
				return -1, fmt.Errorf("%w: output parent component %q disappeared", ErrParentDirectoryMissing, component)
			}
			return -1, fmt.Errorf("open output parent component %q without following links: %w", component, err)
		}
		_ = unix.Close(currentFD)
		currentFD = nextFD
	}
	return currentFD, nil
}

func rejectUnsafeOutputTargetAt(parentFD int, path, base string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect output %q: %w", path, err)
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return fmt.Errorf("output %q is a symbolic link; refusing to follow it", path)
	case unix.S_IFREG:
		return nil
	default:
		return fmt.Errorf("output %q is not a regular file", path)
	}
}

func createPrivateTemporaryAt(parentFD int) (string, int, error) {
	for attempt := 0; attempt < 128; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", -1, err
		}
		name := ".solis-tmp-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, privateOutputMode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", -1, err
		}
		return name, fd, nil
	}
	return "", -1, errors.New("could not allocate a unique temporary output file")
}
