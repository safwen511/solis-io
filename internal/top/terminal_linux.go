//go:build linux

package top

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// IsTerminal reports whether file refers to a Linux terminal.
func IsTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	return err == nil
}

// EnterRawMode enables character-at-a-time input while preserving signal
// generation so Ctrl-C still follows the normal context cancellation path.
func EnterRawMode(file *os.File) (func() error, error) {
	if file == nil {
		return nil, fmt.Errorf("terminal input is required")
	}
	fd := int(file.Fd())
	original, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, fmt.Errorf("read terminal settings: %w", err)
	}
	raw := *original
	raw.Iflag &^= unix.ICRNL | unix.IXON
	raw.Lflag &^= unix.ECHO | unix.ICANON
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil, fmt.Errorf("enable terminal raw mode: %w", err)
	}
	restore := func() error {
		if err := unix.IoctlSetTermios(fd, unix.TCSETS, original); err != nil {
			return fmt.Errorf("restore terminal settings: %w", err)
		}
		return nil
	}
	return restore, nil
}
