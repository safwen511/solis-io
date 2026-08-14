//go:build linux

package top

import (
	"fmt"
	"io"
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

// TerminalDimensions returns the current terminal cell dimensions for writer.
// It is intentionally queried for every application frame so a resize does
// not require a signal handler or retain stale layout state.
func TerminalDimensions(writer io.Writer) (width, height int, available bool) {
	file, ok := writer.(*os.File)
	if !ok || file == nil {
		return 0, 0, false
	}
	size, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ)
	if err != nil || size.Col == 0 || size.Row == 0 {
		return 0, 0, false
	}
	return int(size.Col), int(size.Row), true
}

// EnterApplicationScreen switches an interactive dashboard to the terminal's
// alternate screen and hides the cursor. Repeated dashboard redraws therefore
// do not accumulate in normal shell scrollback. The returned function always
// restores the cursor and the primary screen.
func EnterApplicationScreen(dst io.Writer) (func() error, error) {
	if dst == nil {
		return nil, fmt.Errorf("terminal output is required")
	}
	if _, err := fmt.Fprint(dst, "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H"); err != nil {
		return nil, fmt.Errorf("enter terminal application screen: %w", err)
	}
	restore := func() error {
		if _, err := fmt.Fprint(dst, "\x1b[?25h\x1b[?1049l"); err != nil {
			return fmt.Errorf("restore terminal application screen: %w", err)
		}
		return nil
	}
	return restore, nil
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
