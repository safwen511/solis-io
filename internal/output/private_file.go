package output

import (
	"errors"
	"io"
)

// ErrParentDirectoryMissing identifies an output whose parent directory must
// be created explicitly by the operator before private atomic writing.
var ErrParentDirectoryMissing = errors.New("parent_directory_missing")

// WritePrivateAtomicFile renders one private file and atomically replaces the
// destination. Platform-specific implementations must refuse symbolic-link
// traversal and keep temporary files in the destination directory.
func WritePrivateAtomicFile(path string, render func(io.Writer) error) error {
	if render == nil {
		return errors.New("private output renderer is nil")
	}
	return writePrivateAtomicFile(path, render)
}
