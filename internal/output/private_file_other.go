//go:build !linux

package output

import (
	"errors"
	"io"
)

// writePrivateAtomicFile rejects hardened output on platforms without the required openat safety.
func writePrivateAtomicFile(string, func(io.Writer) error) error {
	return errors.New("private atomic output requires Linux")
}
