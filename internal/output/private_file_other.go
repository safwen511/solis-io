//go:build !linux

package output

import (
	"errors"
	"io"
)

func writePrivateAtomicFile(string, func(io.Writer) error) error {
	return errors.New("private atomic output requires Linux")
}
