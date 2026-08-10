package storagevm

import (
	"io"

	"github.com/safwen511/solis-io/internal/output"
)

// WriteJSONFile atomically replaces one regular output file with a private
// JSON report. The parent directory must already exist; symbolic links are
// rejected and never followed.
func WriteJSONFile(path string, report VMStorageStatsReport) error {
	return output.WritePrivateAtomicFile(path, func(writer io.Writer) error {
		return WriteJSON(writer, report)
	})
}
