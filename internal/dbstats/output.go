package dbstats

import (
	"io"

	"github.com/safwen511/solis-io/internal/observability"
)

// WriteJSON renders JSON in the package's stable operator-facing format.
func WriteJSON(dst io.Writer, status observability.DBStatus) error {
	return observability.WriteDBStatus(dst, status)
}
