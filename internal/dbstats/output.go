package dbstats

import (
	"io"

	"github.com/safwen511/solis-io/internal/observability"
)

func WriteJSON(dst io.Writer, status observability.DBStatus) error {
	return observability.WriteDBStatus(dst, status)
}
