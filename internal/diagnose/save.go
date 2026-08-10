package diagnose

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/output"
)

const diagnosisTimestampFormat = "20060102T150405Z"

// OutputOptions controls whether a diagnosis is printed or saved.
type OutputOptions struct {
	Path      string
	Directory string
	JSON      bool
}

// WriteOutput renders the diagnosis once, then writes it to stdout or a file.
func WriteOutput(stdout io.Writer, report Report, options OutputOptions, now time.Time) (string, error) {
	if options.Path != "" && options.Directory != "" {
		return "", fmt.Errorf("--output and --output-dir cannot be used together")
	}

	var rendered bytes.Buffer
	if options.JSON {
		if err := WriteJSON(&rendered, report); err != nil {
			return "", err
		}
	} else {
		if err := Write(&rendered, report); err != nil {
			return "", err
		}
	}

	if options.Path == "" && options.Directory == "" {
		_, err := stdout.Write(rendered.Bytes())
		return "", err
	}

	path := options.Path
	if options.Directory != "" {
		extension := ".txt"
		if options.JSON {
			extension = ".json"
		}
		filename := fmt.Sprintf(
			"diagnosis-%s-%s-%s%s",
			FormatUTCTimestamp(now),
			SanitizeFilenamePart(report.Inputs.Victim),
			SanitizeFilenamePart(report.Inputs.Suspect),
			extension,
		)
		path = filepath.Join(options.Directory, filename)
	}

	if err := output.WritePrivateAtomicFile(path, func(dst io.Writer) error {
		_, err := dst.Write(rendered.Bytes())
		return err
	}); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(stdout, "diagnosis written to %s\n", path); err != nil {
		return path, err
	}
	return path, nil
}

// FormatUTCTimestamp formats artifact timestamps in compact UTC form.
func FormatUTCTimestamp(value time.Time) string {
	return value.UTC().Format(diagnosisTimestampFormat)
}

// SanitizeFilenamePart replaces characters outside the portable Solis name set.
func SanitizeFilenamePart(value string) string {
	var sanitized strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
			sanitized.WriteRune(char)
		case char >= 'A' && char <= 'Z':
			sanitized.WriteRune(char)
		case char >= '0' && char <= '9':
			sanitized.WriteRune(char)
		case char == '-' || char == '_':
			sanitized.WriteRune(char)
		default:
			sanitized.WriteByte('_')
		}
	}
	if sanitized.Len() == 0 {
		return "_"
	}
	return sanitized.String()
}
