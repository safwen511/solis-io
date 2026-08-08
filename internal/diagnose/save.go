package diagnose

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const diagnosisTimestampFormat = "20060102T150405Z"

// OutputOptions controls whether a diagnosis is printed or saved.
type OutputOptions struct {
	Path      string
	Directory string
}

// WriteOutput renders the diagnosis once, then writes it to stdout or a file.
func WriteOutput(stdout io.Writer, report Report, options OutputOptions, now time.Time) (string, error) {
	if options.Path != "" && options.Directory != "" {
		return "", fmt.Errorf("--output and --output-dir cannot be used together")
	}

	var rendered bytes.Buffer
	if err := Write(&rendered, report); err != nil {
		return "", err
	}

	if options.Path == "" && options.Directory == "" {
		_, err := stdout.Write(rendered.Bytes())
		return "", err
	}

	path := options.Path
	exclusive := false
	if options.Directory != "" {
		filename := fmt.Sprintf(
			"diagnosis-%s-%s-%s.txt",
			FormatUTCTimestamp(now),
			SanitizeFilenamePart(report.Inputs.Victim),
			SanitizeFilenamePart(report.Inputs.Suspect),
		)
		path = filepath.Join(options.Directory, filename)
		exclusive = true
	}

	if err := writeDiagnosisFile(path, rendered.Bytes(), exclusive); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(stdout, "diagnosis written to %s\n", path); err != nil {
		return path, err
	}
	return path, nil
}

func writeDiagnosisFile(path string, data []byte, exclusive bool) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create diagnosis output directory %q: %w", parent, err)
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if exclusive {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return fmt.Errorf("create diagnosis output %q: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write diagnosis output %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close diagnosis output %q: %w", path, err)
	}
	return nil
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
