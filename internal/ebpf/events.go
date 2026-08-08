package ebpf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const defaultEventsRoot = "/sys/kernel/tracing/events/block"

var (
	// ErrTracepointFormatPermission is returned when tracepoint metadata is protected.
	ErrTracepointFormatPermission = errors.New("permission denied reading tracepoint format; try running with sudo")
	formatFieldPattern            = regexp.MustCompile(`^\s*field:(.+?);\s*offset:(\d+);\s*size:(\d+);\s*signed:([01]);\s*$`)
	usefulBlockFields             = map[string]bool{
		"dev":       true,
		"sector":    true,
		"nr_sector": true,
		"rwbs":      true,
		"comm":      true,
		"cmd":       true,
	}
)

// TracepointFormat describes one kernel tracepoint format file.
type TracepointFormat struct {
	Name   string
	ID     uint64
	Fields []TracepointField
}

// TracepointField describes one field in a tracepoint format.
type TracepointField struct {
	Name   string
	Type   string
	Offset uint64
	Size   uint64
	Signed bool
}

// LoadBlockFormats reads the issue and completion tracepoint formats only.
func LoadBlockFormats() ([]TracepointFormat, error) {
	return loadBlockFormats(defaultEventsRoot)
}

func loadBlockFormats(eventsRoot string) ([]TracepointFormat, error) {
	formats := make([]TracepointFormat, 0, 2)
	for _, event := range []string{"block_rq_issue", "block_rq_complete"} {
		path := filepath.Join(eventsRoot, event, "format")
		file, err := os.Open(path)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				return nil, ErrTracepointFormatPermission
			}
			return nil, fmt.Errorf("read tracepoint format %s: %w", path, err)
		}
		format, parseErr := ParseTracepointFormat(file)
		closeErr := file.Close()
		if parseErr != nil {
			return nil, fmt.Errorf("parse tracepoint format %s: %w", path, parseErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close tracepoint format %s: %w", path, closeErr)
		}
		formats = append(formats, format)
	}
	return formats, nil
}

// ParseTracepointFormat parses Linux tracefs format metadata.
func ParseTracepointFormat(src io.Reader) (TracepointFormat, error) {
	var format TracepointFormat
	var haveID bool
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "name:"):
			format.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		case strings.HasPrefix(line, "ID:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "ID:"))
			id, err := strconv.ParseUint(value, 10, 64)
			if err != nil || id == 0 {
				return TracepointFormat{}, fmt.Errorf("invalid event ID %q", value)
			}
			format.ID = id
			haveID = true
		case strings.HasPrefix(line, "field:"):
			field, err := parseTracepointField(line)
			if err != nil {
				return TracepointFormat{}, err
			}
			format.Fields = append(format.Fields, field)
		}
	}
	if err := scanner.Err(); err != nil {
		return TracepointFormat{}, fmt.Errorf("scan format: %w", err)
	}
	if format.Name == "" {
		return TracepointFormat{}, errors.New("tracepoint name is missing")
	}
	if !haveID {
		return TracepointFormat{}, errors.New("tracepoint event ID is missing")
	}
	if len(format.Fields) == 0 {
		return TracepointFormat{}, errors.New("tracepoint fields are missing")
	}
	return format, nil
}

func parseTracepointField(line string) (TracepointField, error) {
	matches := formatFieldPattern.FindStringSubmatch(line)
	if len(matches) != 5 {
		return TracepointField{}, fmt.Errorf("invalid tracepoint field line %q", line)
	}
	fieldType, fieldName, err := splitFieldDeclaration(strings.TrimSpace(matches[1]))
	if err != nil {
		return TracepointField{}, err
	}
	offset, _ := strconv.ParseUint(matches[2], 10, 64)
	size, _ := strconv.ParseUint(matches[3], 10, 64)
	return TracepointField{
		Name:   fieldName,
		Type:   fieldType,
		Offset: offset,
		Size:   size,
		Signed: matches[4] == "1",
	}, nil
}

func splitFieldDeclaration(declaration string) (string, string, error) {
	separator := strings.LastIndexAny(declaration, " \t")
	if separator < 1 || separator == len(declaration)-1 {
		return "", "", fmt.Errorf("invalid field declaration %q", declaration)
	}
	fieldType := strings.TrimSpace(declaration[:separator])
	fieldName := strings.TrimSpace(declaration[separator+1:])

	stars := ""
	for strings.HasPrefix(fieldName, "*") {
		stars += "*"
		fieldName = strings.TrimPrefix(fieldName, "*")
	}
	if stars != "" {
		fieldType = strings.TrimSpace(fieldType + " " + stars)
	}
	if array := strings.IndexByte(fieldName, '['); array >= 0 {
		fieldType += fieldName[array:]
		fieldName = fieldName[:array]
	}
	if bitfield := strings.IndexByte(fieldName, ':'); bitfield >= 0 {
		fieldName = fieldName[:bitfield]
	}
	if fieldType == "" || fieldName == "" {
		return "", "", fmt.Errorf("invalid field declaration %q", declaration)
	}
	return fieldType, fieldName, nil
}

func isUsefulBlockField(name string) bool {
	return usefulBlockFields[name]
}
