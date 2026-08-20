package hostmetrics

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// parsePSI parses and validates psi.
func parsePSI(data []byte, source string) (PSIResourceStatus, error) {
	result := PSIResourceStatus{Availability: measured(source)}
	var someFound, fullFound bool
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		values, err := parsePSIValues(fields, source)
		if err != nil {
			return PSIResourceStatus{}, err
		}
		switch fields[0] {
		case "some":
			result.Some = values
			someFound = true
		case "full":
			result.Full = values
			fullFound = true
		}
	}
	if !someFound {
		return PSIResourceStatus{}, errors.New("PSI some line not found")
	}
	if !fullFound {
		result.Full.Availability = unavailable(source, errors.New("PSI full line not available"))
	}
	return result, nil
}

// parsePSIValues parses and validates psi values.
func parsePSIValues(fields []string, source string) (PSIValues, error) {
	if len(fields) < 4 {
		return PSIValues{}, fmt.Errorf("PSI %q line has too few fields", fields[0])
	}
	values := make(map[string]float64, 3)
	for _, field := range fields[1:] {
		key, value, found := strings.Cut(field, "=")
		if !found || key == "total" {
			continue
		}
		if key != "avg10" && key != "avg60" && key != "avg300" {
			continue
		}
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return PSIValues{}, fmt.Errorf("parse PSI %s: %w", key, err)
		}
		values[key] = parsed
	}
	if len(values) != 3 {
		return PSIValues{}, errors.New("PSI line requires avg10, avg60, and avg300")
	}
	return PSIValues{
		Availability: measured(source),
		Avg10:        values["avg10"], Avg60: values["avg60"], Avg300: values["avg300"],
	}, nil
}
