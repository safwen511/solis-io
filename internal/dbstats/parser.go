// Package dbstats collects fixed, read-only PostgreSQL statistics without SQL
// text, table data, credentials, schemas, dumps, or payloads.
package dbstats

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safwen511/solis-io/internal/observability"
)

// parseVersion parses and validates version.
func parseVersion(output string) (string, error) {
	rows, err := csvRows(output, 1)
	if err != nil {
		return "", fmt.Errorf("parse PostgreSQL version: %w", err)
	}
	if len(rows) != 1 || strings.TrimSpace(rows[0][0]) == "" {
		return "", errors.New("PostgreSQL version output must contain one row")
	}
	return strings.TrimSpace(rows[0][0]), nil
}

// parseDatabaseCounters parses and validates database counters.
func parseDatabaseCounters(output string) ([]observability.DatabaseCounters, error) {
	rows, err := csvRows(output, 7)
	if err != nil {
		return nil, fmt.Errorf("parse pg_stat_database: %w", err)
	}
	result := make([]observability.DatabaseCounters, 0, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row[0]) == "" {
			// pg_stat_database may expose one shared-object row without a
			// database name; the DBStatus model contains named databases only.
			continue
		}
		connections, err := parseNonNegativeInt(row[1])
		if err != nil {
			return nil, errors.New("pg_stat_database contains invalid numbackends")
		}
		values := make([]uint64, 5)
		for index := range values {
			value, err := strconv.ParseUint(strings.TrimSpace(row[index+2]), 10, 64)
			if err != nil {
				return nil, errors.New("pg_stat_database contains an invalid cumulative counter")
			}
			values[index] = value
		}
		result = append(result, observability.DatabaseCounters{
			Name: row[0], Connections: connections, XactCommit: values[0], XactRollback: values[1],
			BlocksRead: values[2], BlocksHit: values[3], Deadlocks: values[4],
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

// parseActivity parses and validates activity.
func parseActivity(output string) (observability.DatabaseActivity, error) {
	rows, err := csvRows(output, 7)
	if err != nil {
		return observability.DatabaseActivity{}, fmt.Errorf("parse pg_stat_activity: %w", err)
	}
	waits := make(map[string]int)
	activity := observability.DatabaseActivity{WaitEvents: []observability.WaitEventCount{}}
	for _, row := range rows {
		if _, err := parseNonNegativeInt(row[0]); err != nil {
			return observability.DatabaseActivity{}, errors.New("pg_stat_activity contains an invalid pid")
		}
		age, err := parsePostgreSQLInterval(row[6])
		if err != nil {
			return observability.DatabaseActivity{}, errors.New("pg_stat_activity contains an invalid query age")
		}
		activity.ActiveSessions++
		if age > activity.OldestActiveSeconds {
			activity.OldestActiveSeconds = age
		}
		waitType, waitEvent := strings.TrimSpace(row[4]), strings.TrimSpace(row[5])
		if waitType != "" || waitEvent != "" {
			activity.WaitingSessions++
			waits[waitType+"\x00"+waitEvent]++
		}
		// Username, database, and state establish row shape only. They are not
		// retained, and an eighth query-text column is rejected by csvRows.
	}
	for key, count := range waits {
		waitType, waitEvent, _ := strings.Cut(key, "\x00")
		activity.WaitEvents = append(activity.WaitEvents, observability.WaitEventCount{Type: waitType, Event: waitEvent, Count: count})
	}
	sort.Slice(activity.WaitEvents, func(i, j int) bool {
		if activity.WaitEvents[i].Type != activity.WaitEvents[j].Type {
			return activity.WaitEvents[i].Type < activity.WaitEvents[j].Type
		}
		return activity.WaitEvents[i].Event < activity.WaitEvents[j].Event
	})
	return activity, nil
}

// parseExtensions parses and validates extensions.
func parseExtensions(output string) ([]string, error) {
	rows, err := csvRows(output, 1)
	if err != nil {
		return nil, fmt.Errorf("parse pg_extension: %w", err)
	}
	result := make([]string, 0, len(rows))
	for _, row := range rows {
		name := strings.TrimSpace(row[0])
		if name == "" {
			return nil, errors.New("pg_extension contains an empty extension name")
		}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

// parseStatementStatistics parses and validates statement statistics.
func parseStatementStatistics(output string) ([]observability.StatementStatistics, error) {
	rows, err := csvRows(output, 5)
	if err != nil {
		return nil, fmt.Errorf("parse pg_stat_statements: %w", err)
	}
	result := make([]observability.StatementStatistics, 0, len(rows))
	for _, row := range rows {
		queryID := strings.TrimSpace(row[0])
		if _, err := strconv.ParseInt(queryID, 10, 64); err != nil {
			return nil, errors.New("pg_stat_statements contains an invalid queryid")
		}
		calls, err := strconv.ParseUint(strings.TrimSpace(row[1]), 10, 64)
		if err != nil {
			return nil, errors.New("pg_stat_statements contains invalid calls")
		}
		total, err := strconv.ParseFloat(strings.TrimSpace(row[2]), 64)
		if err != nil || total < 0 || math.IsNaN(total) || math.IsInf(total, 0) {
			return nil, errors.New("pg_stat_statements contains invalid total_exec_time")
		}
		mean, err := strconv.ParseFloat(strings.TrimSpace(row[3]), 64)
		if err != nil || mean < 0 || math.IsNaN(mean) || math.IsInf(mean, 0) {
			return nil, errors.New("pg_stat_statements contains invalid mean_exec_time")
		}
		rowsValue, err := strconv.ParseInt(strings.TrimSpace(row[4]), 10, 64)
		if err != nil || rowsValue < 0 {
			return nil, errors.New("pg_stat_statements contains invalid rows")
		}
		result = append(result, observability.StatementStatistics{QueryID: queryID, Calls: calls, TotalExecutionMS: total, MeanExecutionMS: mean, Rows: rowsValue})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].QueryID < result[j].QueryID })
	return result, nil
}

// csvRows builds csv rows and returns an error when validation or source access fails.
func csvRows(output string, fields int) ([][]string, error) {
	reader := csv.NewReader(strings.NewReader(output))
	reader.FieldsPerRecord = fields
	reader.ReuseRecord = false
	rows := make([][]string, 0)
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("invalid CSV row shape")
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// parseNonNegativeInt parses and validates non negative int.
func parseNonNegativeInt(value string) (int, error) {
	number, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || number < 0 {
		return 0, errors.New("invalid non-negative integer")
	}
	return number, nil
}

// parsePostgreSQLInterval decodes and validates PostgreSQL interval, rejecting malformed input.
func parsePostgreSQLInterval(value string) (float64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	days := float64(0)
	parts := strings.Fields(value)
	clock := parts[len(parts)-1]
	if len(parts) >= 3 && (parts[1] == "day" || parts[1] == "days") {
		parsedDays, err := strconv.ParseFloat(parts[0], 64)
		if err != nil || parsedDays < 0 || math.IsNaN(parsedDays) || math.IsInf(parsedDays, 0) {
			return 0, errors.New("invalid interval day count")
		}
		days = parsedDays
	} else if len(parts) != 1 {
		return 0, errors.New("unsupported interval format")
	}
	clockParts := strings.Split(clock, ":")
	if len(clockParts) != 3 {
		return 0, errors.New("unsupported interval clock")
	}
	hours, err := strconv.ParseFloat(clockParts[0], 64)
	if err != nil || hours < 0 || math.IsNaN(hours) || math.IsInf(hours, 0) {
		return 0, errors.New("invalid interval hours")
	}
	minutes, err := strconv.ParseFloat(clockParts[1], 64)
	if err != nil || minutes < 0 || minutes >= 60 || math.IsNaN(minutes) || math.IsInf(minutes, 0) {
		return 0, errors.New("invalid interval minutes")
	}
	seconds, err := strconv.ParseFloat(clockParts[2], 64)
	if err != nil || seconds < 0 || seconds >= 60 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return 0, errors.New("invalid interval seconds")
	}
	return days*24*float64(time.Hour/time.Second) + hours*3600 + minutes*60 + seconds, nil
}
