package experiment

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	fioWritePattern = regexp.MustCompile(`write:\s+IOPS=([^,\s]+),\s+BW=([^,\s]+)`)
	fioUtilPattern  = regexp.MustCompile(`util=([0-9]+(\.[0-9]+)?)%`)
)

// Load reads and parses a workload experiment report directory.
func Load(reportDir string) (Report, error) {
	cleanDir := filepath.Clean(reportDir)
	info, err := os.Stat(cleanDir)
	if err != nil {
		return Report{}, fmt.Errorf("open report directory %q: %w", cleanDir, err)
	}
	if !info.IsDir() {
		return Report{}, fmt.Errorf("report path %q is not a directory", cleanDir)
	}

	baseline, err := parseHTTPFile(filepath.Join(cleanDir, "baseline.txt"))
	if err != nil {
		return Report{}, fmt.Errorf("parse baseline report: %w", err)
	}
	duringNoise, err := parseHTTPFile(filepath.Join(cleanDir, "during-noise.txt"))
	if err != nil {
		return Report{}, fmt.Errorf("parse during-noise report: %w", err)
	}
	postNoise, err := parseHTTPFile(filepath.Join(cleanDir, "post-noise.txt"))
	if err != nil {
		return Report{}, fmt.Errorf("parse post-noise report: %w", err)
	}
	fioMetrics, err := parseFIOFile(filepath.Join(cleanDir, "fio-noise.txt"))
	if err != nil {
		return Report{}, fmt.Errorf("parse fio-noise report: %w", err)
	}

	return Report{
		Directory:   cleanDir,
		Baseline:    baseline,
		DuringNoise: duringNoise,
		PostNoise:   postNoise,
		FIO:         fioMetrics,
	}, nil
}

func parseHTTPFile(path string) (HTTPMetrics, error) {
	f, err := os.Open(path)
	if err != nil {
		return HTTPMetrics{}, fmt.Errorf("read %q: %w", path, err)
	}
	defer f.Close()

	var metrics HTTPMetrics
	var foundFailed, foundRPS, foundLatency, foundTransfer bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "Failed requests:"):
			value, err := firstValue(line, "Failed requests:")
			if err != nil {
				return HTTPMetrics{}, fieldError(path, "Failed requests", err)
			}
			metrics.FailedRequests, err = strconv.Atoi(value)
			if err != nil {
				return HTTPMetrics{}, fieldError(path, "Failed requests", err)
			}
			foundFailed = true
		case strings.HasPrefix(line, "Requests per second:"):
			value, err := firstValue(line, "Requests per second:")
			if err != nil {
				return HTTPMetrics{}, fieldError(path, "Requests per second", err)
			}
			metrics.RequestsPerSecond, err = strconv.ParseFloat(value, 64)
			if err != nil {
				return HTTPMetrics{}, fieldError(path, "Requests per second", err)
			}
			foundRPS = true
		case !foundLatency && strings.HasPrefix(line, "Time per request:"):
			value, err := firstValue(line, "Time per request:")
			if err != nil {
				return HTTPMetrics{}, fieldError(path, "Time per request", err)
			}
			metrics.TimePerRequestMS, err = strconv.ParseFloat(value, 64)
			if err != nil {
				return HTTPMetrics{}, fieldError(path, "Time per request", err)
			}
			foundLatency = true
		case strings.HasPrefix(line, "Transfer rate:"):
			fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "Transfer rate:")))
			if len(fields) < 2 {
				return HTTPMetrics{}, fieldError(path, "Transfer rate", fmt.Errorf("value or unit is missing"))
			}
			metrics.TransferRate, err = strconv.ParseFloat(fields[0], 64)
			if err != nil {
				return HTTPMetrics{}, fieldError(path, "Transfer rate", err)
			}
			metrics.TransferRateUnit = strings.Trim(fields[1], "[]")
			foundTransfer = true
		}
	}
	if err := scanner.Err(); err != nil {
		return HTTPMetrics{}, fmt.Errorf("read %q: %w", path, err)
	}

	missing := missingHTTPFields(foundFailed, foundRPS, foundLatency, foundTransfer)
	if len(missing) > 0 {
		return HTTPMetrics{}, fmt.Errorf("parse %q: missing %s", path, strings.Join(missing, ", "))
	}

	return metrics, nil
}

func parseFIOFile(path string) (FIOMetrics, error) {
	f, err := os.Open(path)
	if err != nil {
		return FIOMetrics{}, fmt.Errorf("read %q: %w", path, err)
	}
	defer f.Close()

	var metrics FIOMetrics
	var foundWrite, foundUtil bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !foundWrite {
			matches := fioWritePattern.FindStringSubmatch(line)
			if len(matches) == 3 {
				metrics.IOPS = matches[1]
				metrics.Bandwidth = matches[2]
				foundWrite = true
			}
		}
		if !foundUtil {
			matches := fioUtilPattern.FindStringSubmatch(line)
			if len(matches) >= 2 {
				metrics.DiskUtilPct, err = strconv.ParseFloat(matches[1], 64)
				if err != nil {
					return FIOMetrics{}, fieldError(path, "disk util", err)
				}
				foundUtil = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return FIOMetrics{}, fmt.Errorf("read %q: %w", path, err)
	}
	if !foundWrite {
		return FIOMetrics{}, fmt.Errorf("parse %q: missing fio write IOPS and bandwidth", path)
	}
	if !foundUtil {
		return FIOMetrics{}, fmt.Errorf("parse %q: missing disk util", path)
	}

	return metrics, nil
}

func firstValue(line, prefix string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
	if len(fields) == 0 {
		return "", fmt.Errorf("value is missing")
	}
	return fields[0], nil
}

func fieldError(path, field string, err error) error {
	return fmt.Errorf("parse %q field %q: %w", path, field, err)
}

func missingHTTPFields(failed, rps, latency, transfer bool) []string {
	var missing []string
	if !failed {
		missing = append(missing, "Failed requests")
	}
	if !rps {
		missing = append(missing, "Requests per second")
	}
	if !latency {
		missing = append(missing, "Time per request")
	}
	if !transfer {
		missing = append(missing, "Transfer rate")
	}
	return missing
}
