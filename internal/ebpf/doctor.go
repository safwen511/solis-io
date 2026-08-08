package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultBTFPath       = "/sys/kernel/btf/vmlinux"
	defaultMountInfoPath = "/proc/self/mountinfo"
	defaultTraceRoot     = "/sys/kernel/tracing"
	defaultDebugRoot     = "/sys/kernel/debug"
)

type probeConfig struct {
	BTFPath       string
	MountInfoPath string
	TraceRoot     string
	DebugRoot     string
}

type mount struct {
	point      string
	filesystem string
}

// Inspect performs read-only checks without loading or attaching eBPF programs.
func Inspect() Report {
	return inspect(probeConfig{
		BTFPath:       defaultBTFPath,
		MountInfoPath: defaultMountInfoPath,
		TraceRoot:     defaultTraceRoot,
		DebugRoot:     defaultDebugRoot,
	})
}

func inspect(config probeConfig) Report {
	report := Report{}
	if runtime.GOOS == "linux" {
		report.Checks = append(report.Checks, Check{Status: OK, Name: "OS is Linux", Detail: runtime.GOOS})
	} else {
		report.Checks = append(report.Checks, Check{Status: FAIL, Name: "OS is Linux", Detail: runtime.GOOS})
	}

	report.Checks = append(report.Checks, readableNonemptyFileCheck("Kernel BTF", config.BTFPath))

	mountData, err := os.ReadFile(config.MountInfoPath)
	if err != nil {
		report.Checks = append(report.Checks,
			Check{Status: FAIL, Name: "tracefs availability", Detail: fmt.Sprintf("cannot read %s: %v", config.MountInfoPath, err)},
			Check{Status: WARN, Name: "debugfs availability", Detail: fmt.Sprintf("cannot read %s: %v", config.MountInfoPath, err)},
		)
		report.Checks = append(report.Checks, unavailableTracepointChecks("tracefs mount is unknown")...)
		return report
	}

	mounts := parseMountInfo(string(mountData))
	traceRoot := selectMount(mounts, "tracefs", config.TraceRoot)
	if traceRoot == "" {
		legacyRoot := filepath.Join(config.DebugRoot, "tracing")
		if mountExists(mounts, config.DebugRoot, "debugfs") {
			if info, statErr := os.Stat(legacyRoot); statErr == nil && info.IsDir() {
				traceRoot = legacyRoot
			}
		}
	}
	report.TraceRoot = traceRoot

	if traceRoot == "" {
		report.Checks = append(report.Checks, Check{Status: FAIL, Name: "tracefs availability", Detail: "tracefs is not mounted"})
	} else if readErr := directoryReadable(traceRoot); readErr != nil {
		report.Checks = append(report.Checks, Check{Status: FAIL, Name: "tracefs availability", Detail: fmt.Sprintf("mounted at %s but not readable: %v", traceRoot, readErr)})
	} else {
		report.Checks = append(report.Checks, Check{Status: OK, Name: "tracefs availability", Detail: "mounted and readable at " + traceRoot})
	}

	debugRoot := selectMount(mounts, "debugfs", config.DebugRoot)
	if debugRoot == "" {
		report.Checks = append(report.Checks, Check{Status: WARN, Name: "debugfs availability", Detail: "debugfs is not mounted; dedicated tracefs may still be sufficient"})
	} else if readErr := directoryReadable(debugRoot); readErr != nil {
		report.Checks = append(report.Checks, Check{Status: WARN, Name: "debugfs availability", Detail: fmt.Sprintf("mounted at %s but not readable: %v", debugRoot, readErr)})
	} else {
		report.Checks = append(report.Checks, Check{Status: OK, Name: "debugfs availability", Detail: "mounted and readable at " + debugRoot})
	}

	if traceRoot == "" {
		report.Checks = append(report.Checks, unavailableTracepointChecks("tracefs is not mounted")...)
		return report
	}
	report.Checks = append(report.Checks,
		tracepointCheck(traceRoot, "block_rq_issue"),
		tracepointCheck(traceRoot, "block_rq_complete"),
	)
	return report
}

func readableNonemptyFileCheck(name, path string) Check {
	file, err := os.Open(path)
	if err != nil {
		return Check{Status: FAIL, Name: name, Detail: fmt.Sprintf("%s is unavailable: %v", path, err)}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Check{Status: FAIL, Name: name, Detail: fmt.Sprintf("cannot inspect %s: %v", path, err)}
	}
	if info.Size() == 0 {
		return Check{Status: FAIL, Name: name, Detail: path + " is empty"}
	}
	return Check{Status: OK, Name: name, Detail: path}
}

func directoryReadable(path string) error {
	_, err := os.ReadDir(path)
	return err
}

func tracepointCheck(traceRoot, event string) Check {
	path := filepath.Join(traceRoot, "events", "block", event, "id")
	data, err := os.ReadFile(path)
	name := "block:" + event
	if err != nil {
		return Check{Status: FAIL, Name: name, Detail: fmt.Sprintf("cannot read %s: %v", path, err)}
	}
	id := strings.TrimSpace(string(data))
	value, err := strconv.ParseUint(id, 10, 64)
	if err != nil || value == 0 {
		return Check{Status: FAIL, Name: name, Detail: fmt.Sprintf("invalid tracepoint ID %q in %s", id, path)}
	}
	return Check{Status: OK, Name: name, Detail: fmt.Sprintf("available at %s (ID %d)", path, value)}
}

func unavailableTracepointChecks(reason string) []Check {
	return []Check{
		{Status: FAIL, Name: "block:block_rq_issue", Detail: reason},
		{Status: FAIL, Name: "block:block_rq_complete", Detail: reason},
	}
}

func parseMountInfo(input string) []mount {
	var mounts []mount
	for _, line := range strings.Split(input, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || separator+1 >= len(fields) {
			continue
		}
		mounts = append(mounts, mount{
			point:      unescapeMountField(fields[4]),
			filesystem: fields[separator+1],
		})
	}
	return mounts
}

func unescapeMountField(value string) string {
	replacer := strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	)
	return replacer.Replace(value)
}

func selectMount(mounts []mount, filesystem, preferred string) string {
	var candidates []string
	for _, candidate := range mounts {
		if candidate.filesystem != filesystem {
			continue
		}
		if candidate.point == preferred {
			return candidate.point
		}
		candidates = append(candidates, candidate.point)
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func mountExists(mounts []mount, point, filesystem string) bool {
	for _, candidate := range mounts {
		if candidate.point == point && candidate.filesystem == filesystem {
			return true
		}
	}
	return false
}
