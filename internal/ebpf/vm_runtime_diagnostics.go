package ebpf

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	defaultSelfStatusPath              = "/proc/self/status"
	defaultLockdownPath                = "/sys/kernel/security/lockdown"
	defaultPerfEventParanoidPath       = "/proc/sys/kernel/perf_event_paranoid"
	defaultUnprivilegedBPFDisabledPath = "/proc/sys/kernel/unprivileged_bpf_disabled"
)

type vmBlockDiagnosticConfig struct {
	SelfStatusPath              string
	LockdownPath                string
	PerfEventParanoidPath       string
	UnprivilegedBPFDisabledPath string
	GetEUID                     func() int
	GetMemlock                  func() (string, error)
}

func defaultVMBlockDiagnosticConfig() vmBlockDiagnosticConfig {
	return vmBlockDiagnosticConfig{
		SelfStatusPath:              defaultSelfStatusPath,
		LockdownPath:                defaultLockdownPath,
		PerfEventParanoidPath:       defaultPerfEventParanoidPath,
		UnprivilegedBPFDisabledPath: defaultUnprivilegedBPFDisabledPath,
		GetEUID:                     os.Geteuid,
		GetMemlock:                  currentMemlockLimit,
	}
}

func collectVMBlockRuntimeDiagnostics(config vmBlockDiagnosticConfig, stage string, err error) VMBlockRuntimeDiagnostics {
	euid := -1
	if config.GetEUID != nil {
		euid = config.GetEUID()
	}
	diagnostics := VMBlockRuntimeDiagnostics{
		Stage:                   firstNonEmpty(strings.TrimSpace(stage), "unknown"),
		EUID:                    euid,
		RawError:                boundedError(err),
		CapabilitySummary:       readCapabilitySummary(config.SelfStatusPath),
		LockdownMode:            readDiagnosticValue(config.LockdownPath, parseLockdownMode),
		PerfEventParanoid:       readDiagnosticValue(config.PerfEventParanoidPath, strings.TrimSpace),
		UnprivilegedBPFDisabled: readDiagnosticValue(config.UnprivilegedBPFDisabledPath, strings.TrimSpace),
		MemlockLimit:            "-",
	}
	if config.GetMemlock != nil {
		if value, readErr := config.GetMemlock(); readErr == nil {
			diagnostics.MemlockLimit = firstNonEmpty(strings.TrimSpace(value), "-")
		} else {
			diagnostics.MemlockLimit = "unavailable: " + boundVMBlockDiagnostic(readErr.Error(), 512)
		}
	}
	return diagnostics
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	return boundVMBlockDiagnostic(err.Error(), maxVMBlockVerifierLogBytes)
}

func readDiagnosticValue(path string, parse func(string) string) string {
	if strings.TrimSpace(path) == "" {
		return "-"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "unavailable: " + boundVMBlockDiagnostic(err.Error(), 512)
	}
	value := parse(string(data))
	return firstNonEmpty(strings.TrimSpace(value), "-")
}

func parseLockdownMode(value string) string {
	for _, field := range strings.Fields(value) {
		if strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]") {
			return strings.TrimSuffix(strings.TrimPrefix(field, "["), "]")
		}
	}
	return strings.TrimSpace(value)
}

func readCapabilitySummary(path string) VMBlockCapabilitySummary {
	result := VMBlockCapabilitySummary{CapEff: "-"}
	data, err := os.ReadFile(path)
	if err != nil {
		result.Error = boundVMBlockDiagnostic(err.Error(), 512)
		return result
	}
	var raw string
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(key) == "CapEff" {
			raw = strings.TrimSpace(value)
			break
		}
	}
	if raw == "" {
		result.Error = "CapEff is missing from process status"
		return result
	}
	mask, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		result.Error = "invalid CapEff value: " + boundVMBlockDiagnostic(err.Error(), 256)
		return result
	}
	result.Available = true
	result.CapEff = raw
	result.CAPSysAdmin = capabilitySet(mask, 21)
	result.CAPSysResource = capabilitySet(mask, 24)
	result.CAPPerfmon = capabilitySet(mask, 38)
	result.CAPBPF = capabilitySet(mask, 39)
	return result
}

func capabilitySet(mask uint64, bit uint) bool {
	return bit < 64 && mask&(uint64(1)<<bit) != 0
}

func currentMemlockLimit() (string, error) {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return "", err
	}
	return fmt.Sprintf("soft=%s hard=%s", formatRlimit(limit.Cur), formatRlimit(limit.Max)), nil
}

func formatRlimit(value uint64) string {
	if value == unix.RLIM_INFINITY {
		return "unlimited"
	}
	return strconv.FormatUint(value, 10)
}

func permissionDeniedMessage(euid int, raw error) string {
	var guidance string
	if euid == 0 {
		guidance = "permission denied despite euid=0; check CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN, memlock/rlimit, LSM policy, attach type, or verifier diagnostics"
	} else {
		guidance = "permission denied loading or attaching per-VM eBPF block latency programs; try running with sudo"
	}
	if raw == nil {
		return guidance
	}
	return boundVMBlockDiagnostic(guidance+"; underlying error: "+raw.Error(), maxVMBlockVerifierLogBytes)
}

func isPermissionError(err error) bool {
	return errors.Is(err, ErrVMBlockLatencyPermission) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrPermission)
}
