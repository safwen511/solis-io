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

// defaultVMBlockDiagnosticConfig returns the default vm block diagnostic config.
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

// collectVMBlockRuntimeDiagnostics collects vm block runtime diagnostics from the configured
// evidence sources.
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
	applyVMBlockMapLayoutDiagnostics(&diagnostics, err)
	if config.GetMemlock != nil {
		if value, readErr := config.GetMemlock(); readErr == nil {
			diagnostics.MemlockLimit = firstNonEmpty(strings.TrimSpace(value), "-")
		} else {
			diagnostics.MemlockLimit = "unavailable: " + boundVMBlockDiagnostic(readErr.Error(), 512)
		}
	}
	return diagnostics
}

// applyVMBlockMapLayoutDiagnostics applies vm block map layout diagnostics to the current model.
func applyVMBlockMapLayoutDiagnostics(diagnostics *VMBlockRuntimeDiagnostics, err error) {
	if diagnostics == nil || err == nil {
		return
	}
	var layoutError *VMBlockMapLayoutError
	if !errors.As(err, &layoutError) {
		return
	}
	diagnostics.MapName = layoutError.MapName
	diagnostics.MapLayoutComponent = layoutError.Component
	if layoutError.Component == "value" {
		diagnostics.ValueSizeFromObject = layoutError.SizeFromObject
		diagnostics.GoValueSize = layoutError.GoSize
		return
	}
	diagnostics.KeySizeFromObject = layoutError.SizeFromObject
	diagnostics.GoKeySize = layoutError.GoSize
}

// boundedError trims and bounds an error message before it reaches public diagnostics.
func boundedError(err error) string {
	if err == nil {
		return ""
	}
	return boundVMBlockDiagnostic(err.Error(), maxVMBlockVerifierLogBytes)
}

// readDiagnosticValue reads diagnostic value from its configured source.
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

// parseLockdownMode parses and validates lockdown mode.
func parseLockdownMode(value string) string {
	for _, field := range strings.Fields(value) {
		if strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]") {
			return strings.TrimSuffix(strings.TrimPrefix(field, "["), "]")
		}
	}
	return strings.TrimSpace(value)
}

// readCapabilitySummary reads capability summary from its configured source.
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

// capabilitySet reports whether capability set.
func capabilitySet(mask uint64, bit uint) bool {
	return bit < 64 && mask&(uint64(1)<<bit) != 0
}

// currentMemlockLimit builds current memlock limit and returns an error when validation or source
// access fails.
func currentMemlockLimit() (string, error) {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return "", err
	}
	return fmt.Sprintf("soft=%s hard=%s", formatRlimit(limit.Cur), formatRlimit(limit.Max)), nil
}

// formatRlimit formats rlimit using the stable output contract.
func formatRlimit(value uint64) string {
	if value == unix.RLIM_INFINITY {
		return "unlimited"
	}
	return strconv.FormatUint(value, 10)
}

// permissionDeniedMessage derives stable operator-facing text for permission denied message.
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

// isPermissionError reports whether permission error.
func isPermissionError(err error) bool {
	return errors.Is(err, ErrVMBlockLatencyPermission) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrPermission)
}
