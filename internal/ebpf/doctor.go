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
	BTFPath                     string
	MountInfoPath               string
	TraceRoot                   string
	DebugRoot                   string
	SelfStatusPath              string
	LockdownPath                string
	PerfEventParanoidPath       string
	UnprivilegedBPFDisabledPath string
	GetEUID                     func() int
	GetMemlock                  func() (string, error)
	ObjectProvider              func() ([]byte, error)
	TypedTracepointInspect      func() ([]vmBlockTypedTracepointPrototype, error)
	BTFCapabilityInspect        func() (VMBlockBTFCapabilityReport, error)
}

type mount struct {
	point      string
	filesystem string
}

// Inspect performs read-only checks without loading or attaching eBPF programs.
func Inspect() Report {
	return inspect(probeConfig{
		BTFPath:                     defaultBTFPath,
		MountInfoPath:               defaultMountInfoPath,
		TraceRoot:                   defaultTraceRoot,
		DebugRoot:                   defaultDebugRoot,
		SelfStatusPath:              defaultSelfStatusPath,
		LockdownPath:                defaultLockdownPath,
		PerfEventParanoidPath:       defaultPerfEventParanoidPath,
		UnprivilegedBPFDisabledPath: defaultUnprivilegedBPFDisabledPath,
		GetEUID:                     os.Geteuid,
		GetMemlock:                  currentMemlockLimit,
		ObjectProvider:              embeddedVMBlockObject,
		TypedTracepointInspect:      inspectVMBlockTypedTracepoints,
		BTFCapabilityInspect:        inspectKernelVMBlockBTFCapabilities,
	})
}

// inspect assembles non-invasive host, BTF, capability, lockdown, and object readiness checks.
func inspect(config probeConfig) Report {
	report := Report{}
	if runtime.GOOS == "linux" {
		report.Checks = append(report.Checks, Check{Status: OK, Name: "OS is Linux", Detail: runtime.GOOS})
	} else {
		report.Checks = append(report.Checks, Check{Status: FAIL, Name: "OS is Linux", Detail: runtime.GOOS})
	}

	report.Checks = append(report.Checks, readableNonemptyFileCheck("Kernel BTF", config.BTFPath))
	report.Checks = append(report.Checks, runtimeReadinessChecks(config)...)

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

// readableNonemptyFileCheck reads able nonempty file check from its configured source.
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

// directoryReadable completes directory readable and returns any failure to its caller.
func directoryReadable(path string) error {
	_, err := os.ReadDir(path)
	return err
}

// tracepointCheck builds tracepoint check from validated inputs.
func tracepointCheck(traceRoot, event string) Check {
	path := filepath.Join(traceRoot, "events", "block", event, "id")
	data, err := os.ReadFile(path)
	name := "formatted block:" + event
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

// unavailableTracepointChecks builds unavailable tracepoint checks from validated inputs.
func unavailableTracepointChecks(reason string) []Check {
	return []Check{
		{Status: FAIL, Name: "formatted block:block_rq_issue", Detail: reason},
		{Status: FAIL, Name: "formatted block:block_rq_complete", Detail: reason},
	}
}

// runtimeReadinessChecks distinguishes formatted tracepoint visibility from typed-BTF readiness.
func runtimeReadinessChecks(config probeConfig) []Check {
	checks := make([]Check, 0, 13)
	if config.GetEUID == nil {
		checks = append(checks, Check{Status: WARN, Name: "Effective UID", Detail: "probe unavailable"})
	} else {
		checks = append(checks, Check{Status: OK, Name: "Effective UID", Detail: strconv.Itoa(config.GetEUID())})
	}
	checks = append(checks,
		diagnosticFileCheck("Kernel lockdown mode", config.LockdownPath, parseLockdownMode),
		diagnosticFileCheck("perf_event_paranoid", config.PerfEventParanoidPath, strings.TrimSpace),
		diagnosticFileCheck("unprivileged_bpf_disabled", config.UnprivilegedBPFDisabledPath, strings.TrimSpace),
	)
	if config.GetMemlock == nil {
		checks = append(checks, Check{Status: WARN, Name: "memlock limit", Detail: "probe unavailable"})
	} else if value, err := config.GetMemlock(); err != nil {
		checks = append(checks, Check{Status: WARN, Name: "memlock limit", Detail: err.Error()})
	} else {
		checks = append(checks, Check{Status: OK, Name: "memlock limit", Detail: value})
	}

	capabilities := readCapabilitySummary(config.SelfStatusPath)
	if !capabilities.Available {
		checks = append(checks, Check{Status: WARN, Name: "CapEff", Detail: firstNonEmpty(capabilities.Error, "unavailable")})
	} else {
		checks = append(checks, Check{Status: OK, Name: "CapEff", Detail: capabilities.CapEff})
		checks = append(checks,
			capabilityDoctorCheck("CAP_BPF", capabilities.CAPBPF),
			capabilityDoctorCheck("CAP_PERFMON", capabilities.CAPPerfmon),
			capabilityDoctorCheck("CAP_SYS_ADMIN", capabilities.CAPSysAdmin),
			capabilityDoctorCheck("CAP_SYS_RESOURCE", capabilities.CAPSysResource),
		)
	}

	if config.ObjectProvider == nil {
		checks = append(checks, Check{Status: WARN, Name: "Typed-BTF generated object", Detail: "object probe unavailable"})
	} else if object, err := config.ObjectProvider(); err != nil {
		checks = append(checks, Check{Status: WARN, Name: "Typed-BTF generated object", Detail: err.Error()})
	} else {
		checks = append(checks, Check{Status: OK, Name: "Typed-BTF generated object", Detail: fmt.Sprintf("present (%d bytes)", len(object))})
	}
	if config.TypedTracepointInspect == nil {
		checks = append(checks, Check{Status: WARN, Name: "Typed-BTF block tracepoints", Detail: "BTF symbol probe unavailable"})
	} else if prototypes, err := config.TypedTracepointInspect(); err != nil {
		checks = append(checks, Check{Status: FAIL, Name: "Typed-BTF block tracepoints", Detail: err.Error()})
	} else {
		checks = append(checks, Check{Status: OK, Name: "Typed-BTF block tracepoints", Detail: formatVMBlockTypedTracepointPrototypes(prototypes)})
	}
	checks = append(checks, vmBlockCapabilityDoctorChecks(config.BTFCapabilityInspect)...)
	checks = append(checks, Check{Status: WARN, Name: "Typed-BTF load/attach", Detail: "not attempted by doctor; formatted tracepoint and BTF readiness do not prove program load or attach permission"})
	return checks
}

// vmBlockCapabilityDoctorChecks reports each request-metadata and ownership-path BTF requirement.
func vmBlockCapabilityDoctorChecks(inspect func() (VMBlockBTFCapabilityReport, error)) []Check {
	const unavailable = "BTF field capability probe unavailable"
	if inspect == nil {
		return []Check{
			{Status: WARN, Name: "Request metadata support", Detail: unavailable},
			{Status: WARN, Name: "Operation classification support", Detail: unavailable},
			{Status: WARN, Name: "Device extraction support", Detail: unavailable},
			{Status: WARN, Name: "blkcg ownership path support", Detail: unavailable},
			{Status: WARN, Name: "cgroup identity extraction support", Detail: unavailable},
			{Status: WARN, Name: "VM attribution preflight", Detail: unavailable},
			{Status: WARN, Name: "VM attribution runtime readiness", Detail: "not attempted; doctor does not load or attach eBPF programs"},
		}
	}
	report, err := inspect()
	if err != nil {
		detail := boundVMBlockDiagnostic(err.Error(), maxVMBlockVerifierLogBytes)
		return []Check{
			{Status: WARN, Name: "Request metadata support", Detail: detail},
			{Status: WARN, Name: "Operation classification support", Detail: detail},
			{Status: WARN, Name: "Device extraction support", Detail: detail},
			{Status: WARN, Name: "blkcg ownership path support", Detail: detail},
			{Status: WARN, Name: "cgroup identity extraction support", Detail: detail},
			{Status: WARN, Name: "VM attribution preflight", Detail: "unavailable; capability inspection failed"},
			{Status: WARN, Name: "VM attribution runtime readiness", Detail: "not attempted; doctor does not load or attach eBPF programs"},
		}
	}
	metadata := vmBlockDoctorCapabilityCheck("Request metadata support", report, []string{"request.cmd_flags"})
	operation := vmBlockDoctorCapabilityCheck("Operation classification support", report, []string{"request.cmd_flags", "req_op"})
	device := vmBlockDoctorCapabilityCheck("Device extraction support", report, []string{"request.part", "block_device.bd_dev"})
	ownership := vmBlockDoctorCapabilityCheck("blkcg ownership path support", report, []string{"request.bio", "bio.bi_blkg", "blkcg_gq.blkcg"})
	identity := vmBlockDoctorCapabilityCheck("cgroup identity extraction support", report, []string{"blkcg.css.cgroup", "cgroup.kn", "kernfs_node.id"})
	missing := missingVMBlockCapabilities(report, vmBlockOwnershipRequirements)
	preflight := Check{Status: OK, Name: "VM attribution preflight", Detail: "ownership fields available"}
	if len(missing) > 0 {
		preflight.Status = WARN
		preflight.Detail = "unavailable; missing: " + strings.Join(missing, ", ")
	}
	runtimeReadiness := Check{
		Status: WARN, Name: "VM attribution runtime readiness",
		Detail: "not attempted; run experimental vm-block-latency to validate privileged load, attach, ownership extraction, and exact VM matches",
	}
	return []Check{metadata, operation, device, ownership, identity, preflight, runtimeReadiness}
}

// vmBlockDoctorCapabilityCheck builds VM block doctor capability check from validated inputs.
func vmBlockDoctorCapabilityCheck(name string, report VMBlockBTFCapabilityReport, required []string) Check {
	missing := missingVMBlockCapabilities(report, required)
	if len(missing) > 0 {
		return Check{Status: WARN, Name: name, Detail: "unavailable; missing: " + strings.Join(missing, ", ")}
	}
	return Check{Status: OK, Name: name, Detail: "available in kernel BTF"}
}

// formatVMBlockTypedTracepointPrototypes formats vm block typed tracepoint prototypes using the
// stable output contract.
func formatVMBlockTypedTracepointPrototypes(prototypes []vmBlockTypedTracepointPrototype) string {
	if len(prototypes) == 0 {
		return "typed-BTF symbols present; parameter details unavailable"
	}
	details := make([]string, 0, len(prototypes))
	for _, prototype := range prototypes {
		details = append(details, fmt.Sprintf(
			"%s kernel params (%d): [%s]; program params (%d): [%s]",
			prototype.Name,
			len(prototype.KernelParameters),
			strings.Join(prototype.KernelParameters, ", "),
			len(prototype.ProgramParameters),
			strings.Join(prototype.ProgramParameters, ", "),
		))
	}
	return strings.Join(details, "; ")
}

// diagnosticFileCheck builds diagnostic file check from validated inputs.
func diagnosticFileCheck(name, path string, parse func(string) string) Check {
	data, err := os.ReadFile(path)
	if err != nil {
		return Check{Status: WARN, Name: name, Detail: fmt.Sprintf("cannot read %s: %v", path, err)}
	}
	return Check{Status: OK, Name: name, Detail: firstNonEmpty(strings.TrimSpace(parse(string(data))), "-")}
}

// capabilityDoctorCheck builds capability doctor check from validated inputs.
func capabilityDoctorCheck(name string, enabled bool) Check {
	if enabled {
		return Check{Status: OK, Name: name, Detail: "set in CapEff"}
	}
	return Check{Status: WARN, Name: name, Detail: "not set in CapEff; eBPF operations may rely on another applicable capability or policy"}
}

// parseMountInfo parses and validates mount info.
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

// unescapeMountField derives stable operator-facing text for unescape mount field.
func unescapeMountField(value string) string {
	replacer := strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	)
	return replacer.Replace(value)
}

// selectMount selects mount using deterministic ordering.
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

// mountExists reports whether mount exists.
func mountExists(mounts []mount, point, filesystem string) bool {
	for _, candidate := range mounts {
		if candidate.point == point && candidate.filesystem == filesystem {
			return true
		}
	}
	return false
}
