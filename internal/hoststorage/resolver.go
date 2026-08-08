package hoststorage

import (
	"os/exec"
	"strings"
)

type commandRunner func(name string, args ...string) ([]byte, error)

// Resolve maps a disk file to its containing filesystem and parent block device.
// Unavailable values are left empty for the caller to render as unknown.
func Resolve(diskPath string) Mapping {
	return resolveWithRunner(diskPath, runCommand)
}

func resolveWithRunner(diskPath string, run commandRunner) Mapping {
	diskPath = strings.TrimSpace(diskPath)
	mapping := Mapping{DiskPath: diskPath}
	if diskPath == "" {
		return mapping
	}

	out, err := run("findmnt", "-T", diskPath, "-no", "TARGET,SOURCE,FSTYPE")
	if err != nil {
		return mapping
	}
	mountpoint, source, filesystem, ok := parseFindmnt(out)
	if !ok {
		return mapping
	}
	mapping.Mountpoint = mountpoint
	mapping.SourceDevice = source
	mapping.Filesystem = filesystem

	blockSource := sourceForLSBLK(source)
	if !strings.HasPrefix(blockSource, "/dev/") {
		return mapping
	}
	out, err = run("lsblk", "-no", "PKNAME", blockSource)
	if err != nil {
		return mapping
	}
	mapping.ParentDevice = parseParentDevice(out)

	return mapping
}

func runCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func parseFindmnt(output []byte) (string, string, string, bool) {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			return fields[0], fields[1], fields[2], true
		}
	}

	return "", "", "", false
}

func sourceForLSBLK(source string) string {
	if index := strings.IndexByte(source, '['); index >= 0 {
		return source[:index]
	}
	return source
}

func parseParentDevice(output []byte) string {
	for _, line := range strings.Split(string(output), "\n") {
		parent := strings.TrimSpace(line)
		if parent == "" || parent == "-" {
			continue
		}
		if strings.HasPrefix(parent, "/dev/") {
			return parent
		}
		return "/dev/" + parent
	}

	return ""
}
