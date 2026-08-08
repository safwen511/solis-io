package inventory

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func qemuDetails(name string) (string, string) {
	pid := readLibvirtPIDFile(name)
	if pid != "" {
		if cmdline := readProcCmdline(pid); cmdline != "" {
			return pid, cmdline
		}
		if cmdline := findCmdlineByPID(pid); cmdline != "" {
			return pid, cmdline
		}
	}

	psPID, cmdline := findQEMUFromPS(name)
	if psPID != "" {
		return psPID, cmdline
	}

	return pid, ""
}

func readLibvirtPIDFile(name string) string {
	dirs := []string{
		"/run/libvirt/qemu",
		"/var/run/libvirt/qemu",
	}

	for _, dir := range dirs {
		candidates := []string{filepath.Join(dir, name+".pid")}

		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, entry := range entries {
				entryName := entry.Name()
				if strings.HasSuffix(entryName, ".pid") && strings.Contains(entryName, name) {
					candidates = append(candidates, filepath.Join(dir, entryName))
				}
			}
		}

		for _, path := range candidates {
			b, err := os.ReadFile(path)
			if err == nil {
				if pid := strings.TrimSpace(string(b)); pid != "" {
					return pid
				}
			}
		}
	}

	return ""
}

func readProcCmdline(pid string) string {
	b, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

func findCmdlineByPID(pid string) string {
	out, err := exec.Command("ps", "-ww", "-p", pid, "-o", "args=").CombinedOutput()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}

func findQEMUFromPS(name string) (string, string) {
	out, err := exec.Command("ps", "-ww", "-eo", "pid=,args=").CombinedOutput()
	if err != nil {
		return "", ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		args := strings.Join(fields[1:], " ")
		if strings.Contains(args, "qemu-system") && strings.Contains(args, "guest="+name) {
			return fields[0], args
		}
	}

	return "", ""
}
