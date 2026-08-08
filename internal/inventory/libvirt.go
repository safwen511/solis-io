package inventory

import (
	"os/exec"
	"strings"
)

// Enrich adds host information reported by libvirt and QEMU to each VM.
func Enrich(vms []VM) []VM {
	for i := range vms {
		vms[i].State = domainState(vms[i].Name)
		vms[i].IPLease = leaseIP(vms[i].Name)
		vms[i].Disk = diskPath(vms[i].Name)
		vms[i].QEMUPID, vms[i].QEMUCmdline = qemuDetails(vms[i].Name)
	}

	return vms
}

func domainState(name string) string {
	out, err := exec.Command("virsh", "domstate", name).CombinedOutput()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}

func leaseIP(name string) string {
	out, err := exec.Command("virsh", "domifaddr", name, "--source", "lease").CombinedOutput()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		for _, field := range strings.Fields(line) {
			if strings.Contains(field, ".") && strings.Contains(field, "/") {
				return strings.Split(field, "/")[0]
			}
		}
	}

	return ""
}

func diskPath(name string) string {
	out, err := exec.Command("virsh", "domblklist", name, "--details").CombinedOutput()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == "disk" {
			return fields[3]
		}
	}

	return ""
}
