package inventory

import (
	"os/exec"
	"strings"
)

// EnrichOptions controls host-side inventory queries.
type EnrichOptions struct {
	LibvirtURI string
}

// Enrich adds host information reported by libvirt and QEMU to each VM.
func Enrich(vms []VM) []VM {
	return EnrichWithOptions(vms, EnrichOptions{})
}

// EnrichWithOptions adds host information using the configured libvirt URI.
func EnrichWithOptions(vms []VM, options EnrichOptions) []VM {
	for i := range vms {
		vms[i].State = domainState(vms[i].Name, options.LibvirtURI)
		vms[i].IPLease = leaseIP(vms[i].Name, options.LibvirtURI)
		vms[i].Disk = diskPath(vms[i].Name, options.LibvirtURI)
		vms[i].QEMUPID, vms[i].QEMUCmdline = qemuDetails(vms[i].Name)
	}

	return vms
}

func domainState(name, uri string) string {
	out, err := virshCommand(uri, "domstate", name).CombinedOutput()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}

func leaseIP(name, uri string) string {
	out, err := virshCommand(uri, "domifaddr", name, "--source", "lease").CombinedOutput()
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

func diskPath(name, uri string) string {
	out, err := virshCommand(uri, "domblklist", name, "--details").CombinedOutput()
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

func virshCommand(uri string, args ...string) *exec.Cmd {
	if strings.TrimSpace(uri) != "" {
		args = append([]string{"-c", strings.TrimSpace(uri)}, args...)
	}
	return exec.Command("virsh", args...)
}
