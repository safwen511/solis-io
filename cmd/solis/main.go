package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
)

type VM struct {
	Name    string
	Tenant  string
	Network string
	IPPlan  string
	Memory  string
	VCPUs   string
	DiskGB  string
	Role    string
	State   string
	IPLease string
	Disk    string
	QEMUPID string
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "doctor":
		fmt.Println("solis doctor: compatibility checks will be implemented here")

	case "inventory":
		if err := inventory(); err != nil {
			fmt.Fprintf(os.Stderr, "inventory error: %v\n", err)
			os.Exit(1)
		}

	case "top":
		fmt.Println("solis top: live VM I/O view will be implemented here")

	case "inspect":
		if len(os.Args) < 3 {
			fmt.Println("usage: solis inspect <vm>")
			os.Exit(1)
		}
		fmt.Printf("solis inspect: VM %s inspection will be implemented here\n", os.Args[2])

	default:
		printUsage()
	}
}

func inventory() error {
	vms, err := readVMConfig("lab/config/vms.csv")
	if err != nil {
		return err
	}

	for i := range vms {
		vms[i].State = virshText("domstate", vms[i].Name)
		vms[i].IPLease = getLeaseIP(vms[i].Name)
		vms[i].Disk = getDiskPath(vms[i].Name)
		vms[i].QEMUPID = getQEMUPID(vms[i].Name)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTENANT\tROLE\tSTATE\tPLAN_IP\tLEASE_IP\tQEMU_PID\tDISK")
	for _, vm := range vms {
		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			vm.Name,
			vm.Tenant,
			vm.Role,
			emptyDash(vm.State),
			emptyDash(vm.IPPlan),
			emptyDash(vm.IPLease),
			emptyDash(vm.QEMUPID),
			emptyDash(vm.Disk),
		)
	}
	return w.Flush()
}

func readVMConfig(path string) ([]VM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1

	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	var vms []VM
	for i, row := range rows {
		if i == 0 {
			continue
		}
		if len(row) < 8 {
			continue
		}

		vms = append(vms, VM{
			Name:    strings.TrimSpace(row[0]),
			Tenant:  strings.TrimSpace(row[1]),
			Network: strings.TrimSpace(row[2]),
			IPPlan:  strings.TrimSpace(row[3]),
			Memory:  strings.TrimSpace(row[4]),
			VCPUs:   strings.TrimSpace(row[5]),
			DiskGB:  strings.TrimSpace(row[6]),
			Role:    strings.TrimSpace(row[7]),
		})
	}

	return vms, nil
}

func getLeaseIP(name string) string {
	out := virshText("domifaddr", name, "--source", "lease")
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for _, field := range fields {
			if strings.Contains(field, ".") && strings.Contains(field, "/") {
				return strings.Split(field, "/")[0]
			}
		}
	}
	return ""
}

func getDiskPath(name string) string {
	out := virshText("domblklist", name, "--details")
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == "disk" {
			return fields[3]
		}
	}
	return ""
}

func getQEMUPID(name string) string {
	if pid := readLibvirtPIDFile(name); pid != "" {
		return pid
	}

	if pid := findQEMUPIDFromPS(name); pid != "" {
		return pid
	}

	return ""
}

func readLibvirtPIDFile(name string) string {
	dirs := []string{
		"/run/libvirt/qemu",
		"/var/run/libvirt/qemu",
	}

	for _, dir := range dirs {
		candidates := []string{
			filepath.Join(dir, name+".pid"),
		}

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
				pid := strings.TrimSpace(string(b))
				if pid != "" {
					return pid
				}
			}
		}
	}

	return ""
}

func findQEMUPIDFromPS(name string) string {
	out, err := exec.Command("ps", "-eo", "pid=,args=").CombinedOutput()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		pid := fields[0]
		args := strings.Join(fields[1:], " ")

		if strings.Contains(args, "qemu-system") && strings.Contains(args, "guest="+name) {
			return pid
		}
	}

	return ""
}

func virshText(args ...string) string {
	cmd := exec.Command("virsh", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func emptyDash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return s
}

func printUsage() {
	fmt.Println(`Solis I/O

Usage:
  solis doctor
  solis inventory
  solis top
  solis inspect <vm>

Solis I/O is a Linux-only provider-side KVM storage latency attribution tool.`)
}
