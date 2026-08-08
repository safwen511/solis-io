package inventory

// VM contains configured VM metadata and values discovered from the host.
type VM struct {
	Name        string
	Tenant      string
	Network     string
	IPPlan      string
	Memory      string
	VCPUs       string
	DiskGB      string
	Role        string
	State       string
	IPLease     string
	Disk        string
	QEMUPID     string
	QEMUCmdline string
}

// FindByName returns the VM with the exact requested name.
func FindByName(vms []VM, name string) (*VM, bool) {
	for i := range vms {
		if vms[i].Name == name {
			return &vms[i], true
		}
	}

	return nil, false
}
