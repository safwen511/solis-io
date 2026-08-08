package inventory

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

// LoadFromConfig reads VM definitions from a Solis CSV config file.
func LoadFromConfig(path string) ([]VM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open VM config %q: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1

	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read VM config %q: %w", path, err)
	}

	var vms []VM
	for i, row := range rows {
		if i == 0 || len(row) < 8 {
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
