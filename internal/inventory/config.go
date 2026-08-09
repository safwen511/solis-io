package inventory

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

var requiredHeaders = []string{"name", "tenant", "network", "ip", "memory_mb", "vcpus", "disk_gb", "role"}

// LoadFromConfig reads VM definitions from a Solis CSV config file.
func LoadFromConfig(path string) ([]VM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open VM config %q: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("read VM config %q: inventory CSV is empty", path)
		}
		return nil, fmt.Errorf("read VM config %q header: %w", path, err)
	}
	indexes, err := validateHeader(header)
	if err != nil {
		return nil, fmt.Errorf("validate VM config %q header: %w", path, err)
	}
	r.FieldsPerRecord = len(header)

	seenNames := make(map[string]int)
	var vms []VM
	for rowNumber := 2; ; rowNumber++ {
		row, readErr := r.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read VM config %q row %d: %w", path, rowNumber, readErr)
		}
		vm := VM{
			Name:    field(row, indexes, "name"),
			Tenant:  field(row, indexes, "tenant"),
			Network: field(row, indexes, "network"),
			IPPlan:  field(row, indexes, "ip"),
			Memory:  field(row, indexes, "memory_mb"),
			VCPUs:   field(row, indexes, "vcpus"),
			DiskGB:  field(row, indexes, "disk_gb"),
			Role:    field(row, indexes, "role"),
		}
		if err := validateVMRow(vm); err != nil {
			return nil, fmt.Errorf("validate VM config %q row %d: %w", path, rowNumber, err)
		}
		if firstRow, duplicate := seenNames[vm.Name]; duplicate {
			return nil, fmt.Errorf("validate VM config %q row %d: duplicate VM name %q (first defined on row %d)", path, rowNumber, vm.Name, firstRow)
		}
		seenNames[vm.Name] = rowNumber
		vms = append(vms, vm)
	}
	if len(vms) == 0 {
		return nil, fmt.Errorf("validate VM config %q: inventory contains no VM rows", path)
	}
	return vms, nil
}

func validateHeader(header []string) (map[string]int, error) {
	indexes := make(map[string]int, len(header))
	for index, value := range header {
		name := strings.TrimSpace(strings.TrimPrefix(value, "\ufeff"))
		if name == "" {
			return nil, fmt.Errorf("header column %d is empty", index+1)
		}
		if _, duplicate := indexes[name]; duplicate {
			return nil, fmt.Errorf("duplicate header %q", name)
		}
		indexes[name] = index
	}
	var missing []string
	for _, name := range requiredHeaders {
		if _, ok := indexes[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required headers: %s", strings.Join(missing, ", "))
	}
	return indexes, nil
}

func field(row []string, indexes map[string]int, name string) string {
	return strings.TrimSpace(row[indexes[name]])
}

func validateVMRow(vm VM) error {
	identifiers := []struct{ name, value string }{
		{"name", vm.Name},
		{"tenant", vm.Tenant},
		{"network", vm.Network},
		{"role", vm.Role},
	}
	for _, identifier := range identifiers {
		name, value := identifier.name, identifier.value
		if !validIdentifier(value) {
			return fmt.Errorf("%s %q is empty or invalid; use letters, numbers, dot, dash, or underscore", name, value)
		}
	}
	if net.ParseIP(vm.IPPlan) == nil {
		return fmt.Errorf("ip %q is empty or invalid", vm.IPPlan)
	}
	numericFields := []struct{ name, value string }{
		{"memory_mb", vm.Memory},
		{"vcpus", vm.VCPUs},
		{"disk_gb", vm.DiskGB},
	}
	for _, numericField := range numericFields {
		name, value := numericField.name, numericField.value
		number, err := strconv.Atoi(value)
		if err != nil || number <= 0 {
			return fmt.Errorf("%s %q must be a positive integer", name, value)
		}
	}
	return nil
}

func validIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for index, char := range value {
		valid := char >= 'a' && char <= 'z' ||
			char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' ||
			char == '.' || char == '-' || char == '_'
		if !valid || index == 0 && (char == '.' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}
