package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const inventoryHeader = "name,tenant,network,ip,memory_mb,vcpus,disk_gb,role\n"

func TestLoadFromConfigStrictValidation(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"empty file", "", "inventory CSV is empty"},
		{"header only", inventoryHeader, "inventory contains no VM rows"},
		{"missing header", "name,tenant\na-web,tenant-a\n", "missing required headers"},
		{"duplicate name", inventoryHeader + validInventoryRow("a-web") + validInventoryRow("a-web"), "duplicate VM name \"a-web\""},
		{"invalid memory", inventoryHeader + "a-web,tenant-a,tenant-a-net,192.168.1.2,large,1,10,web\n", "memory_mb \"large\" must be a positive integer"},
		{"invalid vcpus", inventoryHeader + "a-web,tenant-a,tenant-a-net,192.168.1.2,1024,0,10,web\n", "vcpus \"0\" must be a positive integer"},
		{"invalid disk", inventoryHeader + "a-web,tenant-a,tenant-a-net,192.168.1.2,1024,1,-1,web\n", "disk_gb \"-1\" must be a positive integer"},
		{"empty tenant", inventoryHeader + "a-web,,tenant-a-net,192.168.1.2,1024,1,10,web\n", "tenant \"\" is empty or invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeInventory(t, test.data)
			_, err := LoadFromConfig(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadFromConfig() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestLoadFromConfigSupportsRequiredHeadersInDifferentOrder(t *testing.T) {
	path := writeInventory(t, "role,name,disk_gb,vcpus,memory_mb,ip,network,tenant\nweb,a-web,10,1,1024,192.168.1.2,tenant-a-net,tenant-a\n")
	vms, err := LoadFromConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 1 || vms[0].Name != "a-web" || vms[0].Memory != "1024" || vms[0].Role != "web" {
		t.Fatalf("VMs = %#v", vms)
	}
}

func writeInventory(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vms.csv")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validInventoryRow(name string) string {
	return name + ",tenant-a,tenant-a-net,192.168.1.2,1024,1,10,web\n"
}
