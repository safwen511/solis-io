package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveUsesDevelopmentDefaults(t *testing.T) {
	runtime, args, err := Resolve([]string{"inventory"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Source != BuiltInDefaultsSource || runtime.Settings.InventoryCSV != "lab/config/vms.csv" {
		t.Fatalf("runtime = %#v", runtime)
	}
	if len(args) != 1 || args[0] != "inventory" {
		t.Fatalf("args = %v", args)
	}
}

func TestResolveLoadsFlagBeforeOrAfterCommand(t *testing.T) {
	path := writeConfig(t, validConfigJSON("inventory.csv"))
	for _, args := range [][]string{
		{"--config", path, "status"},
		{"status", "--config", path},
	} {
		runtime, remaining, err := Resolve(args, "")
		if err != nil {
			t.Fatal(err)
		}
		if runtime.Path != path || len(remaining) != 1 || remaining[0] != "status" {
			t.Fatalf("runtime/args = %#v, %v", runtime, remaining)
		}
	}
}

func TestResolveLoadsEnvironmentAndFlagWins(t *testing.T) {
	environmentPath := writeNamedConfig(t, "environment.json", validConfigJSON("environment.csv"))
	flagPath := writeNamedConfig(t, "flag.json", validConfigJSON("flag.csv"))

	runtime, _, err := Resolve([]string{"inventory"}, environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Path != environmentPath || filepath.Base(runtime.Settings.InventoryCSV) != "environment.csv" {
		t.Fatalf("environment runtime = %#v", runtime)
	}

	runtime, _, err = Resolve([]string{"inventory", "--config", flagPath}, environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Path != flagPath || filepath.Base(runtime.Settings.InventoryCSV) != "flag.csv" {
		t.Fatalf("flag runtime = %#v", runtime)
	}
}

func TestLoadReportsUsefulErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"malformed JSON", `{`, "parse Solis config"},
		{"unsupported schema", strings.Replace(validConfigJSON("inventory.csv"), `"schema_version":"1"`, `"schema_version":"2"`, 1), "unsupported schema_version"},
		{"missing inventory", strings.Replace(validConfigJSON("inventory.csv"), `"inventory_csv":"inventory.csv"`, `"inventory_csv":""`, 1), "inventory_csv is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, test.data)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "open Solis config") {
		t.Fatalf("Load() error = %v", err)
	}
}

func writeConfig(t *testing.T, data string) string {
	t.Helper()
	return writeNamedConfig(t, "solis.json", data)
}

func writeNamedConfig(t *testing.T, name, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return absPath
}

func validConfigJSON(inventory string) string {
	return `{"schema_version":"1","inventory_csv":"` + inventory + `","capture_output_root":"captures","default_report_dir":"reports/default","libvirt_uri":"qemu:///system","thresholds":{"write_mib_per_sec":10,"write_syscalls_per_sec":10000,"dominance_ratio":2}}`
}
