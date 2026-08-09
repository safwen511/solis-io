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
		{"unsupported schema", strings.Replace(validConfigJSON("inventory.csv"), `"schema_version":"1"`, `"schema_version":"3"`, 1), "unsupported schema_version"},
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

func TestLoadPreservesSchemaVersionOne(t *testing.T) {
	runtime, err := Load(writeConfig(t, validConfigJSON("inventory.csv")))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Settings.SchemaVersion != SchemaVersion || runtime.Settings.Observability != nil {
		t.Fatalf("settings = %#v", runtime.Settings)
	}
}

func TestLoadSchemaVersionTwoObservability(t *testing.T) {
	path := writeConfig(t, validConfigV2JSON("inventory.csv"))
	runtime, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	settings := runtime.Settings
	if settings.SchemaVersion != SchemaVersion2 || settings.Observability == nil {
		t.Fatalf("settings = %#v", settings)
	}
	observability := settings.EffectiveObservability()
	if !observability.Host.Enabled || observability.Host.Interval != "1s" {
		t.Fatalf("host = %#v", observability.Host)
	}
	if observability.Guest.Enabled {
		t.Fatalf("guest collection unexpectedly enabled: %#v", observability.Guest)
	}
	if !filepath.IsAbs(observability.Guest.KnownHosts) || filepath.Base(observability.Guest.KnownHosts) != "known_hosts" {
		t.Fatalf("known_hosts = %q", observability.Guest.KnownHosts)
	}
	if len(observability.Services) != 1 || len(observability.Databases) != 1 {
		t.Fatalf("observability = %#v", observability)
	}
}

func TestSchemaVersionTwoObservabilityDefaultsDisabled(t *testing.T) {
	data := strings.Replace(validConfigJSON("inventory.csv"), `"schema_version":"1"`, `"schema_version":"2"`, 1)
	runtime, err := Load(writeConfig(t, data))
	if err != nil {
		t.Fatal(err)
	}
	observability := runtime.Settings.EffectiveObservability()
	if observability.Guest.Enabled || observability.Host.Enabled {
		t.Fatalf("collectors unexpectedly enabled: %#v", observability)
	}
	if observability.Databases == nil || len(observability.Databases) != 0 {
		t.Fatalf("databases = %#v", observability.Databases)
	}
}

func TestValidateObservabilityRejectsUnsafeValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Settings)
		want   string
	}{
		{
			name: "invalid duration",
			mutate: func(settings *Settings) {
				settings.Observability.Host.Interval = "immediately"
			},
			want: "positive Go duration",
		},
		{
			name: "duplicate health check",
			mutate: func(settings *Settings) {
				health := settings.Observability.Services[0].HealthChecks[0]
				settings.Observability.Services[0].HealthChecks = append(settings.Observability.Services[0].HealthChecks, health)
			},
			want: "duplicate health-check name",
		},
		{
			name: "duplicate service ID",
			mutate: func(settings *Settings) {
				service := settings.Observability.Services[0]
				settings.Observability.Services = append(settings.Observability.Services, service)
			},
			want: "duplicate observability service ID",
		},
		{
			name: "body collection",
			mutate: func(settings *Settings) {
				settings.Observability.Services[0].HealthChecks[0].CollectBody = true
			},
			want: "collect_body must be false",
		},
		{
			name: "unsupported transport",
			mutate: func(settings *Settings) {
				settings.Observability.Guest.Transport = "winrm"
			},
			want: "unsupported",
		},
		{
			name: "unsafe systemd unit",
			mutate: func(settings *Settings) {
				settings.Observability.Services[0].Units[0] = "nginx.service;id"
			},
			want: "invalid systemd unit",
		},
		{
			name: "unapproved credential reference",
			mutate: func(settings *Settings) {
				settings.Observability.Databases[0].CredentialRef = "plain-text-value"
			},
			want: "credential_ref must be empty or use",
		},
		{
			name: "unsupported database kind",
			mutate: func(settings *Settings) {
				settings.Observability.Databases[0].Kind = "mysql"
			},
			want: "kind \"mysql\" is unsupported",
		},
		{
			name: "unsafe database name",
			mutate: func(settings *Settings) {
				settings.Observability.Databases[0].Database = "postgres;id"
			},
			want: "requires a database name using",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := validSchema2Settings()
			test.mutate(&settings)
			if err := Validate(settings); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestLoadRejectsInlineCredentialsAndUnsafeCollectorFields(t *testing.T) {
	tests := []struct {
		name  string
		field string
		want  string
	}{
		{"password", `"password":"solispass",`, "inline credential"},
		{"token", `"api_token":"token-value",`, "inline credential"},
		{"secret", `"client_secret":"secret-value",`, "inline credential"},
		{"arbitrary SSH command", `"ssh_command":"cat /etc/shadow",`, "unsafe observability field"},
		{"raw SQL", `"raw_sql":"SELECT * FROM customers",`, "unsafe observability field"},
		{"table scan field", `"scan_tables":["customers"],`, "unsafe observability field"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := strings.Replace(validConfigV2JSON("inventory.csv"), `"credential_ref":`, test.field+`"credential_ref":`, 1)
			_, err := Load(writeConfig(t, data))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestValidateWithInventoryRejectsUnknownVM(t *testing.T) {
	settings := validSchema2Settings()
	if err := ValidateWithInventory(settings, []string{"a-web", "a-db"}); err != nil {
		t.Fatalf("known inventory rejected: %v", err)
	}
	settings.Observability.Services[0].VM = "missing-web"
	err := ValidateWithInventory(settings, []string{"a-web", "a-db"})
	if err == nil || !strings.Contains(err.Error(), `unknown VM "missing-web"`) {
		t.Fatalf("ValidateWithInventory() error = %v", err)
	}
}

func TestSchemaVersionOneRejectsObservability(t *testing.T) {
	settings := validSchema2Settings()
	settings.SchemaVersion = SchemaVersion
	err := Validate(settings)
	if err == nil || !strings.Contains(err.Error(), "observability requires schema_version") {
		t.Fatalf("Validate() error = %v", err)
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

func validConfigV2JSON(inventory string) string {
	return `{
  "schema_version":"2",
  "inventory_csv":"` + inventory + `",
  "capture_output_root":"captures",
  "default_report_dir":"reports/default",
  "libvirt_uri":"qemu:///system",
  "thresholds":{"write_mib_per_sec":10,"write_syscalls_per_sec":10000,"dominance_ratio":2},
  "observability":{
    "host":{"enabled":true,"interval":"1s","collect_psi":true,"collect_network":true},
    "guest":{"enabled":false,"transport":"ssh","user":"flint","connect_timeout":"5s","max_parallel":4,"known_hosts":"known_hosts"},
    "services":[{"vm":"a-web","units":["nginx.service","solis-workload.service"],"health_checks":[{"name":"web-health","path":"/health","port":80,"collect_body":false}]}],
    "databases":[{"vm":"a-db","kind":"postgresql","database":"postgres","credential_ref":"systemd-credential:solis-a-db-monitor","collect_pg_stat_statements":true}]
  }
}`
}

func validSchema2Settings() Settings {
	return Settings{
		SchemaVersion:     SchemaVersion2,
		InventoryCSV:      "inventory.csv",
		CaptureOutputRoot: "captures",
		LibvirtURI:        "qemu:///system",
		Thresholds:        DefaultThresholds(),
		Observability: &ObservabilityConfig{
			Host: HostObservabilityConfig{Enabled: true, Interval: "1s"},
			Guest: GuestObservabilityConfig{
				Transport:      "ssh",
				User:           "flint",
				ConnectTimeout: "5s",
				MaxParallel:    4,
				KnownHosts:     "known_hosts",
			},
			Services: []ServiceObservabilityConfig{{
				VM:    "a-web",
				Units: []string{"nginx.service"},
				HealthChecks: []HealthCheckConfig{{
					Name: "web-health", Path: "/health", Port: 80,
				}},
			}},
			Databases: []DatabaseObservabilityConfig{{
				VM: "a-db", Kind: "postgresql", Database: "postgres",
				CredentialRef: "systemd-credential:solis-a-db-monitor",
			}},
		},
	}
}
