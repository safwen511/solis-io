package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// ObservabilityConfig contains opt-in definitions for local host, allowlisted
// guest/service, and future database collectors. Loading configuration alone
// never starts collection or contacts a guest or endpoint.
type ObservabilityConfig struct {
	Host      HostObservabilityConfig       `json:"host"`
	Guest     GuestObservabilityConfig      `json:"guest"`
	Services  []ServiceObservabilityConfig  `json:"services"`
	Databases []DatabaseObservabilityConfig `json:"databases"`
}

// HostObservabilityConfig controls the read-only local host status collector.
type HostObservabilityConfig struct {
	Enabled        bool   `json:"enabled"`
	Interval       string `json:"interval"`
	CollectPSI     bool   `json:"collect_psi"`
	CollectNetwork bool   `json:"collect_network"`
}

// GuestObservabilityConfig declares the opt-in allowlisted guest transport.
type GuestObservabilityConfig struct {
	Enabled        bool   `json:"enabled"`
	Transport      string `json:"transport"`
	User           string `json:"user"`
	ConnectTimeout string `json:"connect_timeout"`
	MaxParallel    int    `json:"max_parallel"`
	KnownHosts     string `json:"known_hosts"`
}

// ServiceObservabilityConfig defines allowlisted service metadata and health
// checks for one inventory VM. ID is optional; VM is the default identity.
type ServiceObservabilityConfig struct {
	ID           string              `json:"id,omitempty"`
	VM           string              `json:"vm"`
	Units        []string            `json:"units"`
	HealthChecks []HealthCheckConfig `json:"health_checks"`
}

// HealthCheckConfig contains only endpoint identity and timing metadata.
// CollectBody is an assertion that must remain false.
type HealthCheckConfig struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Port        int    `json:"port"`
	CollectBody bool   `json:"collect_body"`
}

// DatabaseObservabilityConfig defines one future fixed-query PostgreSQL
// statistics source. Raw SQL and table scanning are deliberately absent.
type DatabaseObservabilityConfig struct {
	VM                      string `json:"vm"`
	Kind                    string `json:"kind"`
	Database                string `json:"database"`
	CredentialRef           string `json:"credential_ref"`
	CollectPGStatStatements bool   `json:"collect_pg_stat_statements"`
}

// EffectiveObservability returns a detached configuration value with explicit
// empty service and database lists. Omitted observability therefore means all
// future collectors are disabled.
func (settings Settings) EffectiveObservability() ObservabilityConfig {
	if settings.Observability == nil {
		return ObservabilityConfig{
			Services:  []ServiceObservabilityConfig{},
			Databases: []DatabaseObservabilityConfig{},
		}
	}
	effective := *settings.Observability
	effective.Services = make([]ServiceObservabilityConfig, len(settings.Observability.Services))
	for index, service := range settings.Observability.Services {
		effective.Services[index] = service
		effective.Services[index].Units = append([]string(nil), service.Units...)
		effective.Services[index].HealthChecks = append([]HealthCheckConfig(nil), service.HealthChecks...)
	}
	effective.Databases = append([]DatabaseObservabilityConfig(nil), settings.Observability.Databases...)
	if effective.Services == nil {
		effective.Services = []ServiceObservabilityConfig{}
	}
	if effective.Databases == nil {
		effective.Databases = []DatabaseObservabilityConfig{}
	}
	return effective
}

// ValidateWithInventory applies normal configuration validation and rejects
// service or database VM references missing from the supplied inventory. A nil
// slice means no inventory context is available; an empty non-nil slice means
// an available inventory with no VMs.
func ValidateWithInventory(settings Settings, vmNames []string) error {
	if err := Validate(settings); err != nil {
		return err
	}
	if vmNames == nil || settings.Observability == nil {
		return nil
	}
	known := make(map[string]struct{}, len(vmNames))
	for _, name := range vmNames {
		name = strings.TrimSpace(name)
		if name != "" {
			known[name] = struct{}{}
		}
	}
	for _, service := range settings.Observability.Services {
		if _, ok := known[strings.TrimSpace(service.VM)]; !ok {
			return fmt.Errorf("observability service %q references unknown VM %q", serviceIdentity(service), service.VM)
		}
	}
	for _, database := range settings.Observability.Databases {
		if _, ok := known[strings.TrimSpace(database.VM)]; !ok {
			return fmt.Errorf("observability database %q references unknown VM %q", database.Database, database.VM)
		}
	}
	return nil
}

func validateObservability(observability *ObservabilityConfig) error {
	if observability == nil {
		return nil
	}
	if err := validateOptionalDuration("observability.host.interval", observability.Host.Interval, observability.Host.Enabled); err != nil {
		return err
	}
	if err := validateGuestObservability(observability.Guest); err != nil {
		return err
	}
	if err := validateServices(observability.Services); err != nil {
		return err
	}
	return validateDatabases(observability.Databases)
}

func validateGuestObservability(guest GuestObservabilityConfig) error {
	transport := strings.TrimSpace(guest.Transport)
	if transport != "" && transport != "ssh" {
		return fmt.Errorf("observability.guest.transport %q is unsupported; supported transport is \"ssh\"", guest.Transport)
	}
	if guest.MaxParallel < 0 || guest.Enabled && guest.MaxParallel <= 0 {
		return errors.New("observability.guest.max_parallel must be positive when guest collection is enabled")
	}
	if err := validateOptionalDuration("observability.guest.connect_timeout", guest.ConnectTimeout, guest.Enabled); err != nil {
		return err
	}
	if !guest.Enabled {
		return nil
	}
	if transport == "" {
		return errors.New("observability.guest.transport is required when guest collection is enabled")
	}
	if strings.TrimSpace(guest.User) == "" || containsSpaceOrControl(guest.User) {
		return errors.New("observability.guest.user is required and must not contain whitespace when guest collection is enabled")
	}
	if strings.TrimSpace(guest.KnownHosts) == "" {
		return errors.New("observability.guest.known_hosts is required when guest collection is enabled")
	}
	return nil
}

func validateServices(services []ServiceObservabilityConfig) error {
	seenServices := make(map[string]struct{}, len(services))
	for index, service := range services {
		if strings.TrimSpace(service.VM) == "" {
			return fmt.Errorf("observability.services[%d].vm is required", index)
		}
		identity := serviceIdentity(service)
		if containsSpaceOrControl(identity) {
			return fmt.Errorf("observability service ID %q must not contain whitespace", identity)
		}
		if _, duplicate := seenServices[identity]; duplicate {
			return fmt.Errorf("duplicate observability service ID %q", identity)
		}
		seenServices[identity] = struct{}{}

		seenUnits := make(map[string]struct{}, len(service.Units))
		for _, unit := range service.Units {
			unit = strings.TrimSpace(unit)
			if !validSystemdUnit(unit) {
				return fmt.Errorf("observability service %q has invalid systemd unit %q", identity, unit)
			}
			if _, duplicate := seenUnits[unit]; duplicate {
				return fmt.Errorf("observability service %q has duplicate systemd unit %q", identity, unit)
			}
			seenUnits[unit] = struct{}{}
		}

		seenHealthChecks := make(map[string]struct{}, len(service.HealthChecks))
		for _, health := range service.HealthChecks {
			name := strings.TrimSpace(health.Name)
			if name == "" {
				return fmt.Errorf("observability service %q has a health check with an empty name", identity)
			}
			if _, duplicate := seenHealthChecks[name]; duplicate {
				return fmt.Errorf("observability service %q has duplicate health-check name %q", identity, name)
			}
			seenHealthChecks[name] = struct{}{}
			if err := validateHealthCheck(identity, health); err != nil {
				return err
			}
		}
	}
	return nil
}

func validSystemdUnit(unit string) bool {
	if unit == "" || !strings.HasSuffix(unit, ".service") {
		return false
	}
	for _, character := range unit {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("_.@:-", character) {
			continue
		}
		return false
	}
	return true
}

func validateHealthCheck(service string, health HealthCheckConfig) error {
	path := strings.TrimSpace(health.Path)
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "://") {
		return fmt.Errorf("observability service %q health check %q path must start with \"/\" and must not contain a URL scheme", service, health.Name)
	}
	if health.Port <= 0 || health.Port > 65535 {
		return fmt.Errorf("observability service %q health check %q port must be between 1 and 65535", service, health.Name)
	}
	if health.CollectBody {
		return fmt.Errorf("observability service %q health check %q collect_body must be false; body collection is not supported", service, health.Name)
	}
	return nil
}

func validateDatabases(databases []DatabaseObservabilityConfig) error {
	seen := make(map[string]struct{}, len(databases))
	for index, database := range databases {
		vm := strings.TrimSpace(database.VM)
		name := strings.TrimSpace(database.Database)
		if vm == "" {
			return fmt.Errorf("observability.databases[%d].vm is required", index)
		}
		if strings.TrimSpace(database.Kind) != "postgresql" {
			return fmt.Errorf("observability database %q kind %q is unsupported; supported kind is \"postgresql\"", name, database.Kind)
		}
		if name == "" || containsSpaceOrControl(name) {
			return fmt.Errorf("observability database for VM %q requires a database name without whitespace", vm)
		}
		identity := vm + "/" + name
		if _, duplicate := seen[identity]; duplicate {
			return fmt.Errorf("duplicate observability database %q", identity)
		}
		seen[identity] = struct{}{}
		if err := validateCredentialRef(database.CredentialRef); err != nil {
			return fmt.Errorf("observability database %q: %w", identity, err)
		}
	}
	return nil
}

func validateCredentialRef(reference string) error {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return nil
	}
	approved := []string{"systemd-credential:", "file:", "env:"}
	for _, prefix := range approved {
		if strings.HasPrefix(reference, prefix) {
			if strings.TrimSpace(strings.TrimPrefix(reference, prefix)) == "" {
				return fmt.Errorf("credential_ref using %q requires a non-empty reference", prefix)
			}
			if strings.ContainsAny(reference, "\r\n\x00") {
				return errors.New("credential_ref must not contain control characters")
			}
			return nil
		}
	}
	return errors.New("credential_ref must be empty or use systemd-credential:, file:, or env:")
}

func validateOptionalDuration(field, value string, required bool) error {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return fmt.Errorf("%s is required when its collector is enabled", field)
		}
		return nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return fmt.Errorf("%s %q must be a positive Go duration", field, value)
	}
	return nil
}

func serviceIdentity(service ServiceObservabilityConfig) string {
	if id := strings.TrimSpace(service.ID); id != "" {
		return id
	}
	return strings.TrimSpace(service.VM)
}

func containsSpaceOrControl(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.IsControl(character)
	}) >= 0
}

func rejectUnsafeConfig(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	return walkConfigValue(value, "")
}

func walkConfigValue(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			if unsafeSecretKey(key) {
				return fmt.Errorf("inline credential, password, token, or secret field %q is not allowed; use credential_ref", childPath)
			}
			if forbiddenCollectorKey(key) {
				return fmt.Errorf("unsafe observability field %q is not supported", childPath)
			}
			if err := walkConfigValue(child, childPath); err != nil {
				return err
			}
		}
	case []any:
		for index, child := range typed {
			if err := walkConfigValue(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func unsafeSecretKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
	if normalized == "credential_ref" {
		return false
	}
	return strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "token") ||
		strings.Contains(normalized, "secret") ||
		normalized == "credential" || normalized == "credentials" ||
		normalized == "credential_value" || normalized == "api_key" ||
		normalized == "private_key"
}

func forbiddenCollectorKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
	forbidden := map[string]struct{}{
		"command": {}, "commands": {}, "ssh_command": {},
		"sql": {}, "raw_sql": {}, "query": {}, "queries": {},
		"table": {}, "tables": {}, "scan_tables": {},
		"journal": {}, "collect_journal": {},
		"process_arguments": {}, "collect_process_arguments": {},
		"environment": {}, "collect_environment": {},
		"request_body": {}, "response_body": {},
	}
	_, blocked := forbidden[normalized]
	return blocked
}
