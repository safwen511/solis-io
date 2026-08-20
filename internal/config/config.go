// Package config loads and validates portable Solis runtime configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	SchemaVersion          = "1"
	SchemaVersion2         = "2"
	EnvironmentVariable    = "SOLIS_CONFIG"
	BuiltInDefaultsSource  = "built-in defaults"
	defaultInventoryCSV    = "lab/config/vms.csv"
	defaultCaptureRoot     = "lab/reports/captures"
	defaultReportDirectory = "lab/reports/workload/20260808T174825Z"
	defaultLibvirtURI      = "qemu:///system"
)

// InstalledDefaultPath may be set at build time for an installed binary. It is
// intentionally empty in normal development and release builds unless an
// installer explicitly supplies a root-owned default configuration path.
var InstalledDefaultPath string

// Thresholds controls conservative QEMU writer attribution.
type Thresholds struct {
	WriteMiBPerSecond      float64 `json:"write_mib_per_sec"`
	WriteSyscallsPerSecond float64 `json:"write_syscalls_per_sec"`
	DominanceRatio         float64 `json:"dominance_ratio"`
}

// Settings is the versioned on-disk Solis configuration model.
type Settings struct {
	SchemaVersion     string               `json:"schema_version"`
	InventoryCSV      string               `json:"inventory_csv"`
	CaptureOutputRoot string               `json:"capture_output_root"`
	DefaultReportDir  string               `json:"default_report_dir"`
	LibvirtURI        string               `json:"libvirt_uri"`
	Thresholds        Thresholds           `json:"thresholds"`
	Observability     *ObservabilityConfig `json:"observability,omitempty"`
}

// Runtime contains validated settings and their effective source.
type Runtime struct {
	Settings Settings
	Source   string
	Path     string
	BaseDir  string
}

// DevelopmentDefaults returns the repository-relative lab defaults.
func DevelopmentDefaults() Runtime {
	return Runtime{
		Settings: Settings{
			SchemaVersion:     SchemaVersion,
			InventoryCSV:      defaultInventoryCSV,
			CaptureOutputRoot: defaultCaptureRoot,
			DefaultReportDir:  defaultReportDirectory,
			LibvirtURI:        defaultLibvirtURI,
			Thresholds:        DefaultThresholds(),
		},
		Source:  BuiltInDefaultsSource,
		BaseDir: ".",
	}
}

// DefaultThresholds returns the current conservative attribution defaults.
func DefaultThresholds() Thresholds {
	return Thresholds{
		WriteMiBPerSecond:      10,
		WriteSyscallsPerSecond: 10000,
		DominanceRatio:         2,
	}
}

// Resolve removes the optional global --config flag, applies precedence over
// SOLIS_CONFIG, and returns validated runtime settings plus command arguments.
func Resolve(args []string, environmentPath string) (Runtime, []string, error) {
	flagPath, remaining, err := extractConfigFlag(args)
	if err != nil {
		return Runtime{}, nil, err
	}
	path := strings.TrimSpace(flagPath)
	if path == "" {
		path = strings.TrimSpace(environmentPath)
	}
	if path == "" {
		path = strings.TrimSpace(InstalledDefaultPath)
	}
	if path == "" {
		return DevelopmentDefaults(), remaining, nil
	}
	runtime, err := Load(path)
	if err != nil {
		return Runtime{}, nil, err
	}
	return runtime, remaining, nil
}

// Load reads one strict JSON configuration and resolves relative paths against
// the directory containing that configuration file.
func Load(path string) (Runtime, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Runtime{}, fmt.Errorf("resolve config path %q: %w", path, err)
	}
	file, err := os.Open(absPath)
	if err != nil {
		return Runtime{}, fmt.Errorf("open Solis config %q: %w", absPath, err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return Runtime{}, fmt.Errorf("read Solis config %q: %w", absPath, err)
	}
	if err := rejectUnsafeConfig(data); err != nil {
		return Runtime{}, fmt.Errorf("parse Solis config %q: %w", absPath, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var settings Settings
	if err := decoder.Decode(&settings); err != nil {
		return Runtime{}, fmt.Errorf("parse Solis config %q: %w", absPath, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Runtime{}, fmt.Errorf("parse Solis config %q: %w", absPath, err)
	}
	if err := Validate(settings); err != nil {
		return Runtime{}, fmt.Errorf("validate Solis config %q: %w", absPath, err)
	}

	baseDir := filepath.Dir(absPath)
	settings.InventoryCSV = resolveRelativePath(baseDir, settings.InventoryCSV)
	settings.CaptureOutputRoot = resolveRelativePath(baseDir, settings.CaptureOutputRoot)
	settings.DefaultReportDir = resolveRelativePath(baseDir, settings.DefaultReportDir)
	if settings.Observability != nil {
		settings.Observability.Guest.KnownHosts = resolveRelativePath(baseDir, settings.Observability.Guest.KnownHosts)
	}
	return Runtime{
		Settings: settings,
		Source:   absPath,
		Path:     absPath,
		BaseDir:  baseDir,
	}, nil
}

// Validate enforces the supported schema and required production settings.
func Validate(settings Settings) error {
	schemaVersion := strings.TrimSpace(settings.SchemaVersion)
	if schemaVersion != SchemaVersion && schemaVersion != SchemaVersion2 {
		return fmt.Errorf("unsupported schema_version %q; supported versions are %q and %q", settings.SchemaVersion, SchemaVersion, SchemaVersion2)
	}
	if schemaVersion == SchemaVersion && settings.Observability != nil {
		return errors.New("observability requires schema_version \"2\"")
	}
	if strings.TrimSpace(settings.InventoryCSV) == "" {
		return errors.New("inventory_csv is required")
	}
	if strings.TrimSpace(settings.CaptureOutputRoot) == "" {
		return errors.New("capture_output_root is required")
	}
	if strings.TrimSpace(settings.LibvirtURI) == "" {
		return errors.New("libvirt_uri is required")
	}
	if settings.Thresholds.WriteMiBPerSecond <= 0 {
		return errors.New("thresholds.write_mib_per_sec must be greater than zero")
	}
	if settings.Thresholds.WriteSyscallsPerSecond <= 0 {
		return errors.New("thresholds.write_syscalls_per_sec must be greater than zero")
	}
	if settings.Thresholds.DominanceRatio < 1 {
		return errors.New("thresholds.dominance_ratio must be at least 1")
	}
	return validateObservability(settings.Observability)
}

// extractConfigFlag extracts config flag from validated source data.
func extractConfigFlag(args []string) (string, []string, error) {
	remaining := make([]string, 0, len(args))
	var path string
	seen := false
	for index := 0; index < len(args); index++ {
		if args[index] != "--config" {
			remaining = append(remaining, args[index])
			continue
		}
		if seen {
			return "", nil, errors.New("--config specified more than once")
		}
		if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
			return "", nil, errors.New("--config requires a path")
		}
		path = strings.TrimSpace(args[index+1])
		if path == "" {
			return "", nil, errors.New("--config requires a non-empty path")
		}
		seen = true
		index++
	}
	return path, remaining, nil
}

// ensureJSONEOF ensures jsoneof satisfies the required invariant.
func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values are not allowed")
	}
	return err
}

// resolveRelativePath resolves relative path from the available inputs.
func resolveRelativePath(baseDir, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(baseDir, value))
}
