package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/safwen511/solis-io/internal/version"
)

const (
	manifestFilename      = "manifest.json"
	manifestSchemaVersion = "1"
)

// Manifest records the integrity metadata for every other capture artifact.
// The manifest does not include itself because a stable self-checksum is not
// possible.
type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	CaptureID     string         `json:"capture_id"`
	CreatedAtUTC  string         `json:"created_at_utc"`
	Build         version.Info   `json:"build"`
	Files         []ManifestFile `json:"files"`
}

// ManifestFile records one capture artifact without including its contents.
type ManifestFile struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
	Mode      string `json:"mode"`
}

func buildManifest(directory, captureID string, createdAt time.Time, names []string) (Manifest, error) {
	sortedNames := append([]string(nil), names...)
	sort.Strings(sortedNames)
	manifest := Manifest{
		SchemaVersion: manifestSchemaVersion,
		CaptureID:     captureID,
		CreatedAtUTC:  createdAt.UTC().Format(time.RFC3339Nano),
		Build:         version.BuildInfo(),
		Files:         make([]ManifestFile, 0, len(sortedNames)),
	}
	for _, name := range sortedNames {
		if err := validateArtifactName(name); err != nil {
			return Manifest{}, err
		}
		entry, err := manifestFile(filepath.Join(directory, name), name)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Files = append(manifest.Files, entry)
	}
	return manifest, nil
}

func validateArtifactName(name string) error {
	if filepath.Base(name) != name || name == "." || name == manifestFilename {
		return fmt.Errorf("invalid capture artifact name %q", name)
	}
	return nil
}

func manifestFile(path, name string) (ManifestFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("open capture artifact %q for manifest: %w", path, err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		_ = file.Close()
		return ManifestFile{}, fmt.Errorf("checksum capture artifact %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return ManifestFile{}, fmt.Errorf("close capture artifact %q after checksum: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("stat capture artifact %q for manifest: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return ManifestFile{}, fmt.Errorf("capture artifact %q is not a regular file", path)
	}
	return ManifestFile{
		Path:      name,
		SizeBytes: info.Size(),
		SHA256:    hex.EncodeToString(hash.Sum(nil)),
		Mode:      fmt.Sprintf("%04o", info.Mode().Perm()),
	}, nil
}

// WriteManifest writes deterministic, human-readable JSON.
func WriteManifest(dst io.Writer, manifest Manifest) error {
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(manifest)
}
