package storagevm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteJSONFileIsPrivateAndReplacesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "stats.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	report := VMStorageStatsReport{SchemaVersion: SchemaVersion, VMs: []VMStorageStatsVM{{Name: "a-web"}}}
	if err := WriteJSONFile(path, report); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "old") || !strings.Contains(string(data), `"name": "a-web"`) {
		t.Fatalf("output = %s", data)
	}
}

func TestWriteJSONFileRejectsSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "stats.json")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := WriteJSONFile(link, VMStorageStatsReport{})
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("error = %v", err)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil || string(data) != "unchanged" {
		t.Fatalf("symlink destination changed: %q, error = %v", data, readErr)
	}
}

func TestWriteJSONFileCleansTempOnRenderFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "stats.json")
	report := VMStorageStatsReport{}
	report.Privacy.SecretsCollected = true
	if err := WriteJSONFile(path, report); err == nil {
		t.Fatal("expected privacy failure")
	}
	matches, err := filepath.Glob(filepath.Join(root, ".stats.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %#v", matches)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("final output exists after failure: %v", err)
	}
}
