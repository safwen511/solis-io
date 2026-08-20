//go:build linux

package output

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWritePrivateAtomicFileIsPrivateAndReplacesRegularFile verifies write private atomic file is
// private and replaces regular file.
func TestWritePrivateAtomicFileIsPrivateAndReplacesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "report.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateAtomicFile(path, writePrivateFixture(`{"status":"new"}`)); err != nil {
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
	if string(data) != `{"status":"new"}` {
		t.Fatalf("output = %q", data)
	}
}

// TestWritePrivateAtomicFileRejectsMissingParent verifies write private atomic file rejects missing
// parent.
func TestWritePrivateAtomicFileRejectsMissingParent(t *testing.T) {
	root := t.TempDir()
	missingParent := filepath.Join(root, "missing", "nested")
	path := filepath.Join(missingParent, "report.json")
	err := WritePrivateAtomicFile(path, writePrivateFixture("data"))
	if !errors.Is(err, ErrParentDirectoryMissing) || !strings.Contains(err.Error(), "parent_directory_missing") {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Lstat(missingParent); !os.IsNotExist(statErr) {
		t.Fatalf("missing parent was created: %v", statErr)
	}
}

// TestWritePrivateAtomicFileRejectsSymlinkTarget verifies write private atomic file rejects symlink
// target.
func TestWritePrivateAtomicFileRejectsSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	link := filepath.Join(root, "report.json")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := WritePrivateAtomicFile(link, writePrivateFixture("replacement"))
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("error = %v", err)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil || string(data) != "unchanged" {
		t.Fatalf("symlink destination changed: %q, error = %v", data, readErr)
	}
}

// TestWritePrivateAtomicFileRejectsParentSymlink verifies write private atomic file rejects parent
// symlink.
func TestWritePrivateAtomicFileRejectsParentSymlink(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(root, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	err := WritePrivateAtomicFile(filepath.Join(linkedParent, "report.json"), writePrivateFixture("data"))
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(realParent, "report.json")); !os.IsNotExist(err) {
		t.Fatalf("output unexpectedly created through parent symlink: %v", err)
	}
}

// TestWritePrivateAtomicFileRejectsNonRegularTarget verifies write private atomic file rejects non
// regular target.
func TestWritePrivateAtomicFileRejectsNonRegularTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err := WritePrivateAtomicFile(path, writePrivateFixture("data"))
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error = %v", err)
	}
}

// TestWritePrivateAtomicFileCleansTemporaryFileOnRenderFailure verifies write private atomic file
// cleans temporary file on render failure.
func TestWritePrivateAtomicFileCleansTemporaryFileOnRenderFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "report.json")
	err := WritePrivateAtomicFile(path, func(io.Writer) error { return errors.New("render failed") })
	if err == nil || !strings.Contains(err.Error(), "render failed") {
		t.Fatalf("error = %v", err)
	}
	matches, globErr := filepath.Glob(filepath.Join(root, ".solis-tmp-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %#v", matches)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("final output exists after render failure: %v", err)
	}
}

// TestWritePrivateAtomicFileIsDeterministicForDeterministicRenderer verifies write private atomic
// file is deterministic for deterministic renderer.
func TestWritePrivateAtomicFileIsDeterministicForDeterministicRenderer(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first.json")
	second := filepath.Join(root, "second.json")
	for _, path := range []string{first, second} {
		if err := WritePrivateAtomicFile(path, writePrivateFixture(`{"schema_version":"1"}\n`)); err != nil {
			t.Fatal(err)
		}
	}
	firstData, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstData) != string(secondData) {
		t.Fatalf("outputs differ: %q != %q", firstData, secondData)
	}
}

// writePrivateFixture renders private fixture in the package's stable operator-facing format.
func writePrivateFixture(value string) func(io.Writer) error {
	return func(writer io.Writer) error {
		_, err := io.WriteString(writer, value)
		return err
	}
}
