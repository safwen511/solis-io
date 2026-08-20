package version

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

// TestBuildMetadataDefaults verifies build metadata defaults.
func TestBuildMetadataDefaults(t *testing.T) {
	if Version != "dev" || GitCommit != "unknown" || BuildTime != "unknown" {
		t.Fatalf("build defaults = %q, %q, %q", Version, GitCommit, BuildTime)
	}
	info := BuildInfo()
	if info.GoVersion != runtime.Version() || info.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("runtime build info = %#v", info)
	}
}

// TestWriteHuman verifies write human.
func TestWriteHuman(t *testing.T) {
	info := Info{Version: "1.2.3", GitCommit: "abc123", BuildTime: "2026-08-09T22:00:00Z", GoVersion: "go1.test", Platform: "linux/amd64"}
	var output bytes.Buffer
	if err := WriteHuman(&output, info); err != nil {
		t.Fatal(err)
	}
	want := "version: 1.2.3\ngit_commit: abc123\nbuild_time: 2026-08-09T22:00:00Z\ngo_version: go1.test\nplatform: linux/amd64\n"
	if output.String() != want {
		t.Fatalf("human output = %q, want %q", output.String(), want)
	}
}

// TestWriteJSONDeterministic verifies write json deterministic.
func TestWriteJSONDeterministic(t *testing.T) {
	info := Info{Version: "1.2.3", GitCommit: "abc123", BuildTime: "time", GoVersion: "go1.test", Platform: "linux/amd64"}
	var first, second bytes.Buffer
	if err := WriteJSON(&first, info); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&second, info); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("JSON differs:\n%s\n%s", first.String(), second.String())
	}
	if !strings.HasPrefix(first.String(), "{\n  \"version\": \"1.2.3\",\n  \"git_commit\":") {
		t.Fatalf("unexpected JSON field order:\n%s", first.String())
	}
	var decoded Info
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != info {
		t.Fatalf("decoded info = %#v, want %#v", decoded, info)
	}
}
