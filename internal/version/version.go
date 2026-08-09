// Package version exposes immutable build identity for CLI and evidence output.
package version

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
)

// These values may be replaced at build time with -ldflags -X.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
	GoVersion = runtime.Version()
	Platform  = runtime.GOOS + "/" + runtime.GOARCH
)

// Info is the deterministic version/build metadata schema.
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// BuildInfo returns the effective build identity.
func BuildInfo() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildTime: BuildTime,
		GoVersion: GoVersion,
		Platform:  Platform,
	}
}

// WriteHuman renders stable line-oriented build metadata.
func WriteHuman(dst io.Writer, info Info) error {
	_, err := fmt.Fprintf(
		dst,
		"version: %s\n"+
			"git_commit: %s\n"+
			"build_time: %s\n"+
			"go_version: %s\n"+
			"platform: %s\n",
		info.Version,
		info.GitCommit,
		info.BuildTime,
		info.GoVersion,
		info.Platform,
	)
	return err
}

// WriteJSON renders deterministic JSON using the field order in Info.
func WriteJSON(dst io.Writer, info Info) error {
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(info)
}
