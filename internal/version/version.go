// Package version exposes build-time identity stamped into the binary via
// -ldflags. The Makefile (and CI release pipeline) overrides Version,
// Commit, and BuildDate so the running binary can report exactly which
// source it was built from. Defaults are kept compatible with `go run`
// so a vanilla developer build still works without -ldflags.
package version

import (
	"runtime/debug"
	"strings"
)

const Name = "bpfcompat"

// These three vars are intentionally `var` (not `const`) so they can be
// overridden by -ldflags at build time:
//
//	go build -ldflags "-X github.com/erenari/bpfcompat/internal/version.Version=v1.2.3 \
//	  -X github.com/erenari/bpfcompat/internal/version.Commit=$(git rev-parse --short HEAD) \
//	  -X github.com/erenari/bpfcompat/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
//
// At runtime the human-readable string returned by String() folds these
// together and falls back to runtime/debug.ReadBuildInfo() for `go install`
// / `go build` invocations that didn't pass ldflags.
var (
	Version   = "0.1.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Info captures the resolved build identity for callers (CLI subcommand,
// startup log line, /api/health, metrics labels).
type Info struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Module    string `json:"module,omitempty"`
}

// Resolve returns the final identity. If -ldflags weren't used we look at
// runtime/debug.ReadBuildInfo() to recover whatever Go pulled from the VCS
// stamp (Go 1.18+). The function is intentionally cheap — callers can call
// it from hot paths.
func Resolve() Info {
	info := Info{
		Name:      Name,
		Version:   strings.TrimSpace(Version),
		Commit:    strings.TrimSpace(Commit),
		BuildDate: strings.TrimSpace(BuildDate),
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info.GoVersion = bi.GoVersion
		info.Module = bi.Main.Path
		// Backfill from VCS settings if -ldflags weren't supplied. This is
		// what `go build -buildvcs=true` (the default) injects.
		if info.Commit == "" || info.Commit == "unknown" {
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if v := strings.TrimSpace(s.Value); v != "" {
						info.Commit = v
					}
				case "vcs.time":
					if (info.BuildDate == "" || info.BuildDate == "unknown") && strings.TrimSpace(s.Value) != "" {
						info.BuildDate = s.Value
					}
				}
			}
		}
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.BuildDate == "" {
		info.BuildDate = "unknown"
	}
	if info.Version == "" {
		info.Version = "0.1.0-dev"
	}
	return info
}

// String returns the human-readable one-liner used by `bpfcompat version`
// and the startup log line.
func String() string {
	info := Resolve()
	out := info.Name + " " + info.Version
	if info.Commit != "" && info.Commit != "unknown" {
		short := info.Commit
		if len(short) > 12 {
			short = short[:12]
		}
		out += " (" + short + ")"
	}
	if info.BuildDate != "" && info.BuildDate != "unknown" {
		out += " built " + info.BuildDate
	}
	if info.GoVersion != "" {
		out += " " + info.GoVersion
	}
	return out
}
