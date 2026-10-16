// Package vmcatalog compiles the standard VM profile catalog (vm/profiles/*.yaml)
// into the bpfcompat binary, so an installed CLI can resolve the documented
// profiles (for example the --quick set) without a source checkout.
//
// It only exposes the files; profile lookup and precedence live in
// internal/profilecatalog.
package vmcatalog

import "embed"

// Profiles holds vm/profiles/*.yaml as they were at build time. Paths inside
// the FS are "profiles/<id>.yaml".
//
//go:embed profiles/*.yaml
var Profiles embed.FS
