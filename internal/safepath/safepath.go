// Package safepath is the single choke point for turning data-derived names
// (registry record fields, decision IDs, URL basenames) into on-disk paths.
//
// The functions here reject any component that would escape its base directory
// — absolute paths, "..", volume names, or a leading separator — using
// filepath.IsLocal. They are deliberately strict: callers pass a trusted base
// directory plus one or more UNTRUSTED components, and never the other way
// around. Paths that come straight from a human operator (a CLI --out flag, a
// file the operator points the tool at) are intentionally NOT routed through
// here; those are operator-controlled by design.
package safepath

import (
	"fmt"
	"path/filepath"
)

// ErrEscapesBase is returned when an untrusted component would resolve outside
// the base directory it is being joined to.
type ErrEscapesBase struct {
	Base      string
	Component string
}

func (e *ErrEscapesBase) Error() string {
	return fmt.Sprintf("path component %q escapes base directory %q", e.Component, e.Base)
}

// LocalJoin joins one or more untrusted components onto a trusted base
// directory and returns the cleaned absolute-or-relative path. It returns an
// *ErrEscapesBase if the joined components are not local to the base (i.e. they
// contain "..", an absolute path, or a volume name).
//
// The components are first joined and cleaned together, so a sequence that nets
// out local (e.g. "a/../b" -> "b") is allowed, while one that escapes
// ("a/../../b" -> "../b") is rejected.
func LocalJoin(base string, components ...string) (string, error) {
	rel := filepath.Join(components...)
	// filepath.IsLocal reports whether rel, when evaluated against any
	// directory, stays within that directory. CodeQL recognises it as a
	// path-traversal barrier, and it is the canonical stdlib guard since
	// Go 1.20.
	if !filepath.IsLocal(rel) {
		return "", &ErrEscapesBase{Base: base, Component: rel}
	}
	return filepath.Join(base, rel), nil
}
