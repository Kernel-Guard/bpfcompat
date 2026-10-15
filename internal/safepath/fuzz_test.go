package safepath

import (
	"errors"
	"path/filepath"
	"testing"
)

// FuzzLocalJoin checks the containment contract of the choke point used for
// data-derived file names (decision IDs, registry fields, URL basenames).
//
// Property: whenever LocalJoin succeeds, the result is base itself or a path
// inside base (filepath.Rel from the cleaned base is "." or local); whenever
// it fails, the error is *ErrEscapesBase.
func FuzzLocalJoin(f *testing.F) {
	seeds := [][3]string{
		{"/srv/traces", "decision-1.json", ""},
		{"/srv/traces", "../etc/passwd", ""},
		{"/srv/traces", "a/../../b", ""},
		{"/srv/traces", "a/..", "b"},
		{"relative/base", "/abs", "x"},
		{"", "x", "y"},
		{".", "..", ""},
		{"/", "a", "b"},
		{"../up", "a", "b"},
		{"/srv/traces", "a\x00b", ""},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, base, a, b string) {
		got, err := LocalJoin(base, a, b)
		if err != nil {
			var escape *ErrEscapesBase
			if !errors.As(err, &escape) {
				t.Fatalf("unexpected error type %T: %v", err, err)
			}
			return
		}
		rel, relErr := filepath.Rel(filepath.Clean(base), got)
		if relErr != nil {
			t.Fatalf("LocalJoin(%q, %q, %q) = %q is not relative to base: %v", base, a, b, got, relErr)
		}
		if rel != "." && !filepath.IsLocal(rel) {
			t.Fatalf("LocalJoin(%q, %q, %q) = %q escapes base (rel %q)", base, a, b, got, rel)
		}
	})
}
