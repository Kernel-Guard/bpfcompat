package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad exercises the manifest parser against arbitrary YAML payloads.
// The contract: Load must either parse successfully or return a non-nil
// error. It must never panic, infinite-loop, or consume an unbounded amount
// of memory. The corpus is seeded from the example manifests checked into
// the repo so the fuzzer starts from realistic shapes.
func FuzzLoad(f *testing.F) {
	seedCorpusFromManifests(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		path := filepath.Join(t.TempDir(), "manifest.yaml")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Skipf("write fuzz manifest: %v", err)
		}
		// Load can legitimately error (malformed YAML, missing fields, etc.).
		// What it must not do is panic. The defer recover wraps Load so a
		// panic surfaces as a test failure rather than a process abort.
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("manifest.Load panicked on fuzz input: %v\ninput=%q", rec, raw)
			}
		}()
		_, _ = Load(path)
	})
}

// seedCorpusFromManifests walks the in-repo example manifests so the fuzzer
// starts from realistic inputs. We deliberately fail open: a missing
// examples/ directory shouldn't break the fuzz suite (it's gone in trimmed
// container builds), it just means fewer seeds.
func seedCorpusFromManifests(f *testing.F) {
	f.Helper()
	candidates := []string{
		"../../examples/simple-pass/manifest.yaml",
		"../../examples/ringbuf-modern/manifest.yaml",
		"../../examples/perfbuf-fallback/manifest.yaml",
		"../../examples/unsupported-attach/manifest.yaml",
		"../../examples/core-relocation-fail/manifest.yaml",
	}
	for _, c := range candidates {
		raw, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		f.Add(raw)
	}
	// Hand-rolled minimal corpus entries so the fuzzer has something even
	// when the examples are absent.
	f.Add([]byte(""))
	f.Add([]byte("name: empty\n"))
	f.Add([]byte("programs:\n  - name: foo\n    attach:\n      kind: tracepoint\n"))
	f.Add([]byte("programs:\n  - name: \xff\n    attach:\n      kind: unknown\n"))
}
