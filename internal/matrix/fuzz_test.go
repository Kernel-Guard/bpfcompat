package matrix

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad protects the matrix YAML parser against malformed input. The
// matrix file is operator-authored (CI workflow YAML, repo-committed), but
// the API server also accepts an uploaded matrix via /api/validate, so
// hostile content is in scope.
func FuzzLoad(f *testing.F) {
	seedFromMatrices(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		path := filepath.Join(t.TempDir(), "matrix.yaml")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Skipf("write fuzz matrix: %v", err)
		}
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("matrix.Load panicked on fuzz input: %v\ninput=%q", rec, raw)
			}
		}()
		_, _ = Load(path)
	})
}

func seedFromMatrices(f *testing.F) {
	f.Helper()
	candidates := []string{
		"../../matrices/mvp.yaml",
		"../../matrices/dev-one.yaml",
		"../../matrices/tier1-enterprise-cloud.yaml",
		"../../matrices/extended-15.yaml",
	}
	for _, c := range candidates {
		raw, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		f.Add(raw)
	}
	f.Add([]byte(""))
	f.Add([]byte("profiles: []\n"))
	f.Add([]byte("profiles:\n  - id: a\n    required: true\n"))
}
