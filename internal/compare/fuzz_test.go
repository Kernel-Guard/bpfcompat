package compare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const maxFuzzReportBytes = 1 << 20

// FuzzLoadAndBuild feeds two arbitrary report documents through the
// `bpfcompat diff` / API compare path (LoadReport -> Build -> renderers).
// Reports are produced on other machines and handed back to us, so they are
// untrusted input.
//
// Properties: no panic; on success the diff marshals to JSON, renders to
// Markdown, and its summary counts are consistent with its profile list.
func FuzzLoadAndBuild(f *testing.F) {
	baseRaw, baseErr := os.ReadFile("../../scripts/testdata/action-diff/baseline.json")
	headRaw, headErr := os.ReadFile("../../scripts/testdata/action-diff/candidate-regressed.json")
	if baseErr == nil && headErr == nil {
		f.Add(baseRaw, headRaw)
		f.Add(headRaw, baseRaw)
	}
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Add([]byte(`{"targets":[{"profile_id":"a","required":true,"status":"pass"}]}`),
		[]byte(`{"targets":[{"profile_id":"a","required":true,"status":"fail"},{"profile_id":"a","status":"pass"}]}`))
	f.Add([]byte(`null`), []byte(`[]`))

	f.Fuzz(func(t *testing.T, baseRaw, headRaw []byte) {
		if len(baseRaw) > maxFuzzReportBytes {
			baseRaw = baseRaw[:maxFuzzReportBytes]
		}
		if len(headRaw) > maxFuzzReportBytes {
			headRaw = headRaw[:maxFuzzReportBytes]
		}
		dir := t.TempDir()
		basePath := filepath.Join(dir, "base.json")
		headPath := filepath.Join(dir, "head.json")
		if err := os.WriteFile(basePath, baseRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(headPath, headRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		diff, err := LoadAndBuild(basePath, headPath)
		if err != nil {
			return
		}
		s := diff.Summary
		if s.TotalProfiles != len(diff.Profiles) {
			t.Fatalf("summary total %d != %d profiles", s.TotalProfiles, len(diff.Profiles))
		}
		if s.ChangedProfiles > s.TotalProfiles ||
			s.ImprovedProfiles+s.RegressedProfiles > s.ChangedProfiles ||
			s.RequiredRegressions > s.RegressedProfiles {
			t.Fatalf("inconsistent summary: %+v", s)
		}
		if _, err := json.Marshal(diff); err != nil {
			t.Fatalf("diff does not marshal: %v", err)
		}
		if err := WriteMarkdown(filepath.Join(dir, "diff.md"), diff); err != nil {
			t.Fatalf("write markdown: %v", err)
		}
	})
}
