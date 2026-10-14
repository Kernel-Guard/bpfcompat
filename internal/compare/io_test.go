package compare

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validReportJSON = `{
  "schema_version": "v0.1",
  "run": {"id": "r"},
  "targets": [
    {"profile_id": "a", "required": true, "status": "pass"},
    {"profile_id": "b", "required": false, "status": "fail"}
  ],
  "summary": {"status": "pass"}
}`

func writeIOFixture(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAndBuildAcceptsValidReports(t *testing.T) {
	p := writeIOFixture(t, "r.json", validReportJSON)
	d, err := LoadAndBuild(p, p)
	if err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	if d.Summary.TotalProfiles != 2 {
		t.Fatalf("expected 2 profiles, got %d", d.Summary.TotalProfiles)
	}
}

func TestLoadAndBuildRejectsDuplicateProfileIDs(t *testing.T) {
	good := writeIOFixture(t, "good.json", validReportJSON)
	dup := writeIOFixture(t, "dup.json", `{
  "schema_version": "v0.1",
  "targets": [
    {"profile_id": "a", "required": true, "status": "fail"},
    {"profile_id": "a", "required": true, "status": "pass"}
  ]
}`)
	for _, tc := range []struct{ base, head, side string }{{dup, good, "base"}, {good, dup, "head"}} {
		_, err := LoadAndBuild(tc.base, tc.head)
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("%s duplicate: want ErrInvalidReport, got %v", tc.side, err)
		}
		if !strings.Contains(err.Error(), `"a"`) || !strings.Contains(err.Error(), tc.side+" report") {
			t.Fatalf("%s duplicate: error does not name the side and profile: %v", tc.side, err)
		}
	}
}
