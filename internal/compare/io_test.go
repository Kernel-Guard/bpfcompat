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

func TestLoadAndBuildRejectsReportsWithoutComparableSchema(t *testing.T) {
	good := writeIOFixture(t, "good.json", validReportJSON)
	for name, tc := range map[string]struct{ doc, want string }{
		"null":             {`null`, `schema_version ""`},
		"empty object":     {`{}`, `schema_version ""`},
		"unknown schema":   {`{"schema_version":"v0.2","targets":[{"profile_id":"a"}]}`, `schema_version "v0.2"`},
		"no targets array": {`{"schema_version":"v0.1"}`, "no targets"},
		"zero targets":     {`{"schema_version":"v0.1","targets":[]}`, "no targets"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := writeIOFixture(t, "bad.json", tc.doc)
			for _, side := range []string{"base", "head"} {
				base, head := bad, good
				if side == "head" {
					base, head = good, bad
				}
				_, err := LoadAndBuild(base, head)
				if !errors.Is(err, ErrInvalidReport) {
					t.Fatalf("%s: want ErrInvalidReport, got %v", side, err)
				}
				if !strings.Contains(err.Error(), side+" report") || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("%s: error should name the side and %q: %v", side, tc.want, err)
				}
			}
		})
	}
}

// The schema rule is the one `bpfcompat diff` enforces, surrounding
// whitespace included.
func TestLoadAndBuildAcceptsPaddedSchemaVersion(t *testing.T) {
	p := writeIOFixture(t, "r.json", strings.Replace(validReportJSON, `"v0.1"`, `" v0.1 "`, 1))
	if _, err := LoadAndBuild(p, p); err != nil {
		t.Fatalf("padded schema_version rejected: %v", err)
	}
}
