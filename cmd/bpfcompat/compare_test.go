package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

func compareTestWrite(t *testing.T, dir, name string, v any) string {
	t.Helper()
	p := filepath.Join(dir, name)
	var b []byte
	switch x := v.(type) {
	case string:
		b = []byte(x)
	default:
		var err error
		b, err = json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func compareTestReport(runID string) schema.ReportV01 {
	return schema.ReportV01{
		SchemaVersion: "v0.1",
		Run:           schema.RunInfo{ID: runID},
		Artifact:      schema.Artifact{SHA256: "aaa"},
		Targets: []schema.Target{{
			ProfileID: "ubuntu-22.04-5.15", Required: true, Status: "pass", Verdict: schema.VerdictCompatible,
		}},
		Summary: schema.SummaryInfo{Status: "pass"},
	}
}

func runCompareForTest(t *testing.T, args ...string) (int, string) {
	t.Helper()
	c, restore := captureStdout(t)
	code := run(append([]string{"compare"}, args...))
	out := c.read()
	restore()
	return code, string(out)
}

// A report listing one profile twice (fail, then pass) used to be collapsed to
// its last row: the per-profile view said "unchanged" and required_regressions
// was 0 while the same document's summary said head_required_failed=1. Which
// row represents the obligation is ambiguous, so compare must refuse the input
// instead of guessing.
func TestCompareRejectsDuplicateProfileIDs(t *testing.T) {
	dir := t.TempDir()
	headR := compareTestReport("r2")
	failing := headR.Targets[0]
	failing.Status = "fail"
	failing.Verdict = schema.VerdictIncompatible
	headR.Targets = []schema.Target{failing, headR.Targets[0]}
	base := compareTestWrite(t, dir, "base.json", compareTestReport("r1"))
	head := compareTestWrite(t, dir, "head.json", headR)
	out := filepath.Join(dir, "o.json")

	code, _ := runCompareForTest(t, "--base-report", base, "--head-report", head, "--out", out)
	if code != runner.ExitToolError {
		t.Fatalf("compare with a duplicated profile_id exited %d, want tool error %d", code, runner.ExitToolError)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatalf("compare wrote %s for an ambiguous report", out)
	}
}

// Valid reports keep comparing exactly as before.
func TestCompareValidReportsStillCompare(t *testing.T) {
	dir := t.TempDir()
	base := compareTestWrite(t, dir, "base.json", compareTestReport("r1"))
	head := compareTestWrite(t, dir, "head.json", compareTestReport("r2"))
	out := filepath.Join(dir, "o.json")

	code, stdout := runCompareForTest(t, "--base-report", base, "--head-report", head, "--out", out)
	if code != 0 {
		t.Fatalf("compare of two valid reports exited %d: %s", code, stdout)
	}
	if !strings.Contains(stdout, "Diff summary: profiles=1 changed=0 improved=0 regressed=0 required_regressions=0") {
		t.Fatalf("unexpected summary line: %s", stdout)
	}
}

// A JSON null, an empty object, an unknown schema_version or a report with no
// targets used to compare as a clean, empty diff with exit 0. None of them is
// evidence of anything, so compare must refuse them as a tool error.
func TestCompareRejectsReportsWithoutComparableSchema(t *testing.T) {
	for name, doc := range map[string]string{
		"null":             `null`,
		"empty object":     `{}`,
		"no schema":        `{"targets":[{"profile_id":"p","required":true,"status":"pass"}]}`,
		"unknown schema":   `{"schema_version":"v0.2","targets":[{"profile_id":"p","required":true,"status":"pass"}]}`,
		"no targets array": `{"schema_version":"v0.1"}`,
		"null targets":     `{"schema_version":"v0.1","targets":null}`,
		"zero targets":     `{"schema_version":"v0.1","targets":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			valid := compareTestWrite(t, dir, "valid.json", compareTestReport("r1"))
			bad := compareTestWrite(t, dir, "bad.json", doc)
			for _, pair := range [][2]string{{bad, bad}, {bad, valid}, {valid, bad}} {
				out := filepath.Join(dir, "o.json")
				code, _ := runCompareForTest(t, "--base-report", pair[0], "--head-report", pair[1], "--out", out)
				if code != runner.ExitToolError {
					t.Fatalf("compare accepted %s (base=%s head=%s): exit %d, want %d",
						doc, filepath.Base(pair[0]), filepath.Base(pair[1]), code, runner.ExitToolError)
				}
				if _, err := os.Stat(out); err == nil {
					t.Fatalf("compare wrote %s for an invalid report", out)
				}
			}
		})
	}
}
