package regressiondiff

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

func b(v bool) *bool { return &v }

// target builds one side's evidence for a profile. Verdict is what the run
// recorded; the differ must never derive it itself.
func target(id, verdict string, required bool) schema.Target {
	status := map[string]string{
		schema.VerdictCompatible:   "pass",
		schema.VerdictIncompatible: "fail",
		schema.VerdictInfraError:   "infra_error",
		schema.VerdictUnsupported:  "unsupported",
	}[verdict]
	return schema.Target{
		ProfileID: id, Required: required, Status: status, Verdict: verdict,
		Environment: &schema.EnvironmentCheck{
			RequestedKernelFamily: "5.15",
			ObservedKernel:        "5.15.0-186-generic",
			KernelFamilyMatch:     b(true),
		},
	}
}

// mismatched marks a target as having run a kernel other than the one its
// profile names -- real evidence, but not about the requested obligation.
func mismatched(t schema.Target) schema.Target {
	t.Environment = &schema.EnvironmentCheck{
		RequestedKernelFamily: "5.15",
		ObservedKernel:        "6.12.0-107.el9uek.x86_64",
		KernelFamilyMatch:     b(false),
	}
	return t
}

func report(complete bool, targets ...schema.Target) schema.ReportV01 {
	return schema.ReportV01{
		SchemaVersion: "v0.1",
		Run:           schema.RunInfo{ID: "run-x"},
		Artifact:      schema.Artifact{SHA256: "aaa"},
		Targets:       targets,
		Summary:       schema.SummaryInfo{Verdict: schema.VerdictCompatible, Complete: b(complete)},
	}
}

func build(t *testing.T, baseline, candidate schema.ReportV01) Diff {
	t.Helper()
	d, err := Build(baseline, candidate, "base.json", "cand.json", time.Unix(0, 0).UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return d
}

func onlyCell(t *testing.T, d Diff) Cell {
	t.Helper()
	if len(d.Cells) != 1 {
		t.Fatalf("expected exactly one cell, got %d", len(d.Cells))
	}
	return d.Cells[0]
}

func cellFor(t *testing.T, d Diff, profileID string) Cell {
	t.Helper()
	for i := range d.Cells {
		if d.Cells[i].ProfileID == profileID {
			return d.Cells[i]
		}
	}
	t.Fatalf("no cell for %q in %+v", profileID, d.Cells)
	return Cell{}
}

// The comparison table. Each row is a release decision that must differ.
func TestComparisonTable(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	E, U := schema.VerdictInfraError, schema.VerdictUnsupported

	tests := []struct {
		name       string
		baseline   *schema.Target
		candidate  *schema.Target
		want       string
		wantResult string
		wantExit   int
	}{
		{"compatible to compatible", p(target("k", C, true)), p(target("k", C, true)), UnchangedCompatible, ResultNoRegressions, 0},
		{"compatible to incompatible is the product signal", p(target("k", C, true)), p(target("k", I, true)), NewRegression, ResultRegressed, 2},
		{"incompatible to incompatible is a known limitation", p(target("k", I, true)), p(target("k", I, true)), ExistingIncompatibility, ResultNoRegressions, 0},
		{"incompatible to compatible is a fix", p(target("k", I, true)), p(target("k", C, true)), Fixed, ResultNoRegressions, 0},

		// The rule that stops an unproven baseline from inventing a regression.
		{"infra baseline then incompatible candidate is NOT a regression", p(target("k", E, true)), p(target("k", I, true)), Inconclusive, ResultInconclusive, 1},
		{"compatible baseline then infra candidate", p(target("k", C, true)), p(target("k", E, true)), Inconclusive, ResultInconclusive, 1},
		{"unsupported on either side", p(target("k", U, true)), p(target("k", C, true)), Inconclusive, ResultInconclusive, 1},

		// Environment mislabels are evidence-quality failures, not regressions.
		{"required baseline ran the wrong kernel", p(mismatched(target("k", C, true))), p(target("k", I, true)), Inconclusive, ResultInconclusive, 1},
		{"required candidate ran the wrong kernel", p(target("k", C, true)), p(mismatched(target("k", C, true))), Inconclusive, ResultInconclusive, 1},

		// Optional cells report, they do not gate.
		{"optional regression is visible but non-gating", p(target("k", C, false)), p(target("k", I, false)), NewRegression, ResultNoRegressions, 0},
		{"optional inconclusive is non-gating", p(target("k", C, false)), p(target("k", E, false)), Inconclusive, ResultNoRegressions, 0},

		// Coverage changes.
		{"required coverage removed cannot establish continued support", p(target("k", C, true)), nil, CoverageRemoved, ResultInconclusive, 1},
		{"optional coverage removed is non-gating", p(target("k", C, false)), nil, CoverageRemoved, ResultNoRegressions, 0},
		{"candidate-only cell is new evidence", nil, p(target("k", C, true)), CoverageAdded, ResultNoRegressions, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Every report carries a shared, unchanging anchor cell: a report
			// with no targets is now rejected outright, and the anchor keeps
			// coverage-add/remove rows expressible.
			anchor := target("anchor", C, true)
			baseTargets := []schema.Target{anchor}
			candTargets := []schema.Target{anchor}
			if tc.baseline != nil {
				baseTargets = append(baseTargets, *tc.baseline)
			}
			if tc.candidate != nil {
				candTargets = append(candTargets, *tc.candidate)
			}
			d := build(t, report(true, baseTargets...), report(true, candTargets...))
			cell := cellFor(t, d, "k")
			if cell.Classification != tc.want {
				t.Errorf("classification: want %s, got %s (%s)", tc.want, cell.Classification, cell.Reason)
			}
			if d.Summary.Result != tc.wantResult {
				t.Errorf("result: want %s, got %s", tc.wantResult, d.Summary.Result)
			}
			if got := ExitCode(d); got != tc.wantExit {
				t.Errorf("exit: want %d, got %d", tc.wantExit, got)
			}
		})
	}
}

func p(t schema.Target) *schema.Target { return &t }

// The single most important property of this whole gate.
func TestIncompleteBaselineCanNeverManufactureARegression(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	unproven := []schema.Target{
		target("k", schema.VerdictInfraError, true),
		target("k", schema.VerdictUnsupported, true),
		mismatched(target("k", C, true)),
		{ProfileID: "k", Required: true, Status: "pass"}, // no verdict recorded at all
	}
	for _, base := range unproven {
		d := build(t, report(false, base), report(true, target("k", I, true)))
		cell := onlyCell(t, d)
		if cell.Classification == NewRegression {
			t.Fatalf("baseline %q/%v produced NEW_REGRESSION from an unproven baseline",
				base.Verdict, base.Environment)
		}
		if cell.Classification != Inconclusive {
			t.Fatalf("want %s, got %s", Inconclusive, cell.Classification)
		}
		// The candidate's incompatibility must still be visible as evidence.
		if cell.Candidate.Verdict != I {
			t.Fatalf("candidate evidence was discarded: %+v", cell.Candidate)
		}
	}
}

// The mirror property: a proven required regression must survive noise.
func TestProvenRequiredRegressionSurvivesUnrelatedNoise(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	baseline := report(true,
		target("gating", C, true),
		target("flaky-optional", C, false),
		target("also-required", C, true),
	)
	candidate := report(false,
		target("gating", I, true),                                 // the real regression
		target("flaky-optional", schema.VerdictInfraError, false), // optional noise
		target("also-required", schema.VerdictInfraError, true),   // required noise
	)
	d := build(t, baseline, candidate)
	if d.Summary.NewRequiredRegressions != 1 {
		t.Fatalf("want 1 new required regression, got %d", d.Summary.NewRequiredRegressions)
	}
	if d.Summary.Result != ResultRegressed {
		t.Fatalf("a proven required regression must outrank inconclusive noise; got %s", d.Summary.Result)
	}
	if ExitCode(d) != ExitRegressed {
		t.Fatalf("want exit %d, got %d", ExitRegressed, ExitCode(d))
	}
	// ...and the noise is still counted, not hidden.
	if d.Summary.InconclusiveRequired != 1 || d.Summary.InconclusiveOptional != 1 {
		t.Fatalf("lost coverage must remain visible: %+v", d.Summary)
	}
}

func TestOrderIndependence(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	a := report(true, target("a", C, true), target("b", I, true), target("c", C, false))
	bRep := report(true, target("c", C, false), target("a", I, true), target("b", I, true))
	shuffled := report(true, target("b", I, true), target("c", C, false), target("a", C, true))
	shuffledCand := report(true, target("b", I, true), target("a", I, true), target("c", C, false))

	d1 := build(t, a, bRep)
	d2 := build(t, shuffled, shuffledCand)

	j1, _ := json.Marshal(d1.Cells)
	j2, _ := json.Marshal(d2.Cells)
	if !bytes.Equal(j1, j2) {
		t.Fatalf("diff depends on target order:\n%s\n%s", j1, j2)
	}
	if d1.Summary.Result != d2.Summary.Result {
		t.Fatalf("result depends on order: %s vs %s", d1.Summary.Result, d2.Summary.Result)
	}
}

func TestLoaderContractChangeMakesEveryCellInconclusive(t *testing.T) {
	C := schema.VerdictCompatible
	baseline := report(true, target("k", C, true))
	baseline.Validator = &schema.BinaryIdentity{SHA256: "validator"}
	candidate := report(true, target("k", C, true))
	candidate.Command = &schema.CommandInfo{InvocationSHA256: "inv"}

	d := build(t, baseline, candidate)
	if onlyCell(t, d).Classification != Inconclusive {
		t.Fatal("a baseline loaded by the generic validator and a candidate driven by its own loader are not the same obligation")
	}
	if len(d.Notes) == 0 {
		t.Fatal("the loader change must be stated, not silently applied")
	}
}

func TestChangedObligationIsInconclusive(t *testing.T) {
	C := schema.VerdictCompatible
	base := target("k", C, true)
	cand := target("k", C, true)
	cand.Environment.RequestedKernelFamily = "6.1" // the profile now promises a different series
	d := build(t, report(true, base), report(true, cand))
	cell := onlyCell(t, d)
	if cell.Classification != Inconclusive {
		t.Fatalf("a profile that changed which kernel it claims is a different promise; got %s", cell.Classification)
	}
}

// Replaces an earlier test that asserted "the candidate defines the current
// support claim". That rule let a release dodge its own gate: flip a profile to
// `required: false` in the candidate and a regression on an environment the
// baseline promised became a non-gating optional finding.
func TestRequirednessChangeIsNotLikeForLike(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible

	t.Run("demotion cannot launder a regression into an optional finding", func(t *testing.T) {
		d := build(t, report(true, target("k", C, true)), report(true, target("k", I, false)))
		cell := onlyCell(t, d)

		if cell.Classification == NewRegression && !cell.Required {
			t.Fatal("a required->optional demotion turned a gating regression into an optional one")
		}
		if cell.Classification != Inconclusive {
			t.Fatalf("a support-contract change is not like-for-like evidence; want %s, got %s", Inconclusive, cell.Classification)
		}
		if !cell.Required {
			t.Fatal("an obligation either side treated as required must still gate")
		}
		if !cell.RequiredChanged {
			t.Fatal("the requiredness change must be recorded")
		}
		if d.Summary.Result != ResultInconclusive || ExitCode(d) != ExitInconclusive {
			t.Fatalf("want %s/exit %d, got %s/exit %d", ResultInconclusive, ExitInconclusive, d.Summary.Result, ExitCode(d))
		}
		if d.Summary.NewOptionalRegressions != 0 {
			t.Fatalf("the demotion must not be counted as an optional regression: %+v", d.Summary)
		}
	})

	t.Run("promotion is equally not like-for-like", func(t *testing.T) {
		// The mirror direction. Whether a candidate "regressed" against a
		// promise that did not exist at baseline is not something this evidence
		// settles, so it is not reasoned about asymmetrically.
		d := build(t, report(true, target("k", C, false)), report(true, target("k", I, true)))
		cell := onlyCell(t, d)
		if cell.Classification != Inconclusive {
			t.Fatalf("want %s, got %s", Inconclusive, cell.Classification)
		}
		if !cell.Required || ExitCode(d) != ExitInconclusive {
			t.Fatalf("a newly-required obligation must gate: required=%t exit=%d", cell.Required, ExitCode(d))
		}
	})

	t.Run("unchanged requiredness still compares normally", func(t *testing.T) {
		for _, req := range []bool{true, false} {
			d := build(t, report(true, target("k", C, req)), report(true, target("k", I, req)))
			cell := onlyCell(t, d)
			if cell.Classification != NewRegression {
				t.Fatalf("required=%t: want %s, got %s", req, NewRegression, cell.Classification)
			}
			if cell.RequiredChanged {
				t.Fatalf("required=%t: nothing changed", req)
			}
		}
	})
}

// Comparison keys must be trustworthy before anything is compared. Each of
// these was previously tolerated and produced a diff that looked conclusive.
func TestUnusableComparisonKeysFailClosed(t *testing.T) {
	C := schema.VerdictCompatible
	good := report(true, target("k", C, true))

	dup := report(true, target("k", C, true), target("k", schema.VerdictIncompatible, true))
	blank := report(true, target("k", C, true), target("   ", C, true))
	empty := report(true)

	for _, tc := range []struct {
		name                string
		baseline, candidate schema.ReportV01
		wantSubstr          string
	}{
		{"duplicate profile_id in baseline", dup, good, "ambiguous"},
		{"duplicate profile_id in candidate", good, dup, "ambiguous"},
		{"blank profile_id in baseline", blank, good, "empty profile_id"},
		{"blank profile_id in candidate", good, blank, "empty profile_id"},
		{"zero targets in baseline", empty, good, "no targets"},
		{"zero targets in candidate", good, empty, "no targets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Build(tc.baseline, tc.candidate, "b", "c", "now")
			if err == nil {
				t.Fatalf("expected a refusal, got a diff with %d cells", len(d.Cells))
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("error should say why: want %q in %q", tc.wantSubstr, err.Error())
			}
			var invalid *InvalidEvidenceError
			if !errors.As(err, &invalid) {
				t.Fatalf("want InvalidEvidenceError, got %T", err)
			}
		})
	}

	// A duplicate must never be resolved by silently keeping one of them.
	d, err := Build(dup, good, "b", "c", "now")
	if err == nil {
		for i := range d.Cells {
			if d.Cells[i].ProfileID == "k" {
				t.Fatal("a duplicated profile_id was resolved by picking a winner")
			}
		}
	}
}

// The CLI must map every unusable-evidence refusal to exit 1 -- an inability to
// compare, never a verdict on the candidate.
func TestUnusableEvidenceReachesExitOneThroughCompare(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, r schema.ReportV01) string {
		blob, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, blob, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	C := schema.VerdictCompatible
	good := write("good.json", report(true, target("k", C, true)))
	dup := write("dup.json", report(true, target("k", C, true), target("k", C, true)))
	empty := write("empty.json", report(true))

	for _, bad := range []string{dup, empty} {
		if _, err := Compare(bad, good, time.Now()); err == nil {
			t.Errorf("%s was accepted as a baseline", filepath.Base(bad))
		}
		if _, err := Compare(good, bad, time.Now()); err == nil {
			t.Errorf("%s was accepted as a candidate", filepath.Base(bad))
		}
	}
}

func TestUnsupportedSchemaFailsClosed(t *testing.T) {
	good := report(true, target("k", schema.VerdictCompatible, true))
	for _, bad := range []string{"", "v0.2", "v1.0", "nonsense"} {
		other := good
		other.SchemaVersion = bad
		if err := CheckSchemas(other, good); err == nil {
			t.Errorf("baseline schema %q was accepted", bad)
		}
		if err := CheckSchemas(good, other); err == nil {
			t.Errorf("candidate schema %q was accepted", bad)
		}
	}
	if err := CheckSchemas(good, good); err != nil {
		t.Fatalf("matching supported schemas must compare: %v", err)
	}
}

func TestMalformedAndMissingEvidenceFailClosed(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	blob, _ := json.Marshal(report(true, target("k", schema.VerdictCompatible, true)))
	if err := os.WriteFile(good, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, baseline, candidate string }{
		{"malformed baseline", bad, good},
		{"malformed candidate", good, bad},
		{"missing baseline", filepath.Join(dir, "nope.json"), good},
		{"missing candidate", good, filepath.Join(dir, "nope.json")},
	} {
		if _, err := Compare(tc.baseline, tc.candidate, time.Now()); err == nil {
			t.Errorf("%s: expected an error rather than an empty comparison", tc.name)
		}
	}
}

func TestDiffJSONIsVersionedAndSelfDescribing(t *testing.T) {
	d := build(t, report(true, target("k", schema.VerdictCompatible, true)),
		report(false, target("k", schema.VerdictIncompatible, true)))
	blob, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(blob, &generic); err != nil {
		t.Fatal(err)
	}
	if generic["schema_version"] != SchemaVersion {
		t.Fatalf("diff must carry its own schema version, got %v", generic["schema_version"])
	}
	// It must not be mistakable for a run report.
	if generic["schema_version"] == "v0.1" {
		t.Fatal("the diff schema must be distinct from the run-report schema")
	}
	if d.Summary.CandidateComplete == nil || *d.Summary.CandidateComplete {
		t.Fatal("candidate incompleteness must be surfaced in the summary")
	}
}

// Evidence must be the whole file, not its first JSON value. json.Decoder.Decode
// stops after one value and leaves the rest unread, so a truncated or
// concatenated report compared cleanly from its first value alone -- exit 0 over
// a file nobody can vouch for.
func TestTrailingDataAfterTheReportIsRefused(t *testing.T) {
	dir := t.TempDir()
	valid, err := json.Marshal(report(true, target("k", schema.VerdictCompatible, true)))
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, valid, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		trailer string
	}{
		{"second JSON value", "\n{\"schema_version\":\"v0.1\"}\n"},
		{"stray bytes", "\ngarbage\n"},
		{"truncated append", "\n{\"targets\":"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "trailing.json")
			if err := os.WriteFile(path, append(append([]byte{}, valid...), tc.trailer...), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadReport(path); err == nil {
				t.Fatal("a report with trailing data was accepted, so only its first value would have been compared")
			}
			if _, err := Compare(path, good, time.Now()); err == nil {
				t.Fatal("Compare accepted a baseline with trailing data")
			}
			if _, err := Compare(good, path, time.Now()); err == nil {
				t.Fatal("Compare accepted a candidate with trailing data")
			}
		})
	}

	// Trailing whitespace is not trailing data.
	padded := filepath.Join(dir, "padded.json")
	if err := os.WriteFile(padded, append(append([]byte{}, valid...), "\n\n  \n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(padded); err != nil {
		t.Fatalf("whitespace after the report must be fine: %v", err)
	}
}
