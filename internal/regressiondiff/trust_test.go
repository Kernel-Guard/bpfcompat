package regressiondiff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// The trust boundary. Every test in this file starts from evidence that a CI
// input author could actually supply -- an older report, a hand-edited one, one
// copied through an artifact store, one written by a different producer -- and
// asserts the same thing: absence, ambiguity and contradiction never come out
// as exit 0.

// compareFiles runs the real load-validate-compare path over two files, which
// is the only path a release gate uses.
func compareFiles(t *testing.T, baseline, candidate string) (Diff, int, error) {
	t.Helper()
	dir := t.TempDir()
	bp := filepath.Join(dir, "baseline.json")
	cp := filepath.Join(dir, "candidate.json")
	if err := os.WriteFile(bp, []byte(baseline), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, []byte(candidate), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Compare(bp, cp, time.Unix(0, 0))
	if err != nil {
		// This is exactly what the CLI does with a refusal.
		return Diff{}, ExitInconclusive, err
	}
	return d, ExitCode(d), nil
}

// jsonOf renders a report fixture. Tests that need JSON the Go type cannot
// express (duplicate keys, absent fields, nulls) edit the text afterwards.
func jsonOf(t *testing.T, r schema.ReportV01) string {
	t.Helper()
	blob, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return string(blob)
}

// green is a self-consistent pair that must compare cleanly, so that every
// other test in this file is a single deliberate mutation away from a real
// release decision.
func greenPair(t *testing.T) (string, string) {
	t.Helper()
	return jsonOf(t, report(target("k", schema.VerdictCompatible, true))),
		jsonOf(t, report(target("k", schema.VerdictCompatible, true)))
}

func TestGreenPairIsActuallyGreen(t *testing.T) {
	base, cand := greenPair(t)
	d, exit, err := compareFiles(t, base, cand)
	if err != nil {
		t.Fatalf("the control fixture must compare cleanly, got: %v", err)
	}
	if exit != ExitNoRegressions || d.Summary.Result != ResultNoRegressions {
		t.Fatalf("control: want exit 0/%s, got exit %d/%s", ResultNoRegressions, exit, d.Summary.Result)
	}
}

// STEP 2. A report does not become conclusive because one of its fields
// contains the word COMPATIBLE.
func TestContradictoryStatusAndVerdictIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, status, verdict string
	}{
		{"fail claiming compatible", "fail", schema.VerdictCompatible},
		{"pass claiming incompatible", "pass", schema.VerdictIncompatible},
		{"infra error claiming compatible", "infra_error", schema.VerdictCompatible},
		{"pass claiming a verdict nothing defines", "pass", "SOMETHING_NEW"},
		{"unsupported claiming compatible", "unsupported", schema.VerdictCompatible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := target("k", tc.verdict, true)
			bad.Status = tc.status
			// Built by hand: report() derives a self-consistent summary, and
			// this fixture is deliberately not self-consistent.
			r := report(bad)
			r.Summary.Verdict = ""
			r.Summary.Status = ""
			r.Summary.Complete = nil

			base, _ := greenPair(t)
			for _, side := range []string{"baseline", "candidate"} {
				var d Diff
				var exit int
				var err error
				if side == "baseline" {
					d, exit, err = compareFiles(t, jsonOf(t, r), base)
				} else {
					d, exit, err = compareFiles(t, base, jsonOf(t, r))
				}
				if err == nil {
					t.Fatalf("%s: contradictory evidence produced a diff (%s)", side, d.Summary.Result)
				}
				var invalid *InvalidEvidenceError
				if !errors.As(err, &invalid) {
					t.Fatalf("%s: want InvalidEvidenceError, got %T: %v", side, err, err)
				}
				if exit != ExitInconclusive {
					t.Fatalf("%s: contradictory evidence must be exit 1, not a verdict on the candidate; got %d", side, exit)
				}
				// The refusal must never be dressed up as a regression.
				if strings.Contains(err.Error(), NewRegression) {
					t.Fatalf("%s: a broken input file must not be reported as a regression: %v", side, err)
				}
			}
		})
	}
}

// An unknown verdict with nothing to contradict is unusable, not forged: it is
// inconclusive rather than refused, and it still cannot be green.
func TestUnknownVerdictWithoutStatusIsInconclusiveNotRefused(t *testing.T) {
	odd := target("k", "SOMETHING_NEW", true)
	odd.Status = ""
	base, _ := greenPair(t)
	d, exit, err := compareFiles(t, base, jsonOf(t, report(odd)))
	if err != nil {
		t.Fatalf("an unrecognised verdict is unusable evidence, not a contradiction: %v", err)
	}
	if got := onlyCell(t, d).Classification; got != Inconclusive {
		t.Fatalf("want %s, got %s", Inconclusive, got)
	}
	if exit != ExitInconclusive {
		t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
	}
}

// STEP 7. Targets are the single source of semantic truth; a summary that
// disagrees with them means the file disagrees with itself.
func TestReportLevelContradictionsAreRefused(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible

	mutate := func(f func(*schema.ReportV01), targets ...schema.Target) string {
		r := report(targets...)
		f(&r)
		return jsonOf(t, r)
	}

	for _, tc := range []struct {
		name       string
		report     string
		wantSubstr string
	}{
		{
			"summary claims INCOMPATIBLE while every required target passed",
			mutate(func(r *schema.ReportV01) { r.Summary.Verdict = I; r.Summary.Status = "fail" }, target("k", C, true)),
			"does not agree with itself",
		},
		{
			"summary claims COMPATIBLE over a required incompatibility",
			mutate(func(r *schema.ReportV01) { r.Summary.Verdict = C; r.Summary.Status = "pass" }, target("k", I, true)),
			"does not agree with itself",
		},
		{
			"summary claims complete while a target produced no answer",
			mutate(func(r *schema.ReportV01) { r.Summary.Complete = b(true) },
				target("k", C, true), target("opt", schema.VerdictInfraError, false)),
			"summary.complete",
		},
		{
			"summary claims complete while a required target ran the wrong kernel",
			mutate(func(r *schema.ReportV01) { r.Summary.Complete = b(true) }, mismatched(target("k", C, true))),
			"summary.complete",
		},
		{
			"summary status and verdict contradict each other",
			mutate(func(r *schema.ReportV01) { r.Summary.Status = "fail" }, target("k", C, true)),
			"contradict",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, _ := greenPair(t)
			_, exit, err := compareFiles(t, base, tc.report)
			if err == nil {
				t.Fatal("a report that contradicts itself must not be carried forward as trustworthy evidence")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("want %q in %q", tc.wantSubstr, err.Error())
			}
			if exit != ExitInconclusive {
				t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
			}
		})
	}
}

// STEP 3 and 4. Missing evidence is never evidence of success. The Gate 1
// helper answers "true" for an absent environment on purpose; Gate 2 asks a
// stricter question and must not inherit that answer.
func TestMissingEnvironmentEvidenceCannotBeGreen(t *testing.T) {
	C := schema.VerdictCompatible

	noEnvironment := func(tg schema.Target) schema.Target { tg.Environment = nil; return tg }
	noMatch := func(tg schema.Target) schema.Target {
		tg.Environment = &schema.EnvironmentCheck{
			RequestedKernelFamily: "5.15", ObservedKernel: "5.15.0-186-generic",
		}
		return tg
	}

	for _, tc := range []struct {
		name    string
		degrade func(schema.Target) schema.Target
	}{
		{"no environment object at all", noEnvironment},
		{"environment recorded but kernel_family_match absent", noMatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, side := range []string{"baseline", "candidate", "both"} {
				base := report(target("k", C, true))
				cand := report(target("k", C, true))
				if side != "candidate" {
					base.Targets[0] = tc.degrade(base.Targets[0])
					base.Summary.Complete = b(schema.RunComplete(base.Targets))
				}
				if side != "baseline" {
					cand.Targets[0] = tc.degrade(cand.Targets[0])
					cand.Summary.Complete = b(schema.RunComplete(cand.Targets))
				}
				d, exit, err := compareFiles(t, jsonOf(t, base), jsonOf(t, cand))
				if err != nil {
					t.Fatalf("%s: missing environment evidence is unusable, not malformed: %v", side, err)
				}
				cell := onlyCell(t, d)
				if cell.Classification != Inconclusive {
					t.Fatalf("%s: want %s, got %s (%s)", side, Inconclusive, cell.Classification, cell.Reason)
				}
				if exit != ExitInconclusive {
					t.Fatalf("%s: a required obligation nothing established must not exit 0; got %d", side, exit)
				}
				// Unknown must not be reported as a mismatch: not recording a
				// kernel and booting the wrong one are different findings.
				if strings.Contains(cell.Reason, "but ran") {
					t.Fatalf("%s: unknown environment was described as a mismatch: %s", side, cell.Reason)
				}
			}
		})
	}
}

// The stricter local rule is load-bearing: this is the mutation that would
// reintroduce the fail-open, stated as an executable fact rather than a
// comment. Swapping establishedEnvironment back to the Gate 1 helper makes the
// diff green over evidence that never named a kernel.
func TestGateTwoIsStricterThanTheGateOneHelper(t *testing.T) {
	noEnv := &schema.Target{ProfileID: "k", Required: true, Status: "pass", Verdict: schema.VerdictCompatible}
	if !schema.EstablishedRequestedEnvironment(noEnv) {
		t.Fatal("precondition: the Gate 1 helper is lenient about absent environment metadata")
	}
	if got := establishedEnvironment(noEnv); got != EnvironmentUnknownEvidence {
		t.Fatalf("Gate 2 must read absent environment metadata as %q, got %q", EnvironmentUnknownEvidence, got)
	}
	if conclusive(sideOf(noEnv)) {
		t.Fatal("a side that never recorded its kernel must not be able to settle an obligation")
	}
	// ...while an explicit mismatch stays a mismatch, and a positive match
	// stays established.
	mism := *noEnv
	mism.Environment = &schema.EnvironmentCheck{RequestedKernelFamily: "5.15", ObservedKernel: "6.1.0", KernelFamilyMatch: b(false)}
	if got := establishedEnvironment(&mism); got != EnvironmentMismatchEvidence {
		t.Fatalf("want %q, got %q", EnvironmentMismatchEvidence, got)
	}
	ok := *noEnv
	ok.Environment = &schema.EnvironmentCheck{RequestedKernelFamily: "5.15", ObservedKernel: "5.15.0-186", KernelFamilyMatch: b(true)}
	if got := establishedEnvironment(&ok); got != EnvironmentEstablishedEvidence {
		t.Fatalf("want %q, got %q", EnvironmentEstablishedEvidence, got)
	}
}

// A kernel_family_match with nothing it could have been derived from is an
// assertion, not evidence.
func TestUnattestedKernelFamilyMatchIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		strip func(*schema.EnvironmentCheck)
	}{
		{"requested kernel family removed", func(e *schema.EnvironmentCheck) { e.RequestedKernelFamily = "" }},
		{"observed kernel removed", func(e *schema.EnvironmentCheck) { e.ObservedKernel = "" }},
		{"both removed", func(e *schema.EnvironmentCheck) { e.RequestedKernelFamily = ""; e.ObservedKernel = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := report(target("k", schema.VerdictCompatible, true))
			tc.strip(r.Targets[0].Environment)
			base, _ := greenPair(t)
			_, exit, err := compareFiles(t, base, jsonOf(t, r))
			if err == nil {
				t.Fatal("a kernel_family_match resting on nothing must not be accepted")
			}
			if exit != ExitInconclusive {
				t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
			}
		})
	}
}

// STEP 5. Duplicate object keys: encoding/json keeps the last value, so a file
// a human reads as INCOMPATIBLE parses as COMPATIBLE.
func TestDuplicateJSONKeysAreRefused(t *testing.T) {
	base, _ := greenPair(t)
	valid := jsonOf(t, report(target("k", schema.VerdictIncompatible, true)))

	for _, tc := range []struct {
		name, find, replace string
	}{
		{
			"a second verdict overriding the first",
			`"verdict": "INCOMPATIBLE"`,
			`"verdict": "INCOMPATIBLE",` + "\n" + `  "verdict": "COMPATIBLE"`,
		},
		{
			"a second schema_version smuggling an unknown schema past the check",
			`"schema_version": "v0.1"`,
			`"schema_version": "v9.0",` + "\n" + ` "schema_version": "v0.1"`,
		},
		{
			"a second required demoting a gating obligation",
			`"required": true`,
			`"required": true,` + "\n" + `   "required": false`,
		},
		{
			"a second profile_id",
			`"profile_id": "k"`,
			`"profile_id": "k",` + "\n" + `   "profile_id": "other"`,
		},
		{
			"a second summary",
			`"summary": {`,
			`"summary": {"verdict": "COMPATIBLE"},` + "\n" + ` "summary": {`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(valid, tc.find, tc.replace, 1)
			if mutated == valid {
				t.Fatalf("fixture did not mutate; looked for %q", tc.find)
			}
			// The mutation must really be accepted by a stock decoder,
			// otherwise this test proves nothing about the risk.
			var probe schema.ReportV01
			if err := json.Unmarshal([]byte(mutated), &probe); err != nil {
				t.Fatalf("precondition: encoding/json accepts duplicate keys, got %v", err)
			}
			_, exit, err := compareFiles(t, base, mutated)
			if err == nil {
				t.Fatal("a document whose fields have two values is ambiguous evidence")
			}
			if !strings.Contains(err.Error(), "appears twice") {
				t.Fatalf("the refusal must name the ambiguity: %v", err)
			}
			if exit != ExitInconclusive {
				t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
			}
		})
	}
}

// STEP 6. A field whose absence and whose `false` deserialize to the same Go
// value cannot be read from the struct alone.
func TestAbsentRequirednessIsRefusedRatherThanReadAsOptional(t *testing.T) {
	// The shape that matters: a proven regression on an obligation whose
	// requiredness was deleted. Read as `false`, it is an optional finding and
	// the release ships.
	baseline := jsonOf(t, report(target("k", schema.VerdictCompatible, true)))
	regressed := jsonOf(t, report(target("k", schema.VerdictIncompatible, true)))

	for _, tc := range []struct {
		name, replace string
	}{
		{"required omitted", ``},
		{"required null", `"required": null,`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cand := strings.Replace(regressed, `"required": true,`, tc.replace, 1)
			base := strings.Replace(baseline, `"required": true,`, tc.replace, 1)
			if cand == regressed {
				t.Fatal("fixture did not mutate")
			}
			_, exit, err := compareFiles(t, base, cand)
			if err == nil {
				t.Fatal("a target that never states `required` leaves the support contract unknown")
			}
			if !strings.Contains(err.Error(), "required") {
				t.Fatalf("the refusal must name the missing field: %v", err)
			}
			if exit != ExitInconclusive {
				t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
			}
		})
	}

	// The control: `required: false` stated explicitly is a support decision,
	// not missing evidence, and still compares. Built through report() so its
	// run-level summary is derived from the optional target rather than
	// inherited from the required fixture above.
	optionalBase := jsonOf(t, report(target("k", schema.VerdictCompatible, false)))
	optionalCand := jsonOf(t, report(target("k", schema.VerdictIncompatible, false)))
	d, exit, err := compareFiles(t, optionalBase, optionalCand)
	if err != nil {
		t.Fatalf("an explicit `required: false` is evidence, not absence: %v", err)
	}
	if exit != ExitNoRegressions || d.Summary.NewOptionalRegressions != 1 {
		t.Fatalf("an explicitly optional regression reports without gating: exit=%d summary=%+v", exit, d.Summary)
	}
}

// Nulls and blanks must not become meaningful defaults.
func TestNullAndBlankFieldsCannotBeGreen(t *testing.T) {
	base, _ := greenPair(t)
	valid := jsonOf(t, report(target("k", schema.VerdictCompatible, true)))

	for _, tc := range []struct {
		name, find, replace string
		wantRefusal         bool
	}{
		{"environment null", `"environment": {`, `"environment": null, "unused": {`, false},
		// A missing verdict is unusable rather than forged: `status` alone is
		// the shape of every pre-Gate-1 report, so it is inconclusive, never a
		// refusal -- and never green.
		{"verdict null", `"verdict": "COMPATIBLE",`, `"verdict": null,`, false},
		{"verdict empty", `"verdict": "COMPATIBLE",`, `"verdict": "",`, false},
		{"verdict whitespace", `"verdict": "COMPATIBLE",`, `"verdict": "   ",`, false},
		{"kernel_family_match null", `"kernel_family_match": true`, `"kernel_family_match": null`, false},
		{"profile_id null", `"profile_id": "k"`, `"profile_id": null`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(valid, tc.find, tc.replace, 1)
			if mutated == valid {
				t.Fatalf("fixture did not mutate; looked for %q", tc.find)
			}
			d, exit, err := compareFiles(t, base, mutated)
			if exit == ExitNoRegressions {
				t.Fatalf("a null or blank contract field must not produce a green comparison (err=%v result=%s)", err, d.Summary.Result)
			}
			if tc.wantRefusal && err == nil {
				t.Fatalf("want a refusal, got %s", d.Summary.Result)
			}
		})
	}
}

// STEP 8. The same profile_id can be pointed at a different promise.
func TestSameProfileIDWithADifferentObligationIsInconclusive(t *testing.T) {
	C := schema.VerdictCompatible
	withProfile := func(arch, distro, version, family string) schema.Target {
		tg := target("k", C, true)
		tg.Profile = &schema.TargetEnv{Arch: arch, Distro: distro, Version: version, KernelFamily: family}
		return tg
	}
	baselineTarget := withProfile("x86_64", "ubuntu", "22.04", "5.15")

	for _, tc := range []struct {
		name string
		cand schema.Target
		want string
	}{
		{"architecture changed", withProfile("arm64", "ubuntu", "22.04", "5.15"), "architecture"},
		{"distro changed", withProfile("x86_64", "debian", "22.04", "5.15"), "distro"},
		{"distro version changed", withProfile("x86_64", "ubuntu", "24.04", "5.15"), "distro version"},
		{"kernel family changed", withProfile("x86_64", "ubuntu", "22.04", "6.1"), "kernel family"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, exit, err := compareFiles(t,
				jsonOf(t, report(baselineTarget)), jsonOf(t, report(tc.cand)))
			if err != nil {
				t.Fatalf("a changed obligation is not malformed evidence: %v", err)
			}
			cell := onlyCell(t, d)
			if cell.Classification != Inconclusive {
				t.Fatalf("want %s, got %s (%s)", Inconclusive, cell.Classification, cell.Reason)
			}
			if !strings.Contains(cell.Reason, tc.want) {
				t.Fatalf("the reason must name what changed: want %q in %q", tc.want, cell.Reason)
			}
			if exit != ExitInconclusive {
				t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
			}
		})
	}

	// The control: an identical obligation still compares.
	d := build(t, report(baselineTarget), report(baselineTarget))
	if got := onlyCell(t, d).Classification; got != UnchangedCompatible {
		t.Fatalf("an unchanged obligation must still compare: got %s", got)
	}

	// One-sided absence is not "unknown, so carry on". Gate 2 treated it that
	// way, which made deleting the candidate's profile block a way to turn a
	// changed architecture back into an unchanged one -- weakening the evidence
	// bought a greener answer. Both directions are now inconclusive.
	half := target("k", C, true)
	for _, tc := range []struct {
		name       string
		base, cand schema.Target
	}{
		{"candidate lost its profile block", baselineTarget, half},
		{"baseline never had one", half, baselineTarget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := build(t, report(tc.base), report(tc.cand))
			cell := onlyCell(t, d)
			if cell.Classification != Inconclusive {
				t.Fatalf("want %s, got %s (%s)", Inconclusive, cell.Classification, cell.Reason)
			}
			if !strings.Contains(cell.Reason, "one side does not say") {
				t.Fatalf("the reason must name the missing side: %q", cell.Reason)
			}
		})
	}

	// Both sides silent is the shape of older evidence and stays governed by
	// the other rules rather than being refused for its age.
	d = build(t, report(half), report(half))
	if got := onlyCell(t, d).Classification; got != UnchangedCompatible {
		t.Fatalf("evidence that predates profile metadata must remain comparable: got %s", got)
	}
}

// A shallower candidate must not inherit a deeper baseline's green.
func TestValidationDepthChangeIsInconclusive(t *testing.T) {
	C := schema.VerdictCompatible
	withAttach := func(mode string) schema.Target {
		tg := target("k", C, true)
		tg.Validation = &schema.Validation{AttachMode: mode}
		return tg
	}
	d, exit, err := compareFiles(t,
		jsonOf(t, report(withAttach("best-effort"))), jsonOf(t, report(withAttach("disabled"))))
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	cell := onlyCell(t, d)
	if cell.Classification != Inconclusive {
		t.Fatalf("want %s, got %s (%s)", Inconclusive, cell.Classification, cell.Reason)
	}
	if exit != ExitInconclusive {
		t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
	}
	if got := onlyCell(t, build(t, report(withAttach("best-effort")), report(withAttach("best-effort")))).Classification; got != UnchangedCompatible {
		t.Fatalf("an unchanged attach mode must still compare: got %s", got)
	}
}

// STEP 9. Loader identity: what is the product, and what is the instrument.
func TestLoaderIdentitySemantics(t *testing.T) {
	C := schema.VerdictCompatible

	t.Run("a changed command contract makes every cell inconclusive", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			edit func(*schema.CommandInfo)
		}{
			{"different command", func(c *schema.CommandInfo) { c.InvocationSHA256 = "other" }},
			{"different success exit code", func(c *schema.CommandInfo) { c.ExpectedExitCode = 7 }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				base := report(target("k", C, true))
				base.Command = &schema.CommandInfo{InvocationSHA256: "inv", ExpectedExitCode: 0,
					Binary: &schema.BinaryIdentity{SHA256: "loader-v1"}}
				cand := report(target("k", C, true))
				cmd := *base.Command
				cmd.Binary = &schema.BinaryIdentity{SHA256: "loader-v2"}
				tc.edit(&cmd)
				cand.Command = &cmd

				d, exit, err := compareFiles(t, jsonOf(t, base), jsonOf(t, cand))
				if err != nil {
					t.Fatalf("unexpected refusal: %v", err)
				}
				if got := onlyCell(t, d).Classification; got != Inconclusive {
					t.Fatalf("want %s, got %s", Inconclusive, got)
				}
				if exit != ExitInconclusive {
					t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
				}
				if len(d.Notes) == 0 {
					t.Fatal("the contract change must be stated in the evidence")
				}
			})
		}
	})

	// The project's own loader is the thing being released. Requiring it to be
	// byte-identical between release N and N+1 would make every real command
	// mode comparison incomparable, which is not a safety property -- it is a
	// gate nobody can use.
	t.Run("the project's loader binary may change", func(t *testing.T) {
		base := report(target("k", C, true))
		base.Command = &schema.CommandInfo{InvocationSHA256: "inv", Binary: &schema.BinaryIdentity{SHA256: "loader-v1"}}
		cand := report(target("k", C, true))
		cand.Command = &schema.CommandInfo{InvocationSHA256: "inv", Binary: &schema.BinaryIdentity{SHA256: "loader-v2"}}

		d, exit, err := compareFiles(t, jsonOf(t, base), jsonOf(t, cand))
		if err != nil {
			t.Fatalf("unexpected refusal: %v", err)
		}
		if got := onlyCell(t, d).Classification; got != UnchangedCompatible {
			t.Fatalf("a new build of the released loader is the point of the comparison; got %s", got)
		}
		if exit != ExitNoRegressions {
			t.Fatalf("want exit 0, got %d", exit)
		}
	})

	// The generic validator is bpfcompat's measuring instrument. A changed
	// build is recorded as traceability, and deliberately does not gate.
	t.Run("a changed validator build is noted, not gated", func(t *testing.T) {
		base := report(target("k", C, true))
		base.Validator = &schema.BinaryIdentity{SHA256: strings.Repeat("a", 64)}
		cand := report(target("k", C, true))
		cand.Validator = &schema.BinaryIdentity{SHA256: strings.Repeat("b", 64)}

		d, exit, err := compareFiles(t, jsonOf(t, base), jsonOf(t, cand))
		if err != nil {
			t.Fatalf("unexpected refusal: %v", err)
		}
		if exit != ExitNoRegressions {
			t.Fatalf("a bpfcompat upgrade must not make every environment incomparable; got exit %d", exit)
		}
		if len(d.Notes) == 0 || !strings.Contains(strings.Join(d.Notes, " "), "validator build differs") {
			t.Fatalf("the instrument change must be traceable in the evidence: %v", d.Notes)
		}
	})
}

// STEP 10. A hostile CI artifact must not be read into memory before it is
// judged.
func TestOversizedEvidenceIsRefusedBeforeParsing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"schema_version":"v0.1","filler":"`); err != nil {
		t.Fatal(err)
	}
	chunk := strings.Repeat("A", 1<<20)
	for written := 0; written <= maxEvidenceBytes; written += len(chunk) {
		if _, err := f.WriteString(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvidence(path, "candidate"); err == nil {
		t.Fatal("a file past the evidence limit must be refused")
	} else if !strings.Contains(err.Error(), "evidence limit") {
		t.Fatalf("the refusal must say why: %v", err)
	}
}

// Deep nesting must be refused rather than recursed into.
func TestPathologicallyNestedJSONIsRefusedNotRecursed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deep.json")
	deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	if err := os.WriteFile(path, []byte(deep), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvidence(path, "candidate"); err == nil {
		t.Fatal("deeply nested input must be refused")
	}
}

// STEP 11. The comparison must not destroy the evidence it compares.
func TestOutputNeverOverwritesInputEvidence(t *testing.T) {
	dir := t.TempDir()
	bp := filepath.Join(dir, "baseline.json")
	cp := filepath.Join(dir, "candidate.json")
	base, cand := greenPair(t)
	if err := os.WriteFile(bp, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, []byte(cand), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Compare(bp, cp, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, path string
	}{
		{"over the baseline", bp},
		{"over the candidate", cp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if err := WriteJSON(tc.path, d); err == nil {
				t.Fatal("writing the diff over its own input must be refused")
			}
			if err := WriteMarkdown(tc.path, d); err == nil {
				t.Fatal("writing the Markdown over its own input must be refused")
			}
			after, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("the input evidence was modified")
			}
		})
	}

	// A link is a different name for the same file, and the guard compares
	// identity rather than spelling. Comparing absolute paths let `--out
	// alias.json` destroy the baseline it pointed at while the check saw two
	// unequal strings.
	t.Run("through a symbolic link", func(t *testing.T) {
		alias := filepath.Join(dir, "alias.json")
		if err := os.Symlink(bp, alias); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		defer os.Remove(alias) //nolint:errcheck // best effort cleanup
		before, err := os.ReadFile(bp)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteJSON(alias, d); err == nil {
			t.Fatal("a symlink to the baseline is still the baseline")
		}
		after, err := os.ReadFile(bp)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("the baseline evidence was destroyed through a symlink")
		}
	})

	t.Run("through a hard link", func(t *testing.T) {
		hard := filepath.Join(dir, "hard.json")
		if err := os.Link(bp, hard); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		defer os.Remove(hard) //nolint:errcheck // best effort cleanup
		before, err := os.ReadFile(bp)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteMarkdown(hard, d); err == nil {
			t.Fatal("a hard link to the baseline is still the baseline")
		}
		after, err := os.ReadFile(bp)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("the baseline evidence was destroyed through a hard link")
		}
	})

	// Two names for one output file must be recognised as one file; two
	// genuinely different ones must not.
	t.Run("output identity", func(t *testing.T) {
		if !SameFile(bp, bp) {
			t.Fatal("a path must be the same file as itself")
		}
		if SameFile(bp, cp) {
			t.Fatal("two distinct reports must not compare as one file")
		}
		if !SameFile(filepath.Join(dir, "new.json"), filepath.Join(dir, "sub", "..", "new.json")) {
			t.Fatal("two routes to one not-yet-created file must compare as one file")
		}
		if SameFile(filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")) {
			t.Fatal("two not-yet-created files with different names are not one file")
		}
	})

	// A path that is not an input still writes.
	out := filepath.Join(dir, "diff.json")
	if err := WriteJSON(out, d); err != nil {
		t.Fatalf("a normal output path must still work: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("diff JSON was not written: %v", err)
	}
}

// STEP 12. Comparing a run with itself is a wiring mistake, not a release
// decision: it is permanently, trivially green.
func TestAReportComparedWithItselfIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	base, _ := greenPair(t)
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Compare(path, path, time.Unix(0, 0)); err == nil {
		t.Fatal("the same file on both sides must not produce a green release gate")
	}

	// The same run copied to two paths is the same wiring mistake wearing a
	// different name, and is caught by run identity rather than by path.
	copyPath := filepath.Join(dir, "copy.json")
	if err := os.WriteFile(copyPath, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Compare(path, copyPath, time.Unix(0, 0))
	if err == nil {
		t.Fatal("a copy of the same run must be recognised as the same run")
	}
	if !strings.Contains(err.Error(), "same run") {
		t.Fatalf("the refusal must name the cause: %v", err)
	}

	// Two genuinely distinct runs with the same content still compare: it is
	// run identity that matters, not byte equality.
	other := report(target("k", schema.VerdictCompatible, true))
	otherPath := filepath.Join(dir, "other.json")
	if err := os.WriteFile(otherPath, []byte(jsonOf(t, other)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Compare(path, otherPath, time.Unix(0, 0)); err != nil {
		t.Fatalf("two distinct runs must compare: %v", err)
	}
}

// STEP 14, expressed as behaviour: every guard added here is load-bearing, so
// removing any one of them turns one of these inputs green. Each row is a
// fail-open mutation stated as an input rather than as a patch to the source.
func TestNoUntrustworthyEvidenceReachesExitZero(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	base, _ := greenPair(t)

	contradictory := report(target("k", C, true))
	contradictory.Targets[0].Status = "fail"
	contradictory.Summary = schema.SummaryInfo{}

	noEnv := report(target("k", C, true))
	noEnv.Targets[0].Environment = nil
	noEnv.Summary.Complete = b(schema.RunComplete(noEnv.Targets))

	summaryLies := report(target("k", C, true))
	summaryLies.Summary.Verdict = I
	summaryLies.Summary.Status = "fail"

	archChanged := report(target("k", C, true))
	archChanged.Targets[0].Profile = &schema.TargetEnv{Arch: "arm64"}

	regressed := jsonOf(t, report(target("k", I, true)))

	for _, tc := range []struct{ name, candidate string }{
		{"status and verdict contradict", jsonOf(t, contradictory)},
		{"environment never recorded", jsonOf(t, noEnv)},
		{"summary contradicts its targets", jsonOf(t, summaryLies)},
		{"duplicate verdict keys", strings.Replace(jsonOf(t, report(target("k", I, true))),
			`"verdict": "INCOMPATIBLE"`, `"verdict": "INCOMPATIBLE",`+"\n"+`  "verdict": "COMPATIBLE"`, 1)},
		{"requiredness deleted around a regression", strings.Replace(regressed, `"required": true,`, ``, 1)},
		{"trailing second document", jsonOf(t, report(target("k", C, true))) + "\n{}"},
		{"obligation silently repointed at another architecture", jsonOf(t, archChanged)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baselineJSON := base
			if strings.Contains(tc.name, "architecture") {
				withProfile := report(target("k", C, true))
				withProfile.Targets[0].Profile = &schema.TargetEnv{Arch: "x86_64"}
				baselineJSON = jsonOf(t, withProfile)
			}
			d, exit, err := compareFiles(t, baselineJSON, tc.candidate)
			if exit == ExitNoRegressions {
				t.Fatalf("untrustworthy evidence reached exit 0 (result=%s err=%v)", d.Summary.Result, err)
			}
		})
	}
}

// The mirror: none of the new strictness may turn a genuine, complete,
// self-consistent pair into a refusal. A gate that fails on real evidence is
// not a safer gate, it is an ignored one.
func TestGenuineEvidenceStillCompares(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	full := func(verdict string, required bool) schema.Target {
		tg := target("k", verdict, required)
		tg.Profile = &schema.TargetEnv{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"}
		tg.Validation = &schema.Validation{AttachMode: "best-effort", LoadStatus: "ok"}
		return tg
	}
	for _, tc := range []struct {
		name       string
		base, cand string
		wantClass  string
		wantExit   int
	}{
		{"still supported", C, C, UnchangedCompatible, ExitNoRegressions},
		{"newly broken", C, I, NewRegression, ExitRegressed},
		{"still broken", I, I, ExistingIncompatibility, ExitNoRegressions},
		{"newly fixed", I, C, Fixed, ExitNoRegressions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, exit, err := compareFiles(t,
				jsonOf(t, report(full(tc.base, true))), jsonOf(t, report(full(tc.cand, true))))
			if err != nil {
				t.Fatalf("genuine evidence was refused: %v", err)
			}
			if got := onlyCell(t, d).Classification; got != tc.wantClass {
				t.Fatalf("want %s, got %s (%s)", tc.wantClass, got, onlyCell(t, d).Reason)
			}
			if exit != tc.wantExit {
				t.Fatalf("want exit %d, got %d", tc.wantExit, exit)
			}
		})
	}
}

// Pre-Gate-1 reports are the most common real-world "older report": they carry
// status and no verdict, and no environment at all. They must be readable and
// unusable -- refusing them outright would confuse age with tampering, and
// trusting them would let evidence that predates the contract gate a release.
func TestPreGateOneReportsAreReadableButNeverConclusive(t *testing.T) {
	old := schema.ReportV01{
		SchemaVersion: "v0.1",
		Run:           schema.RunInfo{ID: fmt.Sprintf("legacy-%d", runIDs.Add(1))},
		Targets:       []schema.Target{{ProfileID: "k", Required: true, Status: "pass"}},
		Summary:       schema.SummaryInfo{Status: "pass"},
	}
	base, _ := greenPair(t)
	d, exit, err := compareFiles(t, jsonOf(t, old), base)
	if err != nil {
		t.Fatalf("an older report is unusable evidence, not malformed evidence: %v", err)
	}
	if got := onlyCell(t, d).Classification; got != Inconclusive {
		t.Fatalf("want %s, got %s", Inconclusive, got)
	}
	if exit != ExitInconclusive {
		t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
	}
}
