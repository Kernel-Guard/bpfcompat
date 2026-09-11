package regressiondiff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Property and fuzz coverage for the evidence trust boundary. Hand-picked cases
// prove the failures we thought of; these prove the shape of the contract
// itself, over inputs nobody chose.
//
// Both fuzz targets are bounded and deterministic in CI: `go test` runs their
// seed corpus only, and every seed is committed here rather than generated, so
// no run can be flaky. `go test -fuzz` explores further on demand.

// exitZeroRequiresEstablishedRequiredEvidence is the whole gate in one
// function, and the postcondition every property below checks.
//
// Exit 0 claims that no required environment the baseline supported is broken.
// That claim is only honest if, for every obligation either side treated as
// required, the candidate positively settled it -- and, where the baseline also
// tested it, the baseline settled it too. Anything else is an absence, and an
// absence must reach exit 1.
func exitZeroRequiresEstablishedRequiredEvidence(t *testing.T, d Diff, context string) {
	t.Helper()
	if ExitCode(d) != ExitNoRegressions {
		return
	}
	for i := range d.Cells {
		c := &d.Cells[i]
		if !c.Required {
			continue
		}
		if !conclusive(c.Candidate) {
			t.Fatalf("%s: exit 0 with required obligation %q the candidate never established (%s: %s)",
				context, c.ProfileID, c.Classification, c.Reason)
		}
		if c.Baseline.Present && !conclusive(c.Baseline) {
			t.Fatalf("%s: exit 0 with required obligation %q whose baseline never established it (%s: %s)",
				context, c.ProfileID, c.Classification, c.Reason)
		}
	}
}

// requiredRegressionsAreProven is invariant C: the only statement this tool
// makes about someone's software must rest on two established results and an
// unchanged obligation.
func requiredRegressionsAreProven(t *testing.T, d Diff, context string) {
	t.Helper()
	for i := range d.Cells {
		c := &d.Cells[i]
		if c.Classification != NewRegression {
			continue
		}
		if !conclusive(c.Baseline) || c.Baseline.Verdict != schema.VerdictCompatible {
			t.Fatalf("%s: NEW_REGRESSION on %q without a baseline that proved support (%+v)", context, c.ProfileID, c.Baseline)
		}
		if !conclusive(c.Candidate) || c.Candidate.Verdict != schema.VerdictIncompatible {
			t.Fatalf("%s: NEW_REGRESSION on %q without a candidate that proved breakage (%+v)", context, c.ProfileID, c.Candidate)
		}
		if c.RequiredChanged {
			t.Fatalf("%s: NEW_REGRESSION on %q across a support-contract change", context, c.ProfileID)
		}
	}
}

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Invariant A and B over arbitrary bytes: no input panics, and anything that
// survives validation really does satisfy the comparison-key rules.
func FuzzLoadEvidence(f *testing.F) {
	valid := `{"schema_version":"v0.1","run":{"id":"r1"},"targets":[{"profile_id":"k","required":true,"status":"pass","verdict":"COMPATIBLE","environment":{"requested_kernel_family":"5.15","observed_kernel":"5.15.0-1","kernel_family_match":true}}],"summary":{"status":"pass","verdict":"COMPATIBLE","complete":true}}`
	for _, seed := range []string{
		valid,
		``,
		`{`,
		`null`,
		`[]`,
		`"a string"`,
		`{"schema_version":"v0.1"}`,
		`{"schema_version":"v0.1","targets":[]}`,
		valid + valid,
		valid + "\n\n\t",
		strings.Replace(valid, `"verdict":"COMPATIBLE"`, `"verdict":"INCOMPATIBLE","verdict":"COMPATIBLE"`, 1),
		strings.Replace(valid, `"required":true,`, ``, 1),
		strings.Replace(valid, `"required":true`, `"required":null`, 1),
		strings.Replace(valid, `"profile_id":"k"`, `"profile_id":"  "`, 1),
		strings.Replace(valid, `"status":"pass","verdict":"COMPATIBLE"`, `"status":"fail","verdict":"COMPATIBLE"`, 1),
		strings.Replace(valid, `"kernel_family_match":true`, `"kernel_family_match":null`, 1),
		strings.Repeat("[", 200) + strings.Repeat("]", 200),
		"\x00\x01\x02",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, blob string) {
		dir := t.TempDir()
		path := writeTemp(t, dir, "evidence.json", blob)

		ev, err := LoadEvidence(path, "candidate") // must not panic, whatever this is
		if err != nil {
			return
		}
		// Whatever survived must satisfy every key rule, because the rest of
		// the differ is written assuming it does.
		if len(ev.Report.Targets) == 0 {
			t.Fatal("accepted a report with no targets")
		}
		seen := map[string]bool{}
		for i := range ev.Report.Targets {
			id := strings.TrimSpace(ev.Report.Targets[i].ProfileID)
			if id == "" {
				t.Fatalf("accepted an unidentifiable obligation at target %d", i)
			}
			if seen[id] {
				t.Fatalf("accepted a duplicated profile_id %q", id)
			}
			seen[id] = true
			if i >= len(ev.requiredPresent) || !ev.requiredPresent[i] {
				t.Fatalf("accepted target %d without a stated `required`", i)
			}
		}
	})
}

// Invariants B and C over arbitrary pairs: whatever two files are handed in,
// exit 0 is only ever reached over established required evidence.
func FuzzCompareNeverGreensUnestablishedEvidence(f *testing.F) {
	mk := func(runID, verdict, status string, required bool, env string) string {
		return fmt.Sprintf(`{"schema_version":"v0.1","run":{"id":%q},"targets":[{"profile_id":"k","required":%t,"status":%q,"verdict":%q%s}],"summary":{}}`,
			runID, required, status, verdict, env)
	}
	goodEnv := `,"environment":{"requested_kernel_family":"5.15","observed_kernel":"5.15.0-1","kernel_family_match":true}`
	badEnv := `,"environment":{"requested_kernel_family":"5.15","observed_kernel":"6.1.0","kernel_family_match":false}`

	f.Add(mk("a", "COMPATIBLE", "pass", true, goodEnv), mk("b", "COMPATIBLE", "pass", true, goodEnv))
	f.Add(mk("a", "COMPATIBLE", "pass", true, goodEnv), mk("b", "INCOMPATIBLE", "fail", true, goodEnv))
	f.Add(mk("a", "COMPATIBLE", "pass", true, goodEnv), mk("b", "COMPATIBLE", "pass", true, ""))
	f.Add(mk("a", "COMPATIBLE", "pass", true, ""), mk("b", "COMPATIBLE", "pass", true, ""))
	f.Add(mk("a", "COMPATIBLE", "pass", true, badEnv), mk("b", "COMPATIBLE", "pass", true, goodEnv))
	f.Add(mk("a", "INFRA_ERROR", "infra_error", true, goodEnv), mk("b", "INCOMPATIBLE", "fail", true, goodEnv))
	f.Add(mk("a", "COMPATIBLE", "pass", true, goodEnv), mk("a", "COMPATIBLE", "pass", true, goodEnv))
	f.Add(`{}`, `{}`)
	f.Add(``, mk("b", "COMPATIBLE", "pass", true, goodEnv))

	f.Fuzz(func(t *testing.T, baseline, candidate string) {
		dir := t.TempDir()
		bp := writeTemp(t, dir, "baseline.json", baseline)
		cp := writeTemp(t, dir, "candidate.json", candidate)

		d, err := Compare(bp, cp, time.Unix(0, 0)) // must not panic
		if err != nil {
			return
		}
		exitZeroRequiresEstablishedRequiredEvidence(t, d, "fuzz")
		requiredRegressionsAreProven(t, d, "fuzz")

		// Rendering must survive anything the comparison accepted: a release
		// gate that panics while writing its own report has still failed.
		_ = Markdown(d)
		if _, err := json.Marshal(d); err != nil {
			t.Fatalf("diff could not be serialised: %v", err)
		}
	})
}

// Invariant D: the diff is a function of the evidence, not of the order rows
// happen to appear in.
func TestReorderingTargetsCannotChangeTheDiff(t *testing.T) {
	C, I, E := schema.VerdictCompatible, schema.VerdictIncompatible, schema.VerdictInfraError
	baseTargets := []schema.Target{
		target("a", C, true), target("b", I, true), target("c", C, false),
		target("d", E, false), mismatched(target("e", C, true)),
	}
	candTargets := []schema.Target{
		target("a", I, true), target("b", I, true), target("c", C, false),
		target("d", C, false), target("e", C, true),
	}

	want := build(t, report(baseTargets...), report(candTargets...))
	wantJSON, err := json.Marshal(want.Cells)
	if err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(20260910)) // fixed seed: deterministic in CI
	for i := 0; i < 50; i++ {
		shuffledBase := append([]schema.Target(nil), baseTargets...)
		shuffledCand := append([]schema.Target(nil), candTargets...)
		rng.Shuffle(len(shuffledBase), func(x, y int) {
			shuffledBase[x], shuffledBase[y] = shuffledBase[y], shuffledBase[x]
		})
		rng.Shuffle(len(shuffledCand), func(x, y int) {
			shuffledCand[x], shuffledCand[y] = shuffledCand[y], shuffledCand[x]
		})
		got := build(t, report(shuffledBase...), report(shuffledCand...))
		gotJSON, err := json.Marshal(got.Cells)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotJSON, wantJSON) {
			t.Fatalf("permutation %d changed the diff:\n%s\n%s", i, wantJSON, gotJSON)
		}
		// Compared as JSON: Summary holds *bool fields, and comparing the
		// structs directly would compare pointer identity rather than the
		// coverage flags they carry.
		gotSummary, err := json.Marshal(got.Summary)
		if err != nil {
			t.Fatal(err)
		}
		wantSummary, err := json.Marshal(want.Summary)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotSummary, wantSummary) {
			t.Fatalf("permutation %d changed the summary:\n%s\n%s", i, wantSummary, gotSummary)
		}
	}
}

// Invariant E: a proven required regression cannot be buried under noise,
// however much of it arrives.
func TestNoiseCannotHideAProvenRequiredRegression(t *testing.T) {
	C, I, E, U := schema.VerdictCompatible, schema.VerdictIncompatible,
		schema.VerdictInfraError, schema.VerdictUnsupported

	noise := []struct {
		name       string
		base, cand *schema.Target
	}{
		{"optional infra failure", p(target("n1", C, false)), p(target("n1", E, false))},
		{"optional unsupported", p(target("n2", C, false)), p(target("n2", U, false))},
		{"optional regression", p(target("n3", C, false)), p(target("n3", I, false))},
		{"required infra failure", p(target("n4", C, true)), p(target("n4", E, true))},
		{"required coverage removed", p(target("n5", C, true)), nil},
		{"coverage added", nil, p(target("n6", C, true))},
		{"requiredness churn", p(target("n7", C, true)), p(target("n7", C, false))},
		{"environment mismatch", p(target("n8", C, true)), p(mismatched(target("n8", C, true)))},
		{"a fix elsewhere", p(target("n9", I, true)), p(target("n9", C, true))},
		{"an existing limitation", p(target("n10", I, true)), p(target("n10", I, true))},
	}

	baseTargets := []schema.Target{target("gating", C, true)}
	candTargets := []schema.Target{target("gating", I, true)}
	for _, n := range noise {
		if n.base != nil {
			baseTargets = append(baseTargets, *n.base)
		}
		if n.cand != nil {
			candTargets = append(candTargets, *n.cand)
		}
		d := build(t, report(baseTargets...), report(candTargets...))
		if d.Summary.NewRequiredRegressions != 1 {
			t.Fatalf("after adding %q: want 1 required regression, got %d", n.name, d.Summary.NewRequiredRegressions)
		}
		if d.Summary.Result != ResultRegressed || ExitCode(d) != ExitRegressed {
			t.Fatalf("after adding %q: a proven regression was downgraded to %s (exit %d)", n.name, d.Summary.Result, ExitCode(d))
		}
		requiredRegressionsAreProven(t, d, "noise:"+n.name)
	}
}

// Invariant F, in the direction that matters for a release gate: deleting
// evidence never buys a green result. (It can legitimately narrow the claim --
// a baseline that never tested an environment cannot have regressed on it --
// so the property is stated as the contract exit 0 actually promises, not as a
// blanket monotonicity that would be false.)
func TestRemovingEvidenceNeverBuysAGreenResult(t *testing.T) {
	C, I, E := schema.VerdictCompatible, schema.VerdictIncompatible, schema.VerdictInfraError

	scenarios := map[string][2]schema.Target{
		"proven regression":     {target("k", C, true), target("k", I, true)},
		"unchanged compatible":  {target("k", C, true), target("k", C, true)},
		"unproven baseline":     {target("k", E, true), target("k", I, true)},
		"mismatched candidate":  {target("k", C, true), mismatched(target("k", C, true))},
		"optional obligation":   {target("k", C, false), target("k", I, false)},
		"existing incompatible": {target("k", I, true), target("k", I, true)},
	}

	// Each mutation deletes information from the raw JSON, which is what a
	// truncating CI artifact step or a hand edit actually does.
	deletions := []struct{ name, find, replace string }{
		{"verdict deleted", `"verdict": "`, `"unused_verdict": "`},
		{"status deleted", `"status": "`, `"unused_status": "`},
		{"environment deleted", `"environment": {`, `"unused_environment": {`},
		{"kernel_family_match deleted", `"kernel_family_match":`, `"unused_match":`},
		{"observed kernel deleted", `"observed_kernel": "`, `"unused_observed": "`},
		{"required deleted", `"required": true,`, ``},
		{"summary verdict deleted", `"verdict": "COMPATIBLE",`, ``},
		{"whole targets array emptied", `"targets": [`, `"unused_targets": [`},
	}

	for name, pair := range scenarios {
		for _, side := range []string{"baseline", "candidate"} {
			for _, del := range deletions {
				t.Run(fmt.Sprintf("%s/%s/%s", name, side, del.name), func(t *testing.T) {
					baseJSON := jsonOf(t, report(pair[0]))
					candJSON := jsonOf(t, report(pair[1]))
					if side == "baseline" {
						baseJSON = strings.Replace(baseJSON, del.find, del.replace, 1)
					} else {
						candJSON = strings.Replace(candJSON, del.find, del.replace, 1)
					}
					d, exit, err := compareFiles(t, baseJSON, candJSON)
					if err != nil {
						return // refused: the strongest form of not-green
					}
					if exit == ExitNoRegressions {
						exitZeroRequiresEstablishedRequiredEvidence(t, d, name+"/"+del.name)
					}
					requiredRegressionsAreProven(t, d, name+"/"+del.name)
				})
			}
		}
	}
}

// Adding optional, irrelevant fields must not change a release decision: a
// report is judged on the evidence the contract names, not on its size.
func TestIrrelevantNoiseDoesNotChangeTheDecision(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	baseJSON := jsonOf(t, report(target("k", C, true)))
	candJSON := jsonOf(t, report(target("k", I, true)))

	want, wantExit, err := compareFiles(t, baseJSON, candJSON)
	if err != nil {
		t.Fatal(err)
	}

	noisy := strings.Replace(candJSON, `"profile_id": "k",`,
		`"profile_id": "k", "notes": ["a", "b"], "duration_ms": 1234, "qemu_command": "qemu -x -y", "serial_log": "/tmp/x.log",`, 1)
	got, gotExit, err := compareFiles(t, baseJSON, noisy)
	if err != nil {
		t.Fatalf("optional fields must not make evidence unreadable: %v", err)
	}
	if gotExit != wantExit || got.Summary.Result != want.Summary.Result {
		t.Fatalf("irrelevant fields changed the decision: %s/%d became %s/%d",
			want.Summary.Result, wantExit, got.Summary.Result, gotExit)
	}
	if got.Summary.NewRequiredRegressions != 1 {
		t.Fatalf("the regression was lost under noise: %+v", got.Summary)
	}
}
