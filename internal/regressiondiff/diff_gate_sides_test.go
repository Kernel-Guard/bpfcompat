package regressiondiff

import (
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// A diff is a gate only when at least one profile is required in BOTH
// reports. A diagnostic candidate (no required target) compared against a
// gated baseline must never read as a gated diff, whatever the result -- the
// release under evaluation evaluated no gate. (Overnight review B1.)
func TestDiagnosticCandidateNeverMakesAGatedDiff(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	d := build(t, report(target("k", C, true)), report(target("k", I, false)))
	if d.Summary.CandidateGate != schema.GateNone || d.Summary.BaselineGate != schema.GateEnforced {
		t.Fatalf("side gates: baseline %q candidate %q", d.Summary.BaselineGate, d.Summary.CandidateGate)
	}
	if d.Summary.Gate != schema.GateNone {
		t.Fatalf("a diagnostic candidate must give diff gate none, got %q", d.Summary.Gate)
	}
	if got := GateExitCode(d, true); got == ExitNoRegressions {
		t.Fatalf("--require-gate must not pass a diagnostic candidate")
	}
}

func TestDiagnosticBaselineNeverMakesAGatedDiff(t *testing.T) {
	C := schema.VerdictCompatible
	d := build(t, report(target("k", C, false)), report(target("k", C, true)))
	if d.Summary.Gate != schema.GateNone {
		t.Fatalf("a diagnostic baseline cannot anchor a gated comparison, got %q", d.Summary.Gate)
	}
	if got := GateExitCode(d, true); got != ExitInconclusive {
		t.Fatalf("--require-gate: exit %d, want %d", got, ExitInconclusive)
	}
}

// Required in both reports, but on different profiles: no profile carries a
// required obligation on both sides, so nothing gated was compared.
func TestRequiredOnDifferentProfilesIsNotAGate(t *testing.T) {
	C := schema.VerdictCompatible
	d := build(t,
		report(target("a", C, true), target("b", C, false)),
		report(target("a", C, false), target("b", C, true)))
	if d.Summary.BaselineGate != schema.GateEnforced || d.Summary.CandidateGate != schema.GateEnforced {
		t.Fatalf("fixture: both reports are gated: %q %q", d.Summary.BaselineGate, d.Summary.CandidateGate)
	}
	if d.Summary.Gate != schema.GateNone {
		t.Fatalf("no profile is required on both sides: want gate none, got %q", d.Summary.Gate)
	}
}

// --require-gate never masks a proven required regression.
func TestRequireGateKeepsProvenRegression(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	d := build(t, report(target("k", C, true)), report(target("k", I, true)))
	if d.Summary.Gate != schema.GateEnforced || GateExitCode(d, true) != ExitRegressed {
		t.Fatalf("gate %q exit %d", d.Summary.Gate, GateExitCode(d, true))
	}
}
