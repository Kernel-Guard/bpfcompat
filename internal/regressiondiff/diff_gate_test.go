package regressiondiff

import (
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// A diff with no required cell cannot regress: overallResult only counts
// required cells. So an optional target that went COMPATIBLE -> INCOMPATIBLE
// yields NO_NEW_REGRESSIONS / exit 0. That default is established and stays,
// but the diff must say it is diagnostic, not a gate, and show each side's
// report gate.
func TestDiffWithNoRequiredCellIsLabelledDiagnostic(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	d := build(t, report(target("k", C, false)), report(target("k", I, false)))

	if d.Summary.NewOptionalRegressions != 1 {
		t.Fatalf("fixture: want one optional regression, got %+v", d.Summary)
	}
	if d.Summary.Result != ResultNoRegressions || ExitCode(d) != ExitNoRegressions {
		t.Fatalf("default result/exit must stay %s/0, got %s/%d", ResultNoRegressions, d.Summary.Result, ExitCode(d))
	}
	if d.Summary.Gate != schema.GateNone {
		t.Fatalf("summary.gate = %q, want %q", d.Summary.Gate, schema.GateNone)
	}
	if d.Summary.BaselineGate != schema.GateNone || d.Summary.CandidateGate != schema.GateNone {
		t.Fatalf("each side's report gate must be shown: baseline %q candidate %q", d.Summary.BaselineGate, d.Summary.CandidateGate)
	}
	if !strings.Contains(strings.Join(d.Notes, "\n"), NoRequiredComparisonNote) {
		t.Fatalf("missing the diagnostic-diff note; notes: %q", d.Notes)
	}
	md := Markdown(d)
	for _, want := range []string{"Gate: `none`", "diagnostic diff, not a gate", "Report gates: baseline `none` -> candidate `none`"} {
		if !strings.Contains(md, want) {
			t.Fatalf("Markdown must contain %q:\n%s", want, md)
		}
	}
}

func TestDiffWithARequiredCellIsAGate(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	d := build(t, report(target("k", C, true), target("o", C, false)), report(target("k", C, true), target("o", I, false)))
	if d.Summary.Gate != schema.GateEnforced {
		t.Fatalf("summary.gate = %q, want %q", d.Summary.Gate, schema.GateEnforced)
	}
	if d.Summary.BaselineGate != schema.GateEnforced || d.Summary.CandidateGate != schema.GateEnforced {
		t.Fatalf("side gates: %q %q", d.Summary.BaselineGate, d.Summary.CandidateGate)
	}
	if strings.Contains(strings.Join(d.Notes, "\n"), NoRequiredComparisonNote) {
		t.Fatalf("a gated diff must not carry the diagnostic note")
	}
}

// --require-gate: a diff with no required cell exits 1 (requested gate not
// established), never 2; a gated diff keeps its exit code, including 2.
func TestRequireGateExitCode(t *testing.T) {
	C, I := schema.VerdictCompatible, schema.VerdictIncompatible
	diag := build(t, report(target("k", C, false)), report(target("k", I, false)))
	if got := GateExitCode(diag, false); got != ExitNoRegressions {
		t.Fatalf("default exit for a diagnostic diff must stay 0, got %d", got)
	}
	if got := GateExitCode(diag, true); got != ExitInconclusive {
		t.Fatalf("--require-gate over a diagnostic diff: exit %d, want %d", got, ExitInconclusive)
	}
	regressed := build(t, report(target("k", C, true)), report(target("k", I, true)))
	if got := GateExitCode(regressed, true); got != ExitRegressed {
		t.Fatalf("--require-gate must keep a required regression at exit 2, got %d", got)
	}
	clean := build(t, report(target("k", C, true)), report(target("k", C, true)))
	if got := GateExitCode(clean, true); got != ExitNoRegressions {
		t.Fatalf("--require-gate over a satisfied gate: exit %d, want 0", got)
	}
}
