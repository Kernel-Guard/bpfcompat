package schema

import (
	"strings"
	"testing"
)

// RunVerdict only considers required targets, so a run with none returns
// COMPATIBLE whatever its targets did. RunGate is the signal that tells a
// consumer whether that verdict is a satisfied compatibility gate at all.
func TestRunGateDistinguishesDiagnosticRunsFromGates(t *testing.T) {
	cases := []struct {
		name    string
		targets []Target
		want    string
	}{
		{"no targets", nil, GateNone},
		{"all optional pass", []Target{{Required: false, Verdict: VerdictCompatible}}, GateNone},
		{"all optional fail", []Target{{Required: false, Verdict: VerdictIncompatible}}, GateNone},
		{"all optional infra", []Target{{Required: false, Verdict: VerdictInfraError}}, GateNone},
		{"required pass, optional fail", []Target{
			{Required: true, Verdict: VerdictCompatible},
			{Required: false, Verdict: VerdictIncompatible},
		}, GateEnforced},
		{"required fail", []Target{{Required: true, Verdict: VerdictIncompatible}}, GateEnforced},
	}
	for _, tc := range cases {
		if got := RunGate(tc.targets); got != tc.want {
			t.Errorf("%s: RunGate = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The gate signal is additive: it must not change the verdict a no-gate run
// already reports, or older consumers (and `bpfcompat diff`, which recomputes
// the verdict from targets) would see a report that disagrees with itself.
func TestRunGateDoesNotRedefineTheVerdict(t *testing.T) {
	allFail := []Target{{Required: false, Verdict: VerdictIncompatible}}
	if got := RunVerdict(allFail); got != VerdictCompatible {
		t.Fatalf("RunVerdict for an optional-only run is %q; the established value is %q and must not change", got, VerdictCompatible)
	}
	if RunGate(allFail) != GateNone {
		t.Fatal("an optional-only run must report gate none")
	}
}

func TestNoGateNoteSaysDiagnosticNotGate(t *testing.T) {
	for _, want := range []string{"no required targets", "diagnostic", "not a compatibility gate"} {
		if !strings.Contains(NoGateNote, want) {
			t.Errorf("NoGateNote %q must say %q", NoGateNote, want)
		}
	}
}
