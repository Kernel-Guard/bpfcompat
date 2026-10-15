package main

import (
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

func gateResult(exit int, targets ...schema.Target) runner.RunResult {
	return runner.RunResult{ExitCode: exit, Report: schema.ReportV01{Targets: targets}}
}

// Without --require-gate every established exit code is preserved, including
// exit 0 for an optional-only (diagnostic) run.
func TestGateExitCodeDefaultPreservesEstablishedExitCodes(t *testing.T) {
	opt := schema.Target{Required: false, Verdict: schema.VerdictIncompatible}
	req := schema.Target{Required: true, Verdict: schema.VerdictIncompatible}
	for _, tc := range []struct {
		name string
		r    runner.RunResult
		want int
	}{
		{"optional-only run", gateResult(runner.ExitSuccess, opt), runner.ExitSuccess},
		{"required failure", gateResult(runner.ExitCompatibilityFailure, req), runner.ExitCompatibilityFailure},
		{"required infra", gateResult(runner.ExitToolError, req), runner.ExitToolError},
	} {
		if got := gateExitCode(tc.r, false); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.name, got, tc.want)
		}
	}
}

// With --require-gate a run that evaluated no gate cannot exit 0: the
// requested contract (a compatibility gate) was not established, which is
// exit 1, never exit 2 (nothing about the artifact was proven).
func TestRequireGateRefusesAnOptionalOnlyRun(t *testing.T) {
	opt := schema.Target{Required: false, Verdict: schema.VerdictCompatible}
	if got := gateExitCode(gateResult(runner.ExitSuccess, opt), true); got != runner.ExitToolError {
		t.Fatalf("--require-gate over an optional-only run: exit %d, want %d", got, runner.ExitToolError)
	}
	req := schema.Target{Required: true, Verdict: schema.VerdictCompatible}
	if got := gateExitCode(gateResult(runner.ExitSuccess, req), true); got != runner.ExitSuccess {
		t.Fatalf("--require-gate over a satisfied gate: exit %d, want %d", got, runner.ExitSuccess)
	}
	reqFail := schema.Target{Required: true, Verdict: schema.VerdictIncompatible}
	if got := gateExitCode(gateResult(runner.ExitCompatibilityFailure, reqFail), true); got != runner.ExitCompatibilityFailure {
		t.Fatalf("--require-gate must not mask a required failure: exit %d", got)
	}
}
