package suite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// gateCase is one stubbed case outcome, keyed by the case's artifact name.
type gateCase struct {
	exit    int
	targets []schema.Target
	err     error // ExecuteBootstrap itself failed: no report at all
}

func optTarget(verdict string) schema.Target {
	return schema.Target{ProfileID: "p-opt", Required: false, Status: statusFor(verdict), Verdict: verdict}
}

func reqTarget(verdict string) schema.Target {
	return schema.Target{ProfileID: "p-req", Required: true, Status: statusFor(verdict), Verdict: verdict}
}

func statusFor(verdict string) string {
	switch verdict {
	case schema.VerdictIncompatible:
		return "fail"
	case schema.VerdictInfraError:
		return "infra_error"
	}
	return "pass"
}

// runGateSuite writes a suite whose cases are named after the keys of cases,
// stubs the per-case run, and executes the real suite aggregation.
func runGateSuite(t *testing.T, requireGate bool, names []string, cases map[string]gateCase) Summary {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "m.yaml"), []byte("name: m\nprofiles:\n  - id: p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var spec strings.Builder
	spec.WriteString("name: gate\ndefaults:\n  matrix: m.yaml\n  report_dir: out\ncases:\n")
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n+".bpf.o"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		spec.WriteString("  - name: " + n + "\n    artifact: " + n + ".bpf.o\n")
	}
	suitePath := filepath.Join(dir, "suite.yaml")
	if err := os.WriteFile(suitePath, []byte(spec.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := executeBootstrapFn
	t.Cleanup(func() { executeBootstrapFn = orig })
	executeBootstrapFn = func(ctx context.Context, cfg runner.Config) (runner.RunResult, error) {
		name := strings.TrimSuffix(filepath.Base(cfg.ArtifactPath), ".bpf.o")
		c, ok := cases[name]
		if !ok {
			t.Fatalf("unexpected case %q", name)
		}
		if c.err != nil {
			return runner.RunResult{}, c.err
		}
		r := schema.ReportV01{Run: schema.RunInfo{ID: "run-" + name}, Targets: c.targets}
		r.Summary.Verdict = schema.RunVerdict(c.targets)
		r.Summary.Status = map[string]string{schema.VerdictCompatible: "pass", schema.VerdictIncompatible: "fail", schema.VerdictInfraError: "error"}[r.Summary.Verdict]
		return runner.RunResult{ExitCode: c.exit, Report: r}, nil
	}

	summary, err := Execute(context.Background(), RunOptions{
		SuitePath:    suitePath,
		OutPath:      filepath.Join(dir, "suite.json"),
		MarkdownPath: filepath.Join(dir, "suite.md"),
		RequireGate:  requireGate,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	return summary
}

func caseByName(t *testing.T, s Summary, name string) CaseSummary {
	t.Helper()
	for i := range s.Cases {
		if s.Cases[i].Name == name {
			return s.Cases[i]
		}
	}
	t.Fatalf("case %q not in summary", name)
	return CaseSummary{}
}

// The suite must distinguish a diagnostic case (no required target) from a
// satisfied gate, per case and in aggregate, without changing the default
// exit code.
func TestSuiteGateIsVisiblePerCaseAndInAggregate(t *testing.T) {
	cases := map[string]gateCase{
		"diag":  {exit: runner.ExitSuccess, targets: []schema.Target{optTarget(schema.VerdictIncompatible)}},
		"gated": {exit: runner.ExitSuccess, targets: []schema.Target{reqTarget(schema.VerdictCompatible)}},
	}
	s := runGateSuite(t, false, []string{"diag", "gated"}, cases)
	if s.ExitCode != runner.ExitSuccess || s.Status != "pass" {
		t.Fatalf("default suite exit/status must stay 0/pass, got %d/%s", s.ExitCode, s.Status)
	}
	if got := caseByName(t, s, "diag").Gate; got != schema.GateNone {
		t.Fatalf("diag case gate = %q, want none", got)
	}
	if got := caseByName(t, s, "gated").Gate; got != schema.GateEnforced {
		t.Fatalf("gated case gate = %q, want enforced", got)
	}
	if s.Gate != GatePartial {
		t.Fatalf("aggregate gate = %q, want %q", s.Gate, GatePartial)
	}
	md := RenderMarkdown(s)
	for _, want := range []string{"- Gate: `partial`", "| Gate |", "`none`", "`enforced`", "diagnostic"} {
		if !strings.Contains(md, want) {
			t.Fatalf("suite markdown missing %q:\n%s", want, md)
		}
	}
}

func TestSuiteAggregateGateValues(t *testing.T) {
	req := gateCase{exit: runner.ExitSuccess, targets: []schema.Target{reqTarget(schema.VerdictCompatible)}}
	opt := gateCase{exit: runner.ExitSuccess, targets: []schema.Target{optTarget(schema.VerdictCompatible)}}
	if s := runGateSuite(t, false, []string{"a", "b"}, map[string]gateCase{"a": req, "b": req}); s.Gate != schema.GateEnforced {
		t.Fatalf("all cases gated: aggregate %q, want enforced", s.Gate)
	}
	if s := runGateSuite(t, false, []string{"a", "b"}, map[string]gateCase{"a": opt, "b": opt}); s.Gate != schema.GateNone {
		t.Fatalf("no case gated: aggregate %q, want none", s.Gate)
	}
}

// --require-gate is per case: every case must evaluate a gate. A diagnostic
// case exits 1 (contract not established), which the suite's existing
// precedence rolls up to exit 1. Gated cases keep their exit codes.
func TestSuiteRequireGateFailsDiagnosticCases(t *testing.T) {
	cases := map[string]gateCase{
		"diag":  {exit: runner.ExitSuccess, targets: []schema.Target{optTarget(schema.VerdictCompatible)}},
		"gated": {exit: runner.ExitSuccess, targets: []schema.Target{reqTarget(schema.VerdictCompatible)}},
	}
	s := runGateSuite(t, true, []string{"diag", "gated"}, cases)
	diag := caseByName(t, s, "diag")
	if diag.ExitCode != runner.ExitToolError || diag.Status != "error" || !strings.Contains(diag.Error, "require-gate") {
		t.Fatalf("diag case under --require-gate: exit %d status %q error %q", diag.ExitCode, diag.Status, diag.Error)
	}
	if g := caseByName(t, s, "gated"); g.ExitCode != runner.ExitSuccess || g.Status != "pass" {
		t.Fatalf("gated case must be unaffected: exit %d status %q", g.ExitCode, g.Status)
	}
	if s.ExitCode != runner.ExitToolError {
		t.Fatalf("suite exit %d, want %d", s.ExitCode, runner.ExitToolError)
	}

	if s := runGateSuite(t, true, []string{"gated"}, cases); s.ExitCode != runner.ExitSuccess {
		t.Fatalf("an all-gated suite passes --require-gate, got exit %d", s.ExitCode)
	}
	reqFail := map[string]gateCase{"bad": {exit: runner.ExitCompatibilityFailure, targets: []schema.Target{reqTarget(schema.VerdictIncompatible)}}}
	if s := runGateSuite(t, true, []string{"bad"}, reqFail); s.ExitCode != runner.ExitCompatibilityFailure {
		t.Fatalf("--require-gate must keep a required failure at exit 2, got %d", s.ExitCode)
	}
}

// A case that produced no report has no evidence of a gate: its gate is
// unknown, it never counts as enforced, and it can never make the aggregate
// "enforced".
func TestSuiteMissingCaseReportNeverCountsAsGate(t *testing.T) {
	cases := map[string]gateCase{
		"gated":  {exit: runner.ExitSuccess, targets: []schema.Target{reqTarget(schema.VerdictCompatible)}},
		"broken": {err: errors.New("qemu not found")},
	}
	s := runGateSuite(t, false, []string{"gated", "broken"}, cases)
	if got := caseByName(t, s, "broken").Gate; got != GateUnknown {
		t.Fatalf("broken case gate = %q, want %q", got, GateUnknown)
	}
	if s.Gate == schema.GateEnforced {
		t.Fatal("a suite with a case that produced no report must not be gate enforced")
	}
	// A case with an empty target list is not a gate either.
	empty := map[string]gateCase{"empty": {exit: runner.ExitSuccess}}
	if s := runGateSuite(t, true, []string{"empty"}, empty); s.ExitCode != runner.ExitToolError || s.Gate == schema.GateEnforced {
		t.Fatalf("empty-target case under --require-gate: exit %d gate %q", s.ExitCode, s.Gate)
	}
}
