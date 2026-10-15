package runner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/vm"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// A run whose matrix has no required target is a diagnostic run. Its
// COMPATIBLE verdict is vacuous (RunVerdict ignores optional targets), so the
// run-level note must not say "All required profiles passed": that sentence
// reads as a satisfied compatibility gate when every target may have failed.
func TestOptionalOnlyRunIsLabelledDiagnosticNotAPassedGate(t *testing.T) {
	dir := t.TempDir()
	passPath := filepath.Join(dir, "pass.json")
	writeValidatorResult(t, passPath, map[string]any{
		"status": "pass",
		"host":   map[string]any{"release": "5.15.0-152-generic", "machine": "x86_64"},
		"load":   map[string]any{"status": "pass"},
	})
	failPath := filepath.Join(dir, "fail.json")
	writeValidatorResult(t, failPath, map[string]any{
		"status": "fail",
		"host":   map[string]any{"release": "5.15.0-152-generic", "machine": "x86_64"},
		"load":   map[string]any{"status": "fail", "error": "verifier rejected program"},
	})
	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		now := time.Now().UTC()
		switch {
		case strings.HasPrefix(req.Profile.ID, "infra"):
			return vm.ExecutionResult{ProfileID: req.Profile.ID, Status: "infra_error", InfraError: "qemu died", StartedAt: now, FinishedAt: now}
		case strings.HasPrefix(req.Profile.ID, "fail"):
			return vm.ExecutionResult{ProfileID: req.Profile.ID, Status: "fail", ValidatorResultPath: failPath, StartedAt: now, FinishedAt: now}
		default:
			return vm.ExecutionResult{ProfileID: req.Profile.ID, Status: "pass", ValidatorResultPath: passPath, StartedAt: now, FinishedAt: now}
		}
	})

	required, optional := true, false
	cases := []struct {
		name     string
		profiles []matrix.MatrixProfile
		wantGate string
	}{
		{"all optional pass", []matrix.MatrixProfile{{ID: "pass-a", Required: &optional}}, schema.GateNone},
		{"all optional fail", []matrix.MatrixProfile{{ID: "fail-a", Required: &optional}}, schema.GateNone},
		{"all optional infra_error", []matrix.MatrixProfile{{ID: "infra-a", Required: &optional}}, schema.GateNone},
		{"required pass + optional failure", []matrix.MatrixProfile{
			{ID: "pass-a", Required: &required}, {ID: "fail-b", Required: &optional},
		}, schema.GateEnforced},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			targets, notes := executeTargets(context.Background(), baseCfg(), matrix.Matrix{Profiles: tc.profiles}, t.TempDir(),
				"/tmp/a.bpf.o", "", "", validatorTuning{}, "/tmp/validator", "best-effort", nil)
			if got := schema.RunGate(targets); got != tc.wantGate {
				t.Fatalf("RunGate = %q, want %q", got, tc.wantGate)
			}
			// The established verdict is unchanged in every case.
			if got := schema.RunVerdict(targets); got != schema.VerdictCompatible {
				t.Fatalf("RunVerdict = %q, want %q (unchanged)", got, schema.VerdictCompatible)
			}
			joined := strings.Join(notes, "\n")
			if tc.wantGate == schema.GateNone {
				if strings.Contains(joined, "All required profiles passed") {
					t.Fatalf("a run with no required target must not claim required profiles passed; notes: %q", joined)
				}
				if !strings.Contains(joined, schema.NoGateNote) {
					t.Fatalf("missing the diagnostic-run note; notes: %q", joined)
				}
			} else {
				if strings.Contains(joined, schema.NoGateNote) {
					t.Fatalf("a gated run must not carry the diagnostic-run note; notes: %q", joined)
				}
				if !strings.Contains(joined, "All required profiles passed") {
					t.Fatalf("gated passing run lost its established note; notes: %q", joined)
				}
			}
		})
	}
}
