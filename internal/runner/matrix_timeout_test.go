package runner

import (
	"context"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/vm"
)

// captureTimeout runs one target from matrixYAML under cfg and returns the
// timeout the executor received plus the remaining time on its context.
func captureTimeout(t *testing.T, cfg Config, matrixYAML string) (time.Duration, time.Duration) {
	t.Helper()
	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
	var got, remaining time.Duration
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		got = req.Timeout
		if dl, ok := ctx.Deadline(); ok {
			remaining = time.Until(dl)
		}
		return vm.ExecutionResult{ProfileID: req.Profile.ID, Status: "infra_error", InfraError: "stub"}
	})
	m, err := matrix.LoadBytes([]byte(matrixYAML))
	if err != nil {
		t.Fatal(err)
	}
	executeTargets(context.Background(), cfg, m, t.TempDir(),
		"/tmp/a.bpf.o", "", "", validatorTuning{}, "/tmp/validator", "best-effort", nil)
	return got, remaining
}

const sweepMatrix = "profiles:\n  - id: ubuntu-22.04-5.15\n    timeout: 20m\n"

// CLI without an explicit --timeout: the matrix profile timeout applies to
// both the request and the target context deadline.
func TestMatrixProfileTimeoutAppliesWhenOptedIn(t *testing.T) {
	cfg := Config{Concurrency: 1, Timeout: 180 * time.Second, MatrixProfileTimeouts: true}
	got, remaining := captureTimeout(t, cfg, sweepMatrix)
	if got != 20*time.Minute {
		t.Fatalf("request timeout = %v, want 20m", got)
	}
	if remaining <= 180*time.Second || remaining > 20*time.Minute {
		t.Fatalf("context deadline remaining = %v, want ~20m", remaining)
	}
}

// Explicit --timeout (and every non-CLI caller: action, API server, suite,
// library) leaves MatrixProfileTimeouts false: cfg.Timeout wins, exactly as
// before the fix.
func TestExplicitTimeoutWinsOverMatrixProfileTimeout(t *testing.T) {
	cfg := Config{Concurrency: 1, Timeout: 12 * time.Minute}
	got, remaining := captureTimeout(t, cfg, sweepMatrix)
	if got != 12*time.Minute {
		t.Fatalf("request timeout = %v, want 12m (explicit)", got)
	}
	if remaining > 12*time.Minute {
		t.Fatalf("context deadline remaining = %v, want <= 12m", remaining)
	}
}

func TestMatrixProfileWithoutTimeoutFallsBackToConfig(t *testing.T) {
	cfg := Config{Concurrency: 1, Timeout: 180 * time.Second, MatrixProfileTimeouts: true}
	got, _ := captureTimeout(t, cfg, "profiles:\n  - id: ubuntu-22.04-5.15\n")
	if got != 180*time.Second {
		t.Fatalf("request timeout = %v, want 180s", got)
	}
}
