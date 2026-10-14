package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/vm"
)

// TestExecuteBootstrapRunStartedAtPrecedesTargets pins run.started_at to the
// moment the run began. It used to be stamped while assembling the report,
// after every target had finished, so it postdated all target timestamps and
// misdated the run in the report, registry and artifact history.
func TestExecuteBootstrapRunStartedAtPrecedesTargets(t *testing.T) {
	origLoad, origExec := loadProfileFn, executeProfileFn
	t.Cleanup(func() { loadProfileFn, executeProfileFn = origLoad, origExec })
	loadProfileFn = commandModeProfile

	// Run timestamps use RFC3339 (second precision), so the fake target must
	// take more than a second for the ordering to be observable.
	const targetDuration = 1100 * time.Millisecond
	executeProfileFn = func(_ context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		started := time.Now().UTC()
		time.Sleep(targetDuration)
		return vm.ExecutionResult{
			ProfileID:       req.Profile.ID,
			Status:          "pass",
			CommandMode:     true,
			CommandExitCode: 0,
			HostRelease:     "5.15.0-test",
			HostMachine:     "x86_64",
			StartedAt:       started,
			FinishedAt:      time.Now().UTC(),
		}
	}

	dir := t.TempDir()
	matrixPath := filepath.Join(dir, "matrix.yaml")
	if err := os.WriteFile(matrixPath, []byte("name: started-at\nprofiles:\n  - id: ubuntu-test\n    required: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC().Truncate(time.Second)
	result, err := ExecuteBootstrap(context.Background(), Config{
		WorkDir:    filepath.Join(dir, "work"),
		MatrixPath: matrixPath,
		OutPath:    filepath.Join(dir, "report.json"),
		Timeout:    5 * time.Second,
		Command:    "$BPFCOMPAT_BIN --self-test",
	})
	if err != nil {
		t.Fatalf("ExecuteBootstrap: %v", err)
	}
	if len(result.Report.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(result.Report.Targets))
	}

	runStarted, err := time.Parse(time.RFC3339, result.Report.Run.StartedAt)
	if err != nil {
		t.Fatalf("parse run.started_at %q: %v", result.Report.Run.StartedAt, err)
	}
	target := result.Report.Targets[0]
	targetStarted, err := time.Parse(time.RFC3339, target.StartedAt)
	if err != nil {
		t.Fatalf("parse target started_at %q: %v", target.StartedAt, err)
	}
	targetFinished, err := time.Parse(time.RFC3339, target.FinishedAt)
	if err != nil {
		t.Fatalf("parse target finished_at %q: %v", target.FinishedAt, err)
	}

	if runStarted.Before(before) {
		t.Fatalf("run.started_at %s precedes the call (%s)", runStarted, before)
	}
	if runStarted.After(targetStarted) {
		t.Fatalf("run.started_at %s is after target started_at %s: run start is stamped at report assembly, not when the run began", runStarted, targetStarted)
	}
	if got := targetFinished.Sub(runStarted); got < time.Second {
		t.Fatalf("target finished_at - run.started_at = %s, want >= 1s (target ran %s)", got, targetDuration)
	}
}
