package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/vm"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// A required command-mode target whose guest kernel release was never
// observed must fail the whole run closed: the run is INFRA_ERROR and the
// process exit code is non-zero, whatever the command's own exit code. This
// pins the end of the chain (target -> run verdict -> exit code) that
// TestCommandModeWithoutObservedKernelIsInfraError starts.
func TestRequiredCommandTargetWithoutKernelFailsRunClosed(t *testing.T) {
	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
	stubExecutor(t, func(_ context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		now := time.Now().UTC()
		return vm.ExecutionResult{
			ProfileID: req.Profile.ID, Status: "pass", CommandMode: true,
			CommandExitCode: 0, HostRelease: "",
			StartedAt: now, FinishedAt: now,
		}
	})
	dir := t.TempDir()
	matrixPath := filepath.Join(dir, "matrix.yaml")
	if err := os.WriteFile(matrixPath, []byte("name: required-command\nprofiles:\n  - id: ubuntu-22.04-5.15\n    required: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ExecuteBootstrap(context.Background(), Config{
		Command:    "true",
		MatrixPath: matrixPath,
		Runner:     RunnerVM,
		WorkDir:    filepath.Join(dir, "work"),
		OutPath:    filepath.Join(dir, "report.json"),
		Timeout:    time.Minute,
	})
	if err != nil {
		t.Fatalf("ExecuteBootstrap: %v", err)
	}
	if res.ExitCode == ExitSuccess {
		t.Fatalf("exit code = %d (success); a required target without an observed kernel must fail the run", res.ExitCode)
	}
	if res.ExitCode != ExitToolError {
		t.Fatalf("exit code = %d, want %d (tool/infrastructure error)", res.ExitCode, ExitToolError)
	}
	if v := schema.RunVerdict(res.Report.Targets); v != schema.VerdictInfraError {
		t.Fatalf("run verdict = %s, want %s", v, schema.VerdictInfraError)
	}
}
