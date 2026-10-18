package runner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/vm"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// A command-mode execution that never observed the guest kernel release has
// not established which kernel the command ran against. Whatever the command
// exit code, the target is an infrastructure error, never COMPATIBLE or
// INCOMPATIBLE. (pkg/schema deliberately reads an unset kernel as "unknown",
// so the runner is where a fresh run must refuse to produce a verdict.)
func TestCommandModeWithoutObservedKernelIsInfraError(t *testing.T) {
	for _, tc := range []struct {
		name     string
		exitCode int
		release  string
	}{
		{"exit 0, no release", 0, ""},
		{"exit 1, no release", 1, ""},
		{"exit 0, whitespace release", 0, "  \n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
			stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
				now := time.Now().UTC()
				return vm.ExecutionResult{
					ProfileID: req.Profile.ID, Status: "pass", CommandMode: true,
					CommandExitCode: tc.exitCode, HostRelease: tc.release,
					StartedAt: now, FinishedAt: now,
				}
			})
			cfg := baseCfg()
			cfg.Command = "true"
			targets := runOneTarget(t, cfg, "ubuntu-22.04-5.15", true)
			target := targets[0]
			if target.Status != "infra_error" || target.FailedStage != "infra" {
				t.Fatalf("status=%q failed_stage=%q verdict=%s; want infra_error/infra", target.Status, target.FailedStage, target.Verdict)
			}
			if !strings.Contains(target.InfraError, "guest kernel release") {
				t.Fatalf("infra_error=%q; want it to name the missing guest kernel release", target.InfraError)
			}
			if v := schema.RunVerdict(targets); v != schema.VerdictInfraError {
				t.Fatalf("run verdict=%s; want %s", v, schema.VerdictInfraError)
			}
			if target.Verdict != schema.VerdictInfraError {
				t.Fatalf("target verdict=%s; want %s", target.Verdict, schema.VerdictInfraError)
			}
		})
	}
}

// Control: a command run that recorded its kernel keeps its verdict.
func TestCommandModeWithObservedKernelKeepsVerdict(t *testing.T) {
	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		now := time.Now().UTC()
		return vm.ExecutionResult{
			ProfileID: req.Profile.ID, Status: "pass", CommandMode: true,
			CommandExitCode: 0, HostRelease: "5.15.0-152-generic", HostMachine: "x86_64",
			StartedAt: now, FinishedAt: now,
		}
	})
	cfg := baseCfg()
	cfg.Command = "true"
	targets := runOneTarget(t, cfg, "ubuntu-22.04-5.15", true)
	if targets[0].Status != "pass" || targets[0].Verdict != schema.VerdictCompatible {
		t.Fatalf("status=%q verdict=%s; want pass/%s", targets[0].Status, targets[0].Verdict, schema.VerdictCompatible)
	}
}
