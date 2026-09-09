package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/vm"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// The compatibility contract has exactly one property that a commercial
// consumer cannot verify for themselves: that "INCOMPATIBLE" is a statement
// about their software and nothing else. Every test here defends that boundary
// from one side or the other.
//
// The failure this prevents is not theoretical. Before this taxonomy existed, a
// profile with no supported execution transport -- an environment bpfcompat
// declines to run -- was reported as `status: fail` on a required target and
// rolled up as a compatibility failure, which reads as "your eBPF program does
// not work here". It was never loaded at all.

func stubProfile(t *testing.T, p vm.Profile) {
	t.Helper()
	orig := loadProfileFn
	t.Cleanup(func() { loadProfileFn = orig })
	loadProfileFn = func(path string) (vm.Profile, error) {
		out := p
		if out.ID == "" {
			out.ID = filepath.Base(path)
		}
		return out, nil
	}
}

func stubExecutor(t *testing.T, fn func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult) {
	t.Helper()
	orig := executeProfileFn
	t.Cleanup(func() { executeProfileFn = orig })
	executeProfileFn = fn
}

func runOneTarget(t *testing.T, cfg Config, profileID string, required bool) []schema.Target {
	t.Helper()
	m := matrix.Matrix{Profiles: []matrix.MatrixProfile{{ID: profileID, Required: &required}}}
	targets, _ := executeTargets(
		context.Background(), cfg, m, t.TempDir(),
		"/tmp/a.bpf.o", "", "", validatorTuning{}, "/tmp/validator", "best-effort", nil,
	)
	return targets
}

func baseCfg() Config {
	return Config{Concurrency: 1, Timeout: 2 * time.Second}
}

// --- infrastructure must never present as the user's incompatibility --------

func TestInfrastructureFailuresNeverBecomeIncompatible(t *testing.T) {
	// Each of these is bpfcompat's pipeline breaking, at a different stage.
	// None of them establishes anything about the artifact.
	cases := []struct {
		name   string
		result vm.ExecutionResult
	}{
		{"vm boot fails", vm.ExecutionResult{Status: "infra_error", InfraError: "qemu exited before boot completed"}},
		{"ssh never available", vm.ExecutionResult{Status: "infra_error", InfraError: "ssh not reachable within timeout"}},
		{"guest times out", vm.ExecutionResult{Status: "infra_error", InfraError: "context deadline exceeded"}},
		{"image download fails", vm.ExecutionResult{Status: "infra_error", InfraError: "download image: 404"}},
		{"image checksum mismatch", vm.ExecutionResult{Status: "infra_error", InfraError: "image sha256 mismatch"}},
		{"command upload fails", vm.ExecutionResult{Status: "infra_error", InfraError: "upload command binary: connection reset"}},
		// A guest that comes up but yields no validator result is equally
		// uninformative: the runner must not read "no answer" as "failed".
		{"no validator result", vm.ExecutionResult{Status: "pass", ValidatorResultPath: ""}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
			stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
				r := tc.result
				r.ProfileID = req.Profile.ID
				r.StartedAt = time.Now().UTC()
				r.FinishedAt = r.StartedAt
				return r
			})

			targets := runOneTarget(t, baseCfg(), "ubuntu-22.04-5.15", true)
			got := targets[0].Verdict
			if got == schema.VerdictIncompatible {
				t.Fatalf("infrastructure failure %q surfaced as INCOMPATIBLE, blaming the user's artifact", tc.name)
			}
			if got != schema.VerdictInfraError {
				t.Fatalf("want %s, got %s", schema.VerdictInfraError, got)
			}
			if schema.RunVerdict(targets) != schema.VerdictInfraError {
				t.Fatalf("run verdict must be %s", schema.VerdictInfraError)
			}
			if schema.RunComplete(targets) {
				t.Fatalf("a target with no compatibility answer must mark the run incomplete")
			}
		})
	}
}

func TestUnsupportedProfileIsNotIncompatible(t *testing.T) {
	// A cloud-image profile routed at the virtme-ng runner has no transport.
	// bpfcompat declines to execute it; that is not a verdict on the artifact.
	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64", Runner: "vm"})
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		t.Fatal("executor must not run for an unsupported transport")
		return vm.ExecutionResult{}
	})

	cfg := baseCfg()
	cfg.Runner = RunnerVirtmeNG
	targets := runOneTarget(t, cfg, "ubuntu-22.04-5.15", true)

	if targets[0].Verdict != schema.VerdictUnsupported {
		t.Fatalf("want %s, got %s", schema.VerdictUnsupported, targets[0].Verdict)
	}
	if targets[0].Verdict == schema.VerdictIncompatible {
		t.Fatal("an environment bpfcompat cannot execute must never read as the user's incompatibility")
	}
	if schema.RunComplete(targets) {
		t.Fatal("an unsupported required profile leaves the matrix incompletely covered")
	}
}

// --- ...and a real incompatibility must survive intact ----------------------

func TestGenuineIncompatibilityIsNotReducedToInfraError(t *testing.T) {
	// The mirror image: a verifier rejection is a fact about the artifact, and
	// must not be laundered into "bpfcompat had a problem".
	dir := t.TempDir()
	resultPath := filepath.Join(dir, "validator.json")
	writeValidatorResult(t, resultPath, map[string]any{
		"status": "fail",
		"host":   map[string]any{"release": "5.15.0-152-generic", "machine": "x86_64"},
		"load":   map[string]any{"status": "fail", "error_code": -22, "error": "BPF program rejected by verifier"},
	})

	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		return vm.ExecutionResult{
			ProfileID: req.Profile.ID, Status: "fail", ValidatorResultPath: resultPath,
			StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
		}
	})

	targets := runOneTarget(t, baseCfg(), "ubuntu-22.04-5.15", true)
	if targets[0].Verdict != schema.VerdictIncompatible {
		t.Fatalf("want %s, got %s", schema.VerdictIncompatible, targets[0].Verdict)
	}
	if schema.RunVerdict(targets) != schema.VerdictIncompatible {
		t.Fatalf("a required incompatibility must roll up as %s", schema.VerdictIncompatible)
	}
}

func TestProvenIncompatibilitySurvivesAnUnrelatedInfraFailure(t *testing.T) {
	// The precedence boundary. One required kernel proves the artifact does not
	// load; a different, optional VM fails to boot. Reporting INFRA_ERROR here
	// would hide a real regression behind a flaky runner.
	dir := t.TempDir()
	resultPath := filepath.Join(dir, "validator.json")
	writeValidatorResult(t, resultPath, map[string]any{
		"status": "fail",
		"host":   map[string]any{"release": "5.15.0-152-generic", "machine": "x86_64"},
		"load":   map[string]any{"status": "fail", "error_code": -22, "error": "BPF program rejected by verifier"},
	})

	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		now := time.Now().UTC()
		// loadProfileFn derives the ID from the profile filename, so match on a
		// prefix rather than an exact equality that silently never fires.
		if strings.HasPrefix(req.Profile.ID, "flaky") {
			return vm.ExecutionResult{ProfileID: req.Profile.ID, Status: "infra_error", InfraError: "qemu died", StartedAt: now, FinishedAt: now}
		}
		return vm.ExecutionResult{ProfileID: req.Profile.ID, Status: "fail", ValidatorResultPath: resultPath, StartedAt: now, FinishedAt: now}
	})

	required, optional := true, false
	m := matrix.Matrix{Profiles: []matrix.MatrixProfile{
		{ID: "ubuntu-22.04-5.15", Required: &required},
		{ID: "flaky", Required: &optional},
	}}
	targets, _ := executeTargets(context.Background(), baseCfg(), m, t.TempDir(),
		"/tmp/a.bpf.o", "", "", validatorTuning{}, "/tmp/validator", "best-effort", nil)

	if got := schema.RunVerdict(targets); got != schema.VerdictIncompatible {
		t.Fatalf("a proven required incompatibility must win over an unrelated infra failure; got %s", got)
	}
	if schema.RunComplete(targets) {
		t.Fatal("the infra failure still leaves coverage incomplete and must be reported as such")
	}
}

// --- environment contract ---------------------------------------------------

func TestEnvironmentMismatchIsRecordedNotSilentlyClaimed(t *testing.T) {
	// Committed evidence in reports/ contains `rhel-8-4.18` marked pass whose
	// guest actually booted 5.15.0 UEK. A passing target on the wrong kernel
	// series must not read as proof of support for the requested one.
	dir := t.TempDir()
	resultPath := filepath.Join(dir, "validator.json")
	writeValidatorResult(t, resultPath, map[string]any{
		"status": "pass",
		"host":   map[string]any{"release": "5.15.0-206.153.7.1.el8uek.x86_64", "machine": "x86_64"},
		"load":   map[string]any{"status": "pass"},
	})

	stubProfile(t, vm.Profile{
		Distro: "rhel", Version: "8", KernelFamily: "4.18", Arch: "x86_64",
		Image: vm.ImageConfig{SourceURL: "https://example.invalid/rhel8.qcow2", SHA256: "abc123"},
	})
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		return vm.ExecutionResult{
			ProfileID: req.Profile.ID, Status: "pass", ValidatorResultPath: resultPath,
			StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
		}
	})

	targets := runOneTarget(t, baseCfg(), "rhel-8-4.18", true)
	env := targets[0].Environment
	if env == nil {
		t.Fatal("a target that booted must record which environment actually ran")
	}
	if env.KernelFamilyMatch == nil || *env.KernelFamilyMatch {
		t.Fatalf("4.18 requested, 5.15 booted: kernel_family_match must be false, got %v", env.KernelFamilyMatch)
	}
	if env.ImageSHA256 != "abc123" || env.ImageSourceURL == "" {
		t.Fatalf("image identity missing from evidence: %+v", env)
	}
	if schema.RunComplete(targets) {
		t.Fatal("a target that ran the wrong kernel series cannot count as covered")
	}
}

func TestMatchingEnvironmentIsMarkedComplete(t *testing.T) {
	dir := t.TempDir()
	resultPath := filepath.Join(dir, "validator.json")
	writeValidatorResult(t, resultPath, map[string]any{
		"status": "pass",
		"host":   map[string]any{"release": "5.15.0-152-generic", "machine": "x86_64"},
		"load":   map[string]any{"status": "pass"},
	})

	stubProfile(t, vm.Profile{
		Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64",
		Image: vm.ImageConfig{SourceURL: "https://example.invalid/jammy.img", SHA256: "deadbeef"},
	})
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		return vm.ExecutionResult{
			ProfileID: req.Profile.ID, Status: "pass", ValidatorResultPath: resultPath,
			StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
		}
	})

	targets := runOneTarget(t, baseCfg(), "ubuntu-22.04-5.15", true)
	if targets[0].Verdict != schema.VerdictCompatible {
		t.Fatalf("want %s, got %s", schema.VerdictCompatible, targets[0].Verdict)
	}
	env := targets[0].Environment
	if env == nil || env.KernelFamilyMatch == nil || !*env.KernelFamilyMatch {
		t.Fatalf("5.15 requested and booted must match: %+v", env)
	}
	if env.ObservedKernel != "5.15.0-152-generic" {
		t.Fatalf("observed kernel not recorded: %+v", env)
	}
	if !schema.RunComplete(targets) {
		t.Fatal("a fully answered matrix must be complete")
	}
}

func writeValidatorResult(t *testing.T, path string, body map[string]any) {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal validator result: %v", err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write validator result: %v", err)
	}
}

// --- loader contract: command mode is the Falco-shaped path -----------------

func TestCommandModeIncompatibilityIsTheUsersLoaderNotOurs(t *testing.T) {
	// falcosecurity/libs drives its own scap-open loader and the per-kernel
	// verdict is that binary's exit code. When their loader says "no", that is
	// an INCOMPATIBLE result about their software -- and the evidence has to
	// carry enough loader provenance to defend the claim.
	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		now := time.Now().UTC()
		return vm.ExecutionResult{
			ProfileID: req.Profile.ID, Status: "pass", CommandMode: true,
			CommandExitCode:   1,
			CommandStderrTail: "libbpf: prog 'sys_enter': failed to attach: Operation not permitted",
			HostRelease:       "5.15.0-152-generic", HostMachine: "x86_64",
			StartedAt: now, FinishedAt: now,
		}
	})

	cfg := baseCfg()
	cfg.Command = "$BPFCOMPAT_BIN --modern_bpf --num_events 10"
	cfg.CommandExpectExit = 0

	targets := runOneTarget(t, cfg, "ubuntu-22.04-5.15", true)
	target := targets[0]

	if target.Verdict != schema.VerdictIncompatible {
		t.Fatalf("a real loader exiting non-zero is the user's incompatibility; want %s got %s",
			schema.VerdictIncompatible, target.Verdict)
	}
	if target.ClassificationCode != "COMMAND_VALIDATION_FAILURE" {
		t.Fatalf("expected COMMAND_VALIDATION_FAILURE, got %q", target.ClassificationCode)
	}
	if target.Functional == nil || len(target.Functional.Tests) != 1 {
		t.Fatal("command mode must record the invocation as functional evidence")
	}
	tc := target.Functional.Tests[0]
	if tc.ExitCode != 1 || tc.ExpectedExitCode != 0 {
		t.Fatalf("observed/expected exit codes not recorded: %+v", tc)
	}
	if tc.StderrTail == "" {
		t.Fatal("diagnostic output must be preserved to make the verdict defensible")
	}
	if target.Environment == nil || target.Environment.ObservedKernel != "5.15.0-152-generic" {
		t.Fatalf("command mode must record the observed environment: %+v", target.Environment)
	}
}

func TestCommandModeInfraFailureIsNotTheUsersLoader(t *testing.T) {
	// The same lane, but the guest never came up. Their loader never ran, so
	// nothing may be concluded about it.
	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		now := time.Now().UTC()
		return vm.ExecutionResult{
			ProfileID: req.Profile.ID, Status: "infra_error",
			InfraError: "ssh not reachable within timeout", CommandMode: true,
			StartedAt: now, FinishedAt: now,
		}
	})

	cfg := baseCfg()
	cfg.Command = "$BPFCOMPAT_BIN --modern_bpf --num_events 10"

	targets := runOneTarget(t, cfg, "ubuntu-22.04-5.15", true)
	if targets[0].Verdict != schema.VerdictInfraError {
		t.Fatalf("want %s, got %s", schema.VerdictInfraError, targets[0].Verdict)
	}
	if targets[0].ClassificationCode == "COMMAND_VALIDATION_FAILURE" {
		t.Fatal("a guest that never booted must not be classified as the loader failing")
	}
}
