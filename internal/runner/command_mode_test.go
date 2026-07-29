package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/vm"
)

func commandModeProfile(string) (vm.Profile, error) {
	return vm.Profile{
		ID:           "ubuntu-test",
		Distro:       "ubuntu",
		Version:      "22.04",
		KernelFamily: "5.15",
		Arch:         "x86_64",
	}, nil
}

func stubCommandExecutor(t *testing.T, exitCode int) func(context.Context, vm.ExecutionRequest) vm.ExecutionResult {
	t.Helper()
	return func(_ context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		if req.Command == "" {
			t.Fatalf("expected command on execution request")
		}
		if req.ValidatorBinary != "" {
			t.Fatalf("command mode must not run the validator (got binary %q)", req.ValidatorBinary)
		}
		now := time.Now().UTC()
		return vm.ExecutionResult{
			ProfileID:         req.Profile.ID,
			Status:            "pass",
			CommandMode:       true,
			CommandExitCode:   exitCode,
			CommandStdoutTail: "loaded 3 programs",
			HostRelease:       "5.15.0-test",
			HostMachine:       "x86_64",
			StartedAt:         now.Add(-time.Second),
			FinishedAt:        now,
		}
	}
}

func TestExecuteTargetCommandModePass(t *testing.T) {
	origLoad, origExec := loadProfileFn, executeProfileFn
	t.Cleanup(func() { loadProfileFn, executeProfileFn = origLoad, origExec })
	loadProfileFn = commandModeProfile
	executeProfileFn = stubCommandExecutor(t, 0)

	target, infraErr, requiredFail := executeTarget(
		context.Background(),
		Config{Timeout: 2 * time.Second, Command: "$BPFCOMPAT_BIN --self-test"},
		matrix.MatrixProfile{ID: "ubuntu-test", Required: boolPtr(true)},
		t.TempDir(),
		"", // no staged artifact in command mode
		"",
		"",
		validatorTuning{},
		"", // no validator binary
		"best-effort",
	)

	if infraErr || requiredFail {
		t.Fatalf("expected clean pass, got infraErr=%v requiredFail=%v target=%+v", infraErr, requiredFail, target)
	}
	if target.Status != "pass" {
		t.Fatalf("expected pass status, got %q", target.Status)
	}
	if target.Validation == nil || target.Validation.LoadStatus != "skipped" {
		t.Fatalf("expected load skipped in command mode, got %+v", target.Validation)
	}
	if target.Functional == nil || target.Functional.Status != "pass" || len(target.Functional.Tests) != 1 {
		t.Fatalf("expected single passing functional test, got %+v", target.Functional)
	}
	if target.Host == nil || target.Host.Kernel != "5.15.0-test" {
		t.Fatalf("expected host kernel recorded, got %+v", target.Host)
	}
	if target.ValidatorExit != 0 {
		t.Fatalf("expected validator_exit 0, got %d", target.ValidatorExit)
	}
}

func TestExecuteTargetCommandModeFailRequired(t *testing.T) {
	origLoad, origExec := loadProfileFn, executeProfileFn
	t.Cleanup(func() { loadProfileFn, executeProfileFn = origLoad, origExec })
	loadProfileFn = commandModeProfile
	executeProfileFn = stubCommandExecutor(t, 1)

	target, infraErr, requiredFail := executeTarget(
		context.Background(),
		Config{Timeout: 2 * time.Second, Command: "$BPFCOMPAT_BIN --self-test"},
		matrix.MatrixProfile{ID: "ubuntu-test", Required: boolPtr(true)},
		t.TempDir(),
		"", "", "",
		validatorTuning{},
		"",
		"best-effort",
	)

	if infraErr {
		t.Fatalf("did not expect infra error, got %+v", target)
	}
	if !requiredFail {
		t.Fatalf("expected required compatibility failure")
	}
	if target.Status != "fail" || target.FailedStage != "command" {
		t.Fatalf("unexpected status/stage: %q/%q", target.Status, target.FailedStage)
	}
	if target.ClassificationCode != "COMMAND_VALIDATION_FAILURE" {
		t.Fatalf("expected COMMAND_VALIDATION_FAILURE, got %q", target.ClassificationCode)
	}
}

// A non-zero exit is a pass when --command-expect-exit matches it.
func TestExecuteTargetCommandModeExpectedNonZero(t *testing.T) {
	origLoad, origExec := loadProfileFn, executeProfileFn
	t.Cleanup(func() { loadProfileFn, executeProfileFn = origLoad, origExec })
	loadProfileFn = commandModeProfile
	executeProfileFn = stubCommandExecutor(t, 42)

	target, infraErr, requiredFail := executeTarget(
		context.Background(),
		Config{Timeout: 2 * time.Second, Command: "expect-42", CommandExpectExit: 42},
		matrix.MatrixProfile{ID: "ubuntu-test", Required: boolPtr(true)},
		t.TempDir(),
		"", "", "",
		validatorTuning{},
		"",
		"best-effort",
	)

	if infraErr || requiredFail {
		t.Fatalf("expected pass with expected-exit 42, got infraErr=%v requiredFail=%v", infraErr, requiredFail)
	}
	if target.Status != "pass" {
		t.Fatalf("expected pass, got %q", target.Status)
	}
}

func TestExecuteTargetCommandModeInfraError(t *testing.T) {
	origLoad, origExec := loadProfileFn, executeProfileFn
	t.Cleanup(func() { loadProfileFn, executeProfileFn = origLoad, origExec })
	loadProfileFn = commandModeProfile
	executeProfileFn = func(_ context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		now := time.Now().UTC()
		return vm.ExecutionResult{
			ProfileID:   req.Profile.ID,
			Status:      "infra_error",
			InfraError:  "boot failed",
			CommandMode: true,
			StartedAt:   now,
			FinishedAt:  now,
		}
	}

	target, infraErr, requiredFail := executeTarget(
		context.Background(),
		Config{Timeout: 2 * time.Second, Command: "x"},
		matrix.MatrixProfile{ID: "ubuntu-test", Required: boolPtr(true)},
		t.TempDir(),
		"", "", "",
		validatorTuning{},
		"",
		"best-effort",
	)

	if !infraErr {
		t.Fatalf("expected infra error")
	}
	if requiredFail {
		t.Fatalf("infra error must not count as compatibility failure")
	}
	if target.Status != "infra_error" || target.InfraError != "boot failed" {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestCommandArtifactMetadataStableAndDistinct(t *testing.T) {
	a := commandArtifactMetadata(Config{Command: "loader --run"}, nil)
	b := commandArtifactMetadata(Config{Command: "loader --run"}, nil)
	c := commandArtifactMetadata(Config{Command: "loader --other"}, nil)
	if a.SHA256 == "" || a.SHA256 != b.SHA256 {
		t.Fatalf("expected stable sha for identical command: %q vs %q", a.SHA256, b.SHA256)
	}
	if a.SHA256 == c.SHA256 {
		t.Fatalf("expected distinct sha for different command")
	}
	if a.BaseName != "command" {
		t.Fatalf("expected default basename 'command', got %q", a.BaseName)
	}
}

func TestCommandArtifactMetadataIncludesBinaryContents(t *testing.T) {
	binaryPath := filepath.Join(t.TempDir(), "myloader")
	if err := os.WriteFile(binaryPath, []byte("loader-v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Command: "x", CommandBinary: binaryPath}
	infoV1, err := inspectCommandMetadata(cfg)
	if err != nil {
		t.Fatal(err)
	}
	withBin := commandArtifactMetadata(cfg, infoV1)
	if withBin.BaseName != "myloader" {
		t.Fatalf("expected basename from command binary, got %q", withBin.BaseName)
	}
	if infoV1.Binary == nil || infoV1.Binary.SHA256 == "" || infoV1.Binary.SizeBytes != int64(len("loader-v1")) {
		t.Fatalf("expected binary provenance, got %+v", infoV1.Binary)
	}
	if infoV1.InvocationSHA256 == "" {
		t.Fatal("expected invocation digest")
	}

	if err := os.WriteFile(binaryPath, []byte("loader-v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	infoV2, err := inspectCommandMetadata(cfg)
	if err != nil {
		t.Fatal(err)
	}
	changed := commandArtifactMetadata(cfg, infoV2)
	if withBin.SHA256 == changed.SHA256 {
		t.Fatal("expected synthesized artifact identity to change with loader bytes")
	}
	if infoV1.Binary.SHA256 == infoV2.Binary.SHA256 {
		t.Fatal("expected loader digest to change with loader bytes")
	}
}

func TestCommandInvocationMetadataIncludesExpectedExitCode(t *testing.T) {
	pass, err := inspectCommandMetadata(Config{Command: "loader --self-test", CommandExpectExit: 0})
	if err != nil {
		t.Fatal(err)
	}
	expectedFailure, err := inspectCommandMetadata(Config{Command: "loader --self-test", CommandExpectExit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if pass.InvocationSHA256 == expectedFailure.InvocationSHA256 {
		t.Fatal("expected invocation digest to change with expected exit code")
	}
}

func TestInspectCommandMetadataRejectsMissingBinary(t *testing.T) {
	_, err := inspectCommandMetadata(Config{
		Command:       "$BPFCOMPAT_BIN --self-test",
		CommandBinary: filepath.Join(t.TempDir(), "missing"),
	})
	if err == nil {
		t.Fatal("expected missing command binary to fail before VM execution")
	}
}
