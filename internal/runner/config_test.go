package runner

import (
	"strings"
	"testing"
	"time"
)

func validConfigForTest() Config {
	return Config{
		ArtifactPath: "/tmp/artifact.bpf.o",
		MatrixPath:   "/tmp/matrix.yaml",
		OutPath:      "/tmp/report.json",
		WorkDir:      ".bpfcompat",
		Concurrency:  1,
		Timeout:      30 * time.Second,
	}
}

func TestConfigValidateAllowsDefaultVMRunner(t *testing.T) {
	cfg := validConfigForTest()
	cfg.Runner = ""

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected default runner validation to pass, got %v", err)
	}
}

func TestConfigValidateRejectsHostRunnerByDefault(t *testing.T) {
	cfg := validConfigForTest()
	cfg.Runner = RunnerHost

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected host runner to be rejected without override")
	}
	if !strings.Contains(err.Error(), "--unsafe-allow-host-runner") {
		t.Fatalf("expected hidden override hint in error, got %v", err)
	}
}

func TestConfigValidateAllowsHostRunnerWithUnsafeOverride(t *testing.T) {
	cfg := validConfigForTest()
	cfg.Runner = RunnerHost
	cfg.UnsafeAllowHostRunner = true

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected host runner validation to pass with override, got %v", err)
	}
}

func TestConfigValidateAllowsVirtmeNGRunner(t *testing.T) {
	cfg := validConfigForTest()
	cfg.Runner = RunnerVirtmeNG

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected virtme-ng runner validation to pass, got %v", err)
	}
}

func TestConfigValidateAllowsFirecrackerRunner(t *testing.T) {
	cfg := validConfigForTest()
	cfg.Runner = RunnerFirecracker

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected firecracker runner validation to pass, got %v", err)
	}
}

func TestConfigValidateRejectsUnknownRunner(t *testing.T) {
	cfg := validConfigForTest()
	cfg.Runner = "docker"

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected unknown runner to fail validation")
	}
	if !strings.Contains(err.Error(), "--runner must be one of") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigValidateRequiresArtifactOrCommand(t *testing.T) {
	cfg := validConfigForTest()
	cfg.ArtifactPath = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "--command") {
		t.Fatalf("expected error hinting at --command, got %v", err)
	}
}

func TestConfigValidateAllowsCommandWithoutArtifact(t *testing.T) {
	cfg := validConfigForTest()
	cfg.ArtifactPath = ""
	cfg.Command = "$BPFCOMPAT_BIN --self-test"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected command mode without artifact to pass, got %v", err)
	}
}

func TestConfigValidateCommandRejectsNonVMRunner(t *testing.T) {
	cfg := validConfigForTest()
	cfg.ArtifactPath = ""
	cfg.Command = "loader"
	cfg.Runner = RunnerVirtmeNG

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "--runner") {
		t.Fatalf("expected command mode to reject non-vm runner, got %v", err)
	}
}

func TestConfigValidateCommandExpectExitRange(t *testing.T) {
	cfg := validConfigForTest()
	cfg.ArtifactPath = ""
	cfg.Command = "loader"
	cfg.CommandExpectExit = 300

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "command-expect-exit") {
		t.Fatalf("expected out-of-range exit code rejection, got %v", err)
	}
}

func TestConfigValidateCommandBinaryRequiresCommand(t *testing.T) {
	cfg := validConfigForTest()
	cfg.CommandBinary = "/tmp/loader"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "--command-binary requires --command") {
		t.Fatalf("expected --command-binary to require --command, got %v", err)
	}
}
