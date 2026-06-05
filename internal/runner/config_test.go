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
