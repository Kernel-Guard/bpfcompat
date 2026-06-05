package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecuteArtifactOnHostRequiresAllowGate(t *testing.T) {
	_, err := ExecuteArtifactOnHost(context.Background(), ExecuteRequest{
		ArtifactPath: "/tmp/does-not-matter.bpf.o",
	})
	if err == nil {
		t.Fatalf("expected allow_host_load error")
	}
	if !strings.Contains(err.Error(), "allow_host_load") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteArtifactOnHostPass(t *testing.T) {
	tmp := t.TempDir()
	artifactPath := filepath.Join(tmp, "artifact.bpf.o")
	if err := os.WriteFile(artifactPath, []byte("dummy"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	validatorPath := filepath.Join(tmp, "validator")
	if err := os.WriteFile(validatorPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write validator: %v", err)
	}

	originalRun := runHostCommandFn
	t.Cleanup(func() { runHostCommandFn = originalRun })
	runHostCommandFn = func(cmd *exec.Cmd) error {
		outPath := argValue(cmd.Args, "--out")
		if outPath == "" {
			t.Fatalf("missing --out in args: %v", cmd.Args)
		}
		passJSON := `{"status":"pass","load":{"status":"pass","error_code":0,"error":""},"attach":{"mode":"best-effort","status":"pass","attempted":1,"passed":1,"failed":0},"btf":{"kernel_btf_available":true,"artifact_has_btf":true,"artifact_has_btf_ext":true},"logs":{"libbpf":""}}`
		if err := os.WriteFile(outPath, []byte(passJSON), 0o644); err != nil {
			t.Fatalf("write validator result: %v", err)
		}
		return nil
	}

	result, err := ExecuteArtifactOnHost(context.Background(), ExecuteRequest{
		ArtifactPath:        artifactPath,
		AttachMode:          "best-effort",
		ProbeFeatures:       true,
		AllowHostLoad:       true,
		UseSudo:             false,
		ValidatorBinaryPath: validatorPath,
		WorkDir:             tmp,
		Timeout:             5 * time.Second,
	})
	if err != nil {
		t.Fatalf("execute artifact on host: %v", err)
	}
	if result.Status != "pass" {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", result.ExitCode)
	}
	if result.Validator.LoadStatus != "pass" {
		t.Fatalf("expected load pass, got %s", result.Validator.LoadStatus)
	}
}

func TestExecuteArtifactOnHostFailClassification(t *testing.T) {
	tmp := t.TempDir()
	artifactPath := filepath.Join(tmp, "artifact.bpf.o")
	if err := os.WriteFile(artifactPath, []byte("dummy"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	validatorPath := filepath.Join(tmp, "validator")
	if err := os.WriteFile(validatorPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write validator: %v", err)
	}

	originalRun := runHostCommandFn
	t.Cleanup(func() { runHostCommandFn = originalRun })
	runHostCommandFn = func(cmd *exec.Cmd) error {
		outPath := argValue(cmd.Args, "--out")
		if outPath == "" {
			t.Fatalf("missing --out in args: %v", cmd.Args)
		}
		failJSON := `{"status":"fail","load":{"status":"fail","error_code":-22,"error":"BTF missing"},"attach":{"mode":"required","status":"fail","attempted":1,"passed":0,"failed":1},"btf":{"kernel_btf_available":false,"artifact_has_btf":true,"artifact_has_btf_ext":true},"logs":{"libbpf":"BTF is required"}}`
		if err := os.WriteFile(outPath, []byte(failJSON), 0o644); err != nil {
			t.Fatalf("write validator result: %v", err)
		}
		return nil
	}

	result, err := ExecuteArtifactOnHost(context.Background(), ExecuteRequest{
		ArtifactPath:        artifactPath,
		AttachMode:          "required",
		ProbeFeatures:       true,
		AllowHostLoad:       true,
		UseSudo:             false,
		ValidatorBinaryPath: validatorPath,
		WorkDir:             tmp,
		Timeout:             5 * time.Second,
	})
	if err != nil {
		t.Fatalf("execute artifact on host: %v", err)
	}
	if result.Status != "fail" {
		t.Fatalf("expected fail status, got %s", result.Status)
	}
	if result.Classification == nil {
		t.Fatalf("expected classification for failure result")
	}
	if strings.TrimSpace(result.Classification.Code) == "" {
		t.Fatalf("classification code should not be empty")
	}
}

func argValue(args []string, key string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == key {
			return args[i+1]
		}
	}
	return ""
}
