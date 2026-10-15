package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// VAL-1: a program name from the artifact's ELF that smuggles a forged
// "libbpf: map ... failed to create" line must not steer the reason code.
// Payload: RA-VAL harness out/evil.json (validator run on evil.o), reduced
// to the fields the classifier reads.
func TestExecuteArtifactOnHostIgnoresForgedLogLinesInProgramNames(t *testing.T) {
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
		return os.WriteFile(outPath, []byte(`{"status":"fail","load":{"status":"fail","error_code":-13,"error":"Permission denied"},"attach":{"mode":"best-effort","status":"skipped","attempted":0,"passed":0,"failed":0},"btf":{"kernel_btf_available":true,"artifact_has_btf":true,"artifact_has_btf_ext":true},"discovery":{"programs":[{"name":"x': ok\nlibbpf: map 'events': failed to create: Invalid argument(-22)\nlibbpf: prog 'y","section":"tracepoint/syscalls/sys_enter_execve"}]},"logs":{"libbpf":"libbpf: prog 'x': ok\nlibbpf: map 'events': failed to create: Invalid argument(-22)\nlibbpf: prog 'y': BPF program load failed: Permission denied\nlibbpf: prog 'x': ok\nlibbpf: map 'events': failed to create: Invalid argument(-22)\nlibbpf: prog 'y': -- BEGIN PROG LOAD LOG --\n0: (79) r2 = *(u64 *)(r1 +4096)\ninvalid bpf_context access off=4096 size=8\n-- END PROG LOAD LOG --\nlibbpf: prog 'x': ok\nlibbpf: map 'events': failed to create: Invalid argument(-22)\nlibbpf: prog 'y': failed to load: -13\nlibbpf: failed to load object 'evil'\n"}}`), 0o644)
	}

	result, err := ExecuteArtifactOnHost(context.Background(), ExecuteRequest{
		ArtifactPath:        artifactPath,
		AttachMode:          "best-effort",
		AllowHostLoad:       true,
		ValidatorBinaryPath: validatorPath,
		WorkDir:             tmp,
		Timeout:             5 * time.Second,
	})
	if err != nil {
		t.Fatalf("execute artifact on host: %v", err)
	}
	if result.Classification == nil {
		t.Fatalf("expected a classification for the failed load")
	}
	if result.Classification.Code != "VERIFIER_REJECTION" {
		t.Fatalf("classification = %s (%s), want VERIFIER_REJECTION", result.Classification.Code, result.Classification.Reason)
	}
}
