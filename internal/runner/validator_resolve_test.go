package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveValidatorBinaryEnvOverride(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bpfcompat-validator")
	if err := os.WriteFile(bin, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatalf("write temp validator: %v", err)
	}
	t.Setenv("BPFCOMPAT_VALIDATOR_BIN", bin)

	got, err := resolveValidatorBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, _ := filepath.Abs(bin)
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveValidatorBinaryNotFound(t *testing.T) {
	// Point the env override at a missing file so the resolver falls through to
	// the installed and repo-relative candidates.
	t.Setenv("BPFCOMPAT_VALIDATOR_BIN", filepath.Join(t.TempDir(), "absent"))

	for _, p := range []string{
		"/usr/local/libexec/bpfcompat/bpfcompat-validator",
		"/usr/libexec/bpfcompat/bpfcompat-validator",
		"validator/c-libbpf/bin/bpfcompat-validator",
	} {
		if _, err := os.Stat(p); err == nil {
			t.Skipf("a real validator exists at %s; skipping not-found case", p)
		}
	}

	if _, err := resolveValidatorBinary(); err == nil {
		t.Fatal("expected error when no validator is discoverable")
	}
}
