package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/artifact"
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

func TestResolveValidatorBinaryChecksum(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bpfcompat-validator")
	if err := os.WriteFile(bin, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatalf("write temp validator: %v", err)
	}
	meta, err := artifact.Inspect(bin)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BPFCOMPAT_VALIDATOR_BIN", bin)
	t.Setenv("BPFCOMPAT_VALIDATOR_SHA256", meta.SHA256)
	if _, err := resolveValidatorBinary(); err != nil {
		t.Fatalf("expected matching validator checksum to pass: %v", err)
	}

	t.Setenv("BPFCOMPAT_VALIDATOR_SHA256", strings.Repeat("0", 64))
	if _, err := resolveValidatorBinary(); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
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
