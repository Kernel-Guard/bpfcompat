//go:build hostload

package bpfcompat

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// embeddedValidator holds the static validator binary for the current GOARCH.
// It is defined by the per-arch embed_<arch>.go files (built by
// `make pkg-embed-validator`). Air-gap-safe: no external assets at runtime.

// ValidateBeforeLoad does a real load of the BPF object at artifactPath against
// the local running kernel. No VM, no network. Requires CAP_BPF/CAP_SYS_ADMIN
// (the caller's privilege — the library does not escalate).
func ValidateBeforeLoad(ctx context.Context, artifactPath string, opts ...Option) (Result, error) {
	c := newConfig(opts...)
	bin, cleanup, err := resolveValidator(c)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()
	return validateWith(ctx, execProvider{bin: bin}, artifactPath, c)
}

// ValidateBytes is ValidateBeforeLoad for an object already in memory (e.g.
// pulled from an OCI store by the caller). Nothing here touches the network.
func ValidateBytes(ctx context.Context, obj []byte, opts ...Option) (Result, error) {
	tmp, err := os.CreateTemp("", "bpfcompat-artifact-*.bpf.o")
	if err != nil {
		return Result{}, fmt.Errorf("stage artifact bytes: %w", err)
	}
	path := tmp.Name()
	defer os.Remove(path)
	if _, err := tmp.Write(obj); err != nil {
		_ = tmp.Close()
		return Result{}, fmt.Errorf("write artifact bytes: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return Result{}, fmt.Errorf("flush artifact bytes: %w", err)
	}
	return ValidateBeforeLoad(ctx, path, opts...)
}

// resolveValidator returns an executable validator path and a cleanup func. It
// honours WithValidator; otherwise it extracts the embedded per-arch binary to
// a private temp file.
func resolveValidator(c config) (string, func(), error) {
	if c.validatorBin != "" {
		return c.validatorBin, func() {}, nil
	}
	if len(embeddedValidator) == 0 {
		return "", func() {}, fmt.Errorf("no embedded validator for GOARCH=%s; run `make pkg-embed-validator` or pass WithValidator", runtime.GOARCH)
	}
	dir, err := os.MkdirTemp("", "bpfcompat-validator-")
	if err != nil {
		return "", func() {}, fmt.Errorf("create validator dir: %w", err)
	}
	path := filepath.Join(dir, "bpfcompat-validator")
	if err := os.WriteFile(path, embeddedValidator, 0o755); err != nil {
		os.RemoveAll(dir)
		return "", func() {}, fmt.Errorf("extract validator: %w", err)
	}
	return path, func() { os.RemoveAll(dir) }, nil
}
