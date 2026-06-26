//go:build !hostload

package bpfcompat

import "context"

// ValidateBeforeLoad is disabled in builds without the "hostload" tag and
// returns ErrHostLoadNotEnabled. See the package doc for the rationale.
func ValidateBeforeLoad(ctx context.Context, artifactPath string, opts ...Option) (Result, error) {
	return Result{}, ErrHostLoadNotEnabled
}

// ValidateBytes is disabled in builds without the "hostload" tag and returns
// ErrHostLoadNotEnabled.
func ValidateBytes(ctx context.Context, obj []byte, opts ...Option) (Result, error) {
	return Result{}, ErrHostLoadNotEnabled
}
