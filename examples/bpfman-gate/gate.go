// Package bpfmangate adapts bpfcompat to bpfman's optional pre-load
// validation hook.
//
// bpfman defines the interface; this supplies the implementation, so bpfman
// itself never imports bpfcompat:
//
//	type PreLoadValidator interface {
//	    ValidateBeforeLoad(ctx context.Context, objectPath string) error
//	}
//
// Wire it up at construction:
//
//	mgr, err := manager.New(rt, puller, store, kern, progValidator, logger)
//	if err != nil {
//	    return err
//	}
//	mgr = mgr.WithPreLoadValidator(bpfmangate.New())
//
// Build with -tags hostload so bpfcompat validates against the running
// kernel; without the tag it compiles to a stub that reports the feature is
// unavailable rather than silently passing.
package bpfmangate

import (
	"context"
	"fmt"

	"github.com/kernel-guard/bpfcompat/pkg/bpfcompat"
)

// Gate refuses objects the running kernel's verifier will not accept.
type Gate struct {
	opts []bpfcompat.Option
}

// New returns a Gate. Options are passed through to bpfcompat, so a caller
// can select load-only versus load-and-attach checking, point at an external
// validator binary, and so on.
func New(opts ...bpfcompat.Option) *Gate {
	return &Gate{opts: opts}
}

// ValidateBeforeLoad implements bpfman's PreLoadValidator.
//
// The error is the product here: bpfman surfaces it to the caller verbatim,
// so it carries the classification and the verifier's own reason instead of
// the bare EINVAL the loader would otherwise produce.
func (g *Gate) ValidateBeforeLoad(ctx context.Context, objectPath string) error {
	res, err := bpfcompat.ValidateBeforeLoad(ctx, objectPath, g.opts...)
	if err != nil {
		// Infrastructure failure, not a verdict: the object was never
		// judged, so say so rather than implying it was rejected.
		return fmt.Errorf("pre-load check could not run: %w", err)
	}
	if res.OK() {
		return nil
	}

	reason := res.Classification.Reason
	if reason == "" {
		reason = res.Load.LogTail
	}
	if reason == "" {
		reason = "object rejected by the verifier"
	}
	return fmt.Errorf("%s on kernel %s (%s, errno %d)",
		reason, res.Kernel.Release, res.Classification.Code, res.Load.Errno)
}
