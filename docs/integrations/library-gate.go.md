# Template: embed the pre-load gate in a Go runtime or daemon

For programs that load eBPF **at runtime on a machine you do not control** — a
daemon, agent, or manager — rather than in CI. Instead of finding out from a
bare `EINVAL` in production, ask before loading and fail with a reason.

No VM is involved: this validates against the kernel the process is running on.

## The interface

Define it yourself so your project takes **no dependency** on bpfcompat:

```go
// PreLoadValidator answers whether an object can load on the running kernel.
type PreLoadValidator interface {
	ValidateBeforeLoad(ctx context.Context, objectPath string) error
}
```

Keep the field optional and nil-by-default, so the check is opt-in and the
zero value behaves exactly as before:

```go
type Manager struct {
	// ...
	preLoadValidator PreLoadValidator // optional; nil disables the check
}

func (m *Manager) WithPreLoadValidator(v PreLoadValidator) *Manager {
	m.preLoadValidator = v
	return m
}
```

Call it once the object path is resolved and **before** taking any lock or
touching the kernel, so a refusal costs nothing and leaves nothing behind:

```go
if m.preLoadValidator != nil {
	if err := m.preLoadValidator.ValidateBeforeLoad(ctx, objectPath); err != nil {
		return nil, fmt.Errorf("pre-load validation: %w", err)
	}
}
```

## The implementation

```go
import "github.com/kernel-guard/bpfcompat/pkg/bpfcompat"

type gate struct{ opts []bpfcompat.Option }

func (g *gate) ValidateBeforeLoad(ctx context.Context, objectPath string) error {
	res, err := bpfcompat.ValidateBeforeLoad(ctx, objectPath, g.opts...)
	if err != nil {
		// Infrastructure failure, not a verdict: the object was never judged.
		return fmt.Errorf("pre-load check could not run: %w", err)
	}
	if res.OK() {
		return nil
	}
	return fmt.Errorf("%s on kernel %s (%s, errno %d)",
		res.Classification.Reason, res.Kernel.Release,
		res.Classification.Code, res.Load.Errno)
}
```

Build with `-tags hostload`. Without the tag the package compiles to a stub
that reports the feature is unavailable — deliberately, so a missing build tag
can never look like "everything passed".

## Why the error is the point

Today a kernel-incompatible object comes back as a bare `EINVAL` with the real
reason buried in the verifier log. The gate returns the classification code,
the verifier's own reason, and the errno — before the load is attempted, so
there is no half-loaded state to unwind.

A worked example against a real project's tree (bpfman) lives in
[`examples/bpfman-gate`](../../examples/bpfman-gate).
