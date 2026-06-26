# pkg/bpfcompat

Embeddable Go API for validating compiled eBPF objects against real Linux
kernels.

There are two entry points, sharing one result type:

| Function | What it does | Boots a VM? | Network? |
|---|---|---|---|
| `ValidateBeforeLoad` / `ValidateBytes` | Real load of an object against the **local running kernel** | No | No |
| `Validate` | Full **matrix** run across N kernel profiles in disposable VMs | Yes | Only for OCI artifacts |

`ValidateBeforeLoad` is the pre-load gate: the node it runs on is the node the
program will load on, so the running kernel *is* the target. It does a real
`bpf()` load (the verifier), not static ELF/BTF inference — strictly more
accurate, and fast enough to sit in front of every load.

## Quick start (pre-load gate)

```go
import "github.com/kernel-guard/bpfcompat/pkg/bpfcompat"

res, err := bpfcompat.ValidateBeforeLoad(ctx, "probe.bpf.o")
if err != nil {
    return err
}
if !res.OK() {
    return fmt.Errorf("won't load on %s: [%s] %s",
        res.Kernel.Release, res.Classification.Code, res.Classification.Reason)
}
// safe to load
```

`ValidateBytes(ctx, obj []byte, ...)` is the same for an object already in
memory (e.g. one you pulled from an OCI store yourself). Nothing in this path
touches the network — suitable for air-gapped environments.

## Build requirements for host-load

Host-kernel loading is gated behind the **`hostload` build tag**. Binaries that
must never load BPF on their own kernel (e.g. a public-facing server) are built
*without* the tag, and `ValidateBeforeLoad` / `ValidateBytes` then return
`ErrHostLoadNotEnabled`.

To enable it:

```sh
make pkg-embed-validator      # builds the static validator, stages it for embed
go build -tags hostload ./...  # or: make lib-hostload
```

Runtime requirements:

- **Privilege** — loading BPF needs `CAP_BPF`/`CAP_SYS_ADMIN`. The library does
  not escalate; the caller must already hold it (bpfman does).
- **No external assets** — the static validator is embedded via `go:embed` and
  extracted to a private temp dir per call. `amd64` and `arm64` are supported;
  other arches return a clear error unless a validator is supplied via
  `WithValidator`.

## Matrix mode

`Validate(ctx, Config)` drives the same engine as the `bpfcompat` CLI and GitHub
Action — one or more kernel profiles, each booted in a disposable VM. It does
**not** load on the host (use `ValidateBeforeLoad` for that). Returns a `Report`
with one `Result` per profile plus the raw on-disk report.

## Options

- `WithMode(LoadOnly | LoadAttach)` — `LoadOnly` (default) runs the verifier
  only; `LoadAttach` also attaches to hooks (more invasive).
- `WithFeatureProbe(bool)` — off by default; enables the full kernel-capability
  census (slower).
- `WithValidator(path)` — pin a validator binary instead of the embedded one.

## Stability

**Pre-1.0 / experimental.** While the module is `v0.x`, the surface of this
package may change between minor versions. Once it stabilises it will follow
[semantic versioning](https://semver.org/): no breaking changes to exported
identifiers within a major version. Pin a tag if you depend on it.

The internal seam (`validatorProvider`) lets the embed-and-exec implementation
be replaced by an in-process CGO validator later **without** changing this
public API or the `Result` shape — that change would not be breaking.

## Result

`Result` carries `Loadable` (the gate), `Kernel` (release/arch/BTF), `Load`
(status/errno/verifier-log tail), `Attach`, `Capabilities`, a machine-readable
`Classification` (branch on `Code`, don't parse `Reason`), and `RawJSON` for the
full underlying document. `Result.OK()` == `Loadable`.
