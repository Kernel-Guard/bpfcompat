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

- `WithMode(LoadOnly | LoadAttach | LoadAttachRequired)`:
  - `LoadOnly` (default) runs the verifier only.
  - `LoadAttach` also attaches to hooks, best effort (more invasive).
  - `LoadAttachRequired` makes attach part of the contract, exactly like the
    CLI's required attach mode (see below).
- `WithRequiredPrograms(names...)` — under `LoadAttachRequired`, programs that
  must be attached (the library equivalent of a manifest's
  `attach.required`).
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

`Result` carries:

- `Loadable`: the load gate.
- `Kernel`: release, arch, BTF.
- `Load`: status, errno, verifier-log tail.
- `Attach`, `Capabilities`.
- `Classification`: machine-readable. Branch on `Code`; don't parse `Reason`.
- `RawJSON`: the full underlying document.

`Result.OK()` == `Loadable`.

### Attach evidence and verdict (same as the CLI)

The validator document is evaluated by the same code the matrix runner uses
(`internal/runner.EvaluateValidatorResult`). The host-load path and `Validate`
therefore report what the CLI reports for the same evidence:

- `Status` / `Verdict` / `FailedStage`. `Status` is "pass", "fail",
  "unsupported" or "infra_error"; `Verdict` is COMPATIBLE, INCOMPATIBLE,
  UNSUPPORTED or INFRA_ERROR. `Compatible()` is true only for COMPATIBLE.
  On the matrix path, `Status`/`Verdict` are the target's recorded values
  about the kernel that actually ran. A target that booted another kernel
  series than requested can read COMPATIBLE while `Compatible()` is false,
  because `Compatible()` additionally requires the requested environment.
- `Attach.Accounting`:
  - `v1`: counts and per-program records add up.
  - `unavailable`: an older validator.
  - `inconsistent`: the accounting contradicted itself and was discarded.
- `Attach.Coverage`: complete, partial, none, empty, not_evaluated or
  unavailable. It is computed from scope and attempts, never from successes.
- The scope counts, `Attach.EffectiveMode` and `Attach.RecordsTruncated`.
- `Attach.Programs`: per program, the `Outcome`, plus `Errno`, `Detail`,
  `ReasonClass` and `Attribution: errno_only` for a failure. The errno
  family is evidence, not a diagnosed cause.
- `Notes`. On the host-load path these are the CLI's load, attach and
  classification notes for the same evidence: a subset of the CLI's notes,
  without the capability, map-fixup or per-program load notes. Example:
  `attach not fully exercised: 1/2 selected programs attached, 1 not
  exercised (xdp x1)`.

`OK()` stays the load gate only. Use `Compatible()` for the attach contract
(and, on the matrix path, for the requested environment). Under
`LoadAttachRequired`, `OK()` can be true while `Compatible()` is false: the
object loaded, but the attach contract was not established.

Unprivileged library use is classified exactly like the CLI. A
`CAPABILITY_FAILURE` (INCOMPATIBLE) may reflect missing `CAP_BPF` or
`CAP_SYS_ADMIN` on the calling process rather than the kernel. The CLI always
runs as root inside a VM.

| Evidence | Status / Classification |
|---|---|
| every selected program attached | pass (COMPATIBLE) |
| a selected program failed to attach | fail, `ATTACH_FAILED` (low confidence, raw errno); `UNSUPPORTED_ATTACH_TYPE` only when every failure is EOPNOTSUPP |
| a selected program the validator cannot attach (XDP, LSM, tc, …) | unsupported, `ATTACH_NOT_EXERCISED` |
| no program selected | unsupported, `ATTACH_SCOPE_EMPTY` |
| a `WithRequiredPrograms` name not attached | unsupported, `ATTACH_NOT_EXERCISED` |
| validator without accounting | infra_error, `ATTACH_ACCOUNTING_UNAVAILABLE` |
| contradictory accounting | infra_error, `ATTACH_ACCOUNTING_INCONSISTENT` |

`Validate` (matrix) takes required attach from the manifest (`attach.required`)
like the CLI. It returns `ErrRequiredModeNeedsManifest` for
`Mode: LoadAttachRequired` rather than silently running best effort.

These fields are additive. `OK()`, `Loadable` and the existing `Attach` counts
keep their meaning. `Classification` is now also set for loadable objects when
a required-mode attach contract was not established; that can only happen
with the new `LoadAttachRequired` mode.
