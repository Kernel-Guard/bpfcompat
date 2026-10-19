# BPFCompat Compatibility Contract

This document defines what a bpfcompat result means, and — just as importantly —
what it does not mean. It is the reference for anyone gating a release on a
bpfcompat report.

A compatibility run answers one question:

> Did **this exact artifact**, loaded by **this exact loader**, work on **this
> exact environment**?

Four contracts make that answerable. Each is carried in the JSON report
(`schema_version: v0.1`, source of truth
[`pkg/schema/report_v0_1.go`](../pkg/schema/report_v0_1.go)). The Markdown report
is rendered from the same data and is presentation only — never parse it.

---

## Artifact contract — *what was tested?*

| Input | Evidence |
|---|---|
| Local `.bpf.o` | `artifact.sha256`, `artifact.basename`, `artifact.size_bytes` |
| OCI reference | `artifact.source` (the reference as supplied), `artifact.source_digest` (the immutable image digest it resolved to), plus the `sha256` of the eBPF object extracted from it |
| Command mode with no artifact | `artifact` describes a synthetic command identity; the loader is the subject instead |

`artifact.sha256` is always the identity of the bytes that were actually loaded
in the guest.

A mutable tag is never the final identity. `ghcr.io/org/gadget:latest` points at
different bytes next week, so `artifact.source` alone cannot support a claim
about a past run; `artifact.source_digest` can. Both are recorded because the
first says what the user asked for and the second says what they got.

**Answers:** *was this exact shipped artifact tested?*

---

## Loader contract — *how was it exercised?*

bpfcompat has two loader modes, and the distinction is the product.

### Generic validator (artifact mode)

A static libbpf validator loads the object and optionally attaches it.
Provenance: `validator.basename`, `validator.sha256`, `validator.size_bytes` —
the same staged bytes are reused for every target in the run.

From v0.4.0-rc.5, when the GitHub Action is pinned to a release (a tag, or a
commit that maps to one) and the prebuilt assets verify, the run uses that
attested validator, selected by path and pinned digest: a validator installed
elsewhere on the runner is not used, and other bytes fail closed. A workflow
that sets `BPFCOMPAT_VALIDATOR_BIN` or `BPFCOMPAT_VALIDATOR_SHA256` itself
keeps its own settings, with a warning, and every fallback to a source build
while pinned to a release is a `::warning::` annotation. Neither of those runs
is pinned to the qualified release validator (on a source-build fallback a
validator installed under `/usr/local/libexec` or `/usr/libexec` is still
searched first); compare `validator.sha256` with the release `SHA256SUMS` when
it matters. With v0.3.7 and v0.4.0-rc.4 that search order applies to every run,
so a validator installed in those directories is used before the verified one.

### The project's own loader (command mode)

The mode that matters for real adoption. Falco's maintainers made the point
directly: a generic validator is not their compatibility contract, because
`scap-open` drives libbpf differently than a validator does. Command mode ships
the project's real loader into each guest and takes **its exit code** as the
per-kernel verdict.

Provenance:

| Field | Meaning |
|---|---|
| `command.binary.{basename,sha256,size_bytes}` | the loader binary that was shipped into the guest |
| `command.invocation_sha256` | digest of the invocation, stable across runs |
| `command.expected_exit_code` | what counts as success |
| `targets[].functional.tests[0].command` | the invocation as run |
| `targets[].functional.tests[0].exit_code` | what the loader actually returned |
| `targets[].functional.tests[0].{stdout_tail,stderr_tail}` | bounded diagnostic output |

A command-mode target is tied to a kernel by the guest kernel release recorded
before the command starts. From v0.4.0-rc.5, if that release cannot be read (or
is empty), the command is not started and the target is `INFRA_ERROR`, never
`COMPATIBLE` or `INCOMPATIBLE`; a required target then fails the run closed.
Earlier releases record the release on a best-effort basis and run the command
even when it cannot be read.

Only the invocation bpfcompat was given is recorded. Guest environment contents
are not captured, and output is truncated to tails. Do not put secrets in the
command string — it is written to the report verbatim so the verdict is
defensible.

**Answers:** *did the exact loader we ship succeed on the exact artifact, here?*

---

## Environment contract — *where was it tested?*

Each target separates what was **requested** from what was **observed**.

| Field | Meaning |
|---|---|
| `targets[].profile` | the environment the matrix asked for (distro, version, kernel family, arch) |
| `targets[].host` | the guest as reported from inside it (`kernel`, `arch` are observed) |
| `targets[].environment.requested_kernel_family` | the profile's declared kernel series |
| `targets[].environment.observed_kernel` | the release the guest actually booted |
| `targets[].environment.kernel_family_match` | whether those agree on `MAJOR.MINOR` |
| `targets[].environment.image_source_url` / `image_sha256` | which disk image was booted (the SHA-256 is verified before boot) |
| `targets[].environment.requested_distro` / `requested_distro_version` | the profile's distribution and release |
| `targets[].environment.observed_os_id` / `observed_os_version_id` | the guest's `/etc/os-release` `ID` and `VERSION_ID` |
| `targets[].environment.distro_match` | whether the guest is that distribution (and, where both are numeric, that major release); unset when either side has no known identity |

`kernel_family_match: false` means the target ran, produced a real result, and
that result **does not support a claim about the requested kernel series**. This
is not hypothetical: reports in this repository show a target labelled
`rhel-8-4.18` marked `pass` whose guest booted `5.15.0-…el8uek`. The artifact
result is genuine; the 4.18 claim is not. A run containing such a target is
marked `summary.complete: false`.

Only the major release is compared, so `distro_match` catches another
distribution or major release, not a different point release (Ubuntu 20.04
against 20.10, RHCOS 4.14 against 4.18).

`distro_match: false` has the same meaning for the distribution: the kernel
series can be right while the userspace is not (an AlmaLinux or Oracle Linux
image dropped into the bring-your-own `rhel-8-4.18` slot). An unset
`distro_match` is unknown, not a mismatch: reports written before this field
existed, and distributions without a known `os-release` ID, carry none.

Consumers that need strict environment fidelity should gate on
`targets[].environment.kernel_family_match` and
`targets[].environment.distro_match`.

**Answers:** *was the environment we intended to validate the one that ran?*

---

## Verdict contract

`targets[].verdict` and `summary.verdict` carry the taxonomy. Its single job is
to keep a statement about **your software** separate from a statement about
**bpfcompat**.

| Verdict | Meaning | Statement about |
|---|---|---|
| `COMPATIBLE` | the contract executed and was satisfied | your software |
| `INCOMPATIBLE` | the environment executed far enough to establish that your artifact or loader does not satisfy the contract | your software |
| `INFRA_ERROR` | bpfcompat could not establish compatibility — image download, boot, guest transport, timeout, internal error | bpfcompat |
| `UNSUPPORTED` | bpfcompat intentionally cannot execute this environment (no supported transport for the profile) | bpfcompat |

`INFRA_ERROR` and `UNSUPPORTED` prove **nothing either way** about your
software. A target that never loaded your program is not evidence that your
program is broken.

### Run-level roll-up

**Only `required` targets gate the run.** `required: false` is documented as "a
failure here does not fail the gate", and that holds for every outcome — a
compatibility failure, a VM that never booted, an environment we cannot execute.
If an optional target could set the exit code it would be required in everything
but name. What an optional target lost is still reported, through
`summary.complete` and its own entry, rather than by blocking the release.

Over the required targets:

1. Any `INCOMPATIBLE` → run is `INCOMPATIBLE`.
2. Otherwise, any `INFRA_ERROR`, any `UNSUPPORTED`, or any target that did not
   establish the environment it was asked about
   (`environment.kernel_family_match: false`), or on another distribution
   (`environment.distro_match: false`) → run is `INFRA_ERROR`.
3. Otherwise → `COMPATIBLE`.

Rule 1 deliberately outranks rule 2. A proven incompatibility is a definitive
fact, and downgrading it because an unrelated VM failed would hide a real
regression behind a flaky runner.

Rule 2 covers the case that matters most for a support claim. A required profile
whose guest booted a different kernel series produces a genuine result *about
the kernel that ran* — that evidence is kept — but the requested contract was
never exercised, so the run must not exit `0` claiming it held. And because it
was **our** environment that failed to be what we asked for, this is
`INFRA_ERROR` and never `INCOMPATIBLE`.

`summary.complete` is `false` when **any** target — required or optional —
produced no answer about the environment it was asked about (`INFRA_ERROR`,
`UNSUPPORTED`, or an environment mismatch). Coverage describes what was tested;
it is not a gating decision. **`COMPATIBLE` with `complete: false` means
"nothing we managed to test was incompatible" — not "the matrix passed".**

### Unrecognised states

A target status bpfcompat does not recognise maps to `INFRA_ERROR`, never to
`INCOMPATIBLE`. An unknown state means the tool does not understand what
happened, which is not evidence that the user's program failed to load. It still
fails closed, so it cannot pass silently either.

### Relationship to `status`

`targets[].status` and `summary.status` predate this taxonomy and keep their
existing values (`pass` / `fail` / `infra_error` / `unsupported`, and
`pass` / `fail` / `error` at run level). They are unchanged for existing
consumers. New integrations should gate on `verdict`.

---

## Evidence contract

| Question | Field |
|---|---|
| Which schema is this? | `schema_version` |
| What was tested? | `artifact.sha256`, `artifact.source`, `artifact.source_digest` |
| How was it loaded? | `validator.*` or `command.*` + `targets[].functional.tests[]` |
| Where did it run? | `targets[].host`, `targets[].environment` |
| What is the answer? | `targets[].verdict`, `summary.verdict`, `summary.complete` |
| Why did it fail? | `targets[].classification_code`, `classification_reason`, `failed_stage`, `infra_error` |
| Can I reproduce it? | `run.id`, `matrix.*`, `environment.image_sha256`, timestamps |

Versioning follows
[schema-stability-contract.md](schema-stability-contract.md): additive changes
keep the major, breaking changes bump it, unknown fields and unknown enum values
must be tolerated. Everything in this document is additive within `v0.1`.

Field-by-field reference: [evidence-schema.md](evidence-schema.md).

---

## CI semantics

| Exit code | Verdict | What a CI consumer should conclude |
|---:|---|---|
| `0` | `COMPATIBLE` | Every required target was exercised as requested and none was incompatible. Optional targets may still have failed — check `summary.complete`. |
| `2` | `INCOMPATIBLE` | A required target proved your artifact or loader does not work there. **Do not merge / do not ship.** |
| `1` | `INFRA_ERROR` | bpfcompat could not establish the requested contract on a required target — it failed to run, or the guest was not the environment that was asked for. This says nothing about your software; retry, or investigate the runner or the profile. |

A consumer that reads only the process exit status is safe: every case where the
requested contract was not established on a required target is non-zero. No new
JSON field has to be adopted to avoid a false green.

Exit codes are unchanged from earlier releases. What changed is the precedence:
a run with both a proven required incompatibility and an unrelated
infrastructure failure now exits `2` rather than `1`, because the incompatibility
is the more specific and more actionable fact. Both were already non-zero, so a
CI job that simply gates on success is unaffected.

A consumer that wants to distinguish "block the merge" from "our CI is flaky"
should branch on the exit code, or read `summary.verdict`.

---

## Scope and limits

What a `COMPATIBLE` verdict does **not** claim:

- It is not a guarantee of production correctness. It reports that the artifact
  loaded — and, depending on validation mode, attached or passed the behaviour
  commands you supplied — in a disposable VM on that kernel.
- It covers exactly the kernels in the matrix. Nothing is inferred about
  untested kernels, and `summary.complete: false` marks the ones that were
  skipped.
- It reflects the loader that was exercised. A `COMPATIBLE` result from the
  generic validator does not guarantee your own loader succeeds; that is what
  command mode is for.
- Attach and behaviour coverage depend on `validation_mode`; `load_only` proves
  loading, not attaching.

Known limitations of the supported path:

- **Artifact paths.** A missing path that starts with `/`, `./`, `../` or `~`,
  or that ends in `.bpf.o`, is never pulled from a registry. A missing
  relative path without such a prefix may still be read as a registry
  reference, whatever its suffix, when it contains `@sha256:` or when it has a
  `/` and its first component looks like a registry host (contains `.` or `:`,
  or is `localhost`); it is pulled only if it also parses as a valid image
  reference. For example `out.v2/prog.o`, `build.d/x.elf` and
  `localhost/prog.o` are pulled. Spell local files with `./` or an absolute
  path. Docker Hub images need an explicit `docker.io/` host for tag
  references; a short digest reference (`name@sha256:…`) is still pulled from
  Docker Hub. These rules apply from v0.4.0-rc.5; earlier releases treat any
  missing path that parses as an image reference as one and try to pull it
  (for example `build/prog.bpf.o` from Docker Hub).
- **Action `artifact` input.** The Action decides "remote" before looking at
  the workspace. An input that contains `://` or `@sha256:`, that is
  `localhost` or starts with `localhost:` or `localhost/`, or whose first
  component contains `.` or `:` and is followed by `/`, is passed to the CLI
  unchanged even when a file of that name exists in the workspace. The CLI
  runs from the Action's own checkout, so such a path is not looked up in the
  workspace. Dot-directories are caught by this rule too: `.output/minimal.bpf.o`
  (the libbpf-bootstrap layout) fails with "no such file" (from v0.4.0-rc.5;
  earlier releases read it as an image on registry host `.output`), and
  `.output/minimal.o` is read as an image on registry host `.output`. Prefix
  workspace files with `./` (for example `./.output/minimal.bpf.o` or
  `./out.v2/prog.o`).
- **Untrusted names in reports.** Program, map and section names, and libbpf or
  verifier log text, come from the artifact. The Markdown report and the Action
  job summary do not escape all of them, so treat rendered names as untrusted
  text.
- **Classification codes.** `classification_code` and its confidence are
  derived from log text that artifact-controlled names can influence. Verdicts,
  exit codes and gates do not depend on them; do not base a security or
  authorization decision on the code alone.
- **Action binary.** An executable at the `binary` input path in the calling
  workspace (default `./bin/bpfcompat`) is used in preference to the verified
  prebuilt CLI.
- **Shared hosts.** Guests are reached over SSH on a loopback port without
  host-key pinning. Run VM jobs on single-tenant runners.
