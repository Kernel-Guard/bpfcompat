# CLAUDE.md

Instructions for Claude Code and other coding agents working in this repository.
[CONTRIBUTING.md](CONTRIBUTING.md) still applies in full. For agent-run sessions,
[docs/engineering/orchestration.md](docs/engineering/orchestration.md) is
binding, as are the subagent definitions in `.claude/agents/`. This file adds
the rules that keep evidence honest; it does not replace them.

## What bpfcompat is

bpfcompat answers one question with evidence: does this eBPF artifact, or the
project's own loader, work on these kernels? It boots each requested kernel in
a disposable QEMU/KVM guest, runs a C/libbpf validator or the project's loader
there, and emits a versioned JSON report with a per-target verdict
(`COMPATIBLE`, `INCOMPATIBLE`, `INFRA_ERROR`, …).

What a verdict claims, and what it does not, is defined in
[docs/compatibility-contract.md](docs/compatibility-contract.md). Read it before
changing anything that produces or consumes a verdict. Field meanings are in
[docs/evidence-schema.md](docs/evidence-schema.md), and versioning rules in
[docs/schema-stability-contract.md](docs/schema-stability-contract.md).

## Layout

- `cmd/bpfcompat/`: the CLI (`test`, `suite`, `diff`, `compare`, …). `main.go` is
  the only place allowed to call `os.Exit`.
- `internal/runner/`: orchestrates one run. It resolves profiles and the
  validator, executes targets, and turns validator results into verdicts.
- `internal/vm/`: QEMU/KVM execution (plus the Firecracker and virtme-ng
  backends), the image cache, cloud-init seeding and SSH transport.
- `internal/classifier/`: maps raw signals (errno, verifier and libbpf text) to
  classification codes.
- `internal/report`, `compare`, `regressiondiff`, `suite`, `matrix`,
  `manifest`, `freshness`, `artifact`: reports, diffs, suites, matrices,
  manifests and artifact intake.
- `pkg/bpfcompat/`: the embeddable library. With `-tags hostload` it loads on the
  host kernel without a VM. `pkg/schema/` holds the report types.
- `validator/c-libbpf/`: the in-guest validator (`src/main.c`). Its behaviour is
  described in [docs/validator.md](docs/validator.md).
- `vm/profiles/`: kernel/OS profiles. `vm/cache/` holds local images and is not
  committed. `matrices/` and `suites/` hold run definitions.
- Frozen experimental surfaces: `internal/{api,runtime,agent,cloudregistry}` and
  the paths matched by `scripts/check-experimental-freeze.sh`. Changes there
  need the `experimental-change-approved` label; see
  [docs/production-support-boundary.md](docs/production-support-boundary.md).

## Commands

```bash
make build                    # bin/bpfcompat
make validator-static         # in-guest validator; needs clang + libbpf-dev. Use static for guests.
go vet ./...
go test -race -count=1 ./...  # what CI runs
golangci-lint run --new-from-rev=origin/main ./...   # new code must be clean
make env-docs-check check-docs-drift check-release-consistency
bash scripts/check-experimental-freeze.sh origin/main
make doctor                   # host prerequisites for VM runs
make acceptance-dev-one       # a real local VM run on one kernel (needs /dev/kvm)
```

CI also runs many `scripts/*_test.sh` checks; see `.github/workflows/ci.yml`.
Run the ones covering files you touch. Behaviour changes need tests and a
`CHANGELOG.md` `[Unreleased]` line. Commit-message style is in CONTRIBUTING.md.

## Evidence classes: never upgrade one into another

| Class | What it shows | What it does not show |
|---|---|---|
| Synthetic (unit tests, fixtures, stand-in binaries) | The logic handles the inputs it was given | That any kernel behaves that way |
| Real validator, no VM (hostload, local build) | That validator's behaviour on the host kernel | Other kernels; the guest environment |
| Real VM, local (QEMU/KVM on a workstation) | That kernel and image, with no GitHub provenance | A hosted or release-qualifying run |
| Hosted CI (a GitHub workflow run) | That run, at that commit, with its run ID | Any other commit, attempt or workflow |

- Label every result with its class, and with the exact kernel (`uname -r`) and
  image for VM evidence. Local evidence never fills a slot that policy reserves
  for a hosted run, and citing an unrelated workflow ID does not make it one.
- Load-only evidence never proves attach or runtime correctness. A program that
  loaded but was not attached, or was attached without its behaviour exercised,
  is reported as exactly that. A required attach must never be reported as
  satisfied by a partial pass.
- Running diagnostics is not satisfying a gate. A run with no required target
  can exit 0 without having gated anything; do not describe it as a passing
  compatibility gate.
- Keep unknown, unavailable, inconsistent and inconclusive evidence as it is.
  Never default a missing field to a pass, relabel an `INFRA_ERROR`, or
  manufacture a result. Missing evidence is written as missing.

## Verdict logic has one implementation

The CLI (`internal/runner`) and the library (`pkg/bpfcompat`) must reach the
same verdict from the same validator evidence. Shared evaluation code belongs in
`internal/runner`. `pkg/bpfcompat` may import it, but `internal/runner` must
never import `pkg/bpfcompat`. Do not copy a switch statement into the other
frontend. When you add a new outcome (for example a new errno mapped to
`INFRA_ERROR`), add a parity fixture that runs both paths.

## Working in parallel

- Before starting, run `gh pr list` and read the open PRs that touch the same
  files. Extend or stack on overlapping work rather than duplicating it, and
  record which PR owns which files.
- Use one git worktree or clone per workstream and one branch per agent. Never
  let two agents edit the same worktree or push the same branch. Keep the
  concurrency bounded: at most one local VM job per workstream, and never the
  same kernel suite twice.
- Integrate before claiming a combined result: merge the branches locally, run
  the full checks on the merge, and review cross-PR interactions. Unit tests on
  each branch alone have missed real divergence before.
- Review and approve exact commit SHAs. CI that ran on another commit is not
  evidence for the current head. Any push, rebase or base change voids earlier
  approvals and results.
- Stacked PRs (whose base is not `main`) do not run every workflow; CodeQL, for
  example, runs only against `main`. List the checks that actually ran on the
  head; do not assume full coverage.
- Cache isolation: never symlink writable cache metadata (`vm/cache/*.sha256`,
  locks, run directories) from another checkout. Copy it, or use a private cache
  directory. Image bytes may be shared only read-only.

## Honesty and release policy

- Never fabricate approvals, customers, adopters, endorsements, quotes or test
  results. Never write an operator approval or confirmation marker on someone's
  behalf.
- Release, tagging, promotion and qualification follow
  [docs/production-release-process.md](docs/production-release-process.md) and
  the authorization levels in orchestration.md. Do what the current request
  authorizes; a task-specific restriction is not repository policy, and a
  repository-policy step is not waived by a task request. An approval covers its
  recorded action and commit only.
- Temporary release state (freezes, qualification windows, current heads)
  belongs in a dated document with an explicit scope and expiry, not in this
  file.
- Do not commit secrets, tokens, private correspondence, machine-specific
  absolute paths, or references to volatile scratch directories.
- Security issues go through [SECURITY.md](SECURITY.md), never public issues.
