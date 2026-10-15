# Supply-Chain & Trust Posture

This document records the supply-chain controls that ship as code in this
repository and the maintainer-side settings that must be configured in the
GitHub repository UI/API (they cannot be set from committed files).

## In-repo controls (automated)

| Control | Where | Trigger |
|---|---|---|
| CodeQL static analysis (Go, security-and-quality) | `.github/workflows/codeql.yml` | push/PR to `main`, weekly, manual |
| OpenSSF Scorecard | `.github/workflows/scorecard.yml` | push to `main`, weekly, `branch_protection_rule`, manual |
| Dependency updates (gomod + github-actions) | `.github/dependabot.yml` | weekly (Mondays) |
| Vulnerability scan | `govulncheck` in `.github/workflows/ci.yml` | every PR |
| Lint | `golangci-lint` in `.github/workflows/ci.yml` | every PR |
| SBOM (CycloneDX) | `.github/workflows/release-artifacts.yml` | push to `main`, tags, manual |
| Keyless signing (cosign / Sigstore OIDC) | `.github/workflows/release-artifacts.yml` | tag releases (`v*`) |
| SHA256 checksums | `.github/workflows/release-artifacts.yml` | all builds |
| Candidate VM positive/negative gate | `.github/workflows/release-artifacts.yml` | tag releases (`v*`) |
| Binary and container provenance | `.github/workflows/release-artifacts.yml` | tag releases (`v*`) |
| Attested candidate promotion record | `.github/workflows/release-artifacts.yml` | tag releases (`v*`) |
| Release-channel alias isolation | `scripts/promote-release.sh` | tag releases (`v*`) |
| Protected-environment preflight | `scripts/check-production-environment.sh` | tag releases (`v*`) |
| Exact-input manual publication | `.github/workflows/promote-release.yml` | explicit `workflow_dispatch` |
| Pinned validator build inputs (digest-pinned builder, exact libbpf/libelf/zlib/zstd/glibc/GCC) | `validator/build-inputs.lock`, `scripts/build-validator-pinned.sh` | all release-artifacts builds |
| Stable validator == qualified release-candidate validator | `scripts/check-validator-matches-candidate.sh` | stable tags (`vX.Y.Z`) |
| Protected moving-alias rollback drill | `.github/workflows/rollback-drill.yml` | explicit `workflow_dispatch` from `main` |

The tagged-release workflow builds candidate binaries once, tests those bytes
in a pinned vendor VM, builds and verifies the candidate image, and stages a
private draft. It has no publication job. A separate `workflow_dispatch`-only
workflow is dispatched on the exact `v*` tag and accepts the candidate run ID,
full commit, image digest, and confirmation phrase. It re-verifies the
candidate and draft before calling the sole promotion script.

Promotion pauses for 15 minutes at the `production-release` environment. The
workflows refuse release processing unless that environment has no required
reviewers, disables administrator bypass, and restricts deployments to `v*`
tags. This is an explicit solo-maintainer posture, not independent review.

The static validator links distro libbpf, libelf, zlib, zstd and glibc, so
its bytes depend on those packages, not only on `validator/` sources. It is
built in the digest-pinned builder image named in `validator/build-inputs.lock`
with exactly the packages listed there; the build fails closed if any version
is unavailable, proves the linked libbpf version and compiler from the binary,
and must be byte-identical to the lock's recorded reproduction when the
validator tree is unchanged. A stable tag additionally refuses any validator
whose sha256 differs from its release candidate's, because the qualification
campaigns ran exactly those bytes. Changing the lock means a new release
candidate.

Prereleases publish only their exact `X.Y.Z-rc.N` image tag. Stable aliases
(`X.Y`, `latest`) are reachable only through the stable release channel.

### Validator lock maintenance (known limitation)

`validator/build-inputs.lock` pins exact package versions, several of them from
the `noble-updates` pocket (e.g. `libc6-dev`, `zlib1g-dev`, `libelf-dev`,
`gcc-13`). Ubuntu's archive keeps only the newest version in `-updates`, so
the next stable-release update (SRU) of any of them removes the pinned version
and `scripts/build-validator-pinned.sh` then fails closed at `apt-get install`.
That is intended: bump the lock (new versions, new `reproduces=` line from a
pinned build), which changes the shipped validator and therefore needs a new
release candidate. Pinning the apt step to a fixed snapshot.ubuntu.com
timestamp would keep old versions installable. It is a follow-up: one local
experiment (snapshot `20261014T154800Z`, `ca-certificates` installed first)
reproduced the qualified validator byte-for-byte in about 8 minutes, but an
earlier identical attempt stalled for over 13 minutes, so it is not wired into
the release build until it is shown to be reliable.

`dist/validator-build-inputs.json` is a build record: it is attested with the
candidate provenance and kept in the workflow run artifact, but it is not a
release asset and is not listed in `SHA256SUMS`.

### Verifying a signed release

```bash
cosign verify-blob \
  --certificate SHA256SUMS.crt --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS
```

## Maintainer-side settings (configure once, in the GitHub UI/API)

These are not files in the repo. Track their status here.

- [x] **Production branch protection on `main`**: block force-pushes and
      deletions, require conversation resolution and an up-to-date branch,
      enforce checks for admins, dismiss stale reviews, require zero human
      approvals, and require the documented production checks. Set via:
      `gh api -X PUT repos/Kernel-Guard/bpfcompat/branches/main/protection --input -`
- [x] **Immutable release tags**: active repository ruleset prevents updates
      or deletion of `v*` tags, with no bypass actor.
- [x] **Protected `production-release` environment**: require no human
      reviewers, apply a 15-minute wait, disable admin bypass, and allow only
      `v*` tag deployments. Candidate and promotion workflows fail closed
      until this configuration exists.
- [x] **Secret scanning + push protection** (wired 2026-06-14): enabled via
      `gh api -X PATCH repos/Kernel-Guard/bpfcompat` with
      `security_and_analysis.secret_scanning` + `secret_scanning_push_protection`.
- [x] **Dependabot alerts + security updates** (wired 2026-06-14): enabled via
      `gh api -X PUT .../vulnerability-alerts` and `.../automated-security-fixes`.
- [ ] **Code scanning default setup OFF if CodeQL workflow is used** (avoid
      double analysis): Settings → Code security → Code scanning. Do this after
      `codeql.yml` lands on `main`.
- [x] **OpenSSF Best Practices badge** (passing, 2026-06-15): project
      [13230](https://www.bestpractices.dev/projects/13230) at the *passing*
      tier; badge is in the README row. Keep the self-assessment current as the
      project evolves, and pursue the *silver*/*gold* tiers when ready.
- [ ] **Scorecard badge publishing**: the first successful `scorecard.yml` run
      on `main` populates <https://scorecard.dev/viewer/?uri=github.com/Kernel-Guard/bpfcompat>
      and resolves the README badge.

## Notes

- `publish_results: true` in the Scorecard workflow requires the repository to
  be public; it is a no-op signal otherwise.
- CodeQL uses `build-mode: autobuild` (Go does not support `none`); autobuild
  runs `go build`, which does not need the C/libbpf validator toolchain (the
  validator is a separate non-Go component).
- The `Kernel-Guard` GitHub org and the "KernelGuard" site branding should be
  reconciled before a wider public launch; see the project roadmap.
