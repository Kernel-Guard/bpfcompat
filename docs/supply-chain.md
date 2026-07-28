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

The tagged-release workflow is the sole production promotion path. It builds
candidate binaries once, tests those bytes in a pinned vendor VM, builds and
verifies the candidate image, stages a draft release, promotes the verified
image digest, and only then publishes the release. Promotion pauses at the
`production-release` environment. The workflow refuses tag processing if that
environment does not require the release reviewer, prevent self-review,
disable admin bypass, and restrict deployments to `v*` tags.

Prereleases publish only their exact `X.Y.Z-rc.N` image tag. Stable aliases
(`X.Y`, `latest`) are reachable only through the stable release channel.

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

- [ ] **Production branch protection on `main`**: block force-pushes and
      deletions, require conversation resolution and an up-to-date branch,
      enforce checks for admins, dismiss stale reviews, and require one
      non-author approval plus the documented production checks. Set via:
      `gh api -X PUT repos/Kernel-Guard/bpfcompat/branches/main/protection --input -`
- [ ] **Protected `production-release` environment**: after the selected
      reviewer accepts the duty in writing, require that reviewer, prevent
      self-review, disable admin bypass, and allow only `v*` tag deployments.
      Tag releases fail closed until this configuration exists.
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
