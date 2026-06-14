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

### Verifying a signed release

```bash
cosign verify-blob \
  --certificate SHA256SUMS.crt --signature SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github.com/Kernel-Guard/bpfcompat/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS
```

## Maintainer-side settings (configure once, in the GitHub UI/API)

These are not files in the repo. Track their status here.

- [x] **Branch protection on `main`** (wired 2026-06-14): blocks force-pushes
      and deletions, requires conversation resolution, and requires the CI
      checks `Test (-race)`, `golangci-lint`, `govulncheck`, `Build (Go side)`.
      `enforce_admins` is off (solo-maintainer bypass) and no review count is
      required. Add `Analyze (Go)` to the required contexts once `codeql.yml`
      is on `main`. Set via:
      `gh api -X PUT repos/Kernel-Guard/bpfcompat/branches/main/protection --input -`
- [x] **Secret scanning + push protection** (wired 2026-06-14): enabled via
      `gh api -X PATCH repos/Kernel-Guard/bpfcompat` with
      `security_and_analysis.secret_scanning` + `secret_scanning_push_protection`.
- [x] **Dependabot alerts + security updates** (wired 2026-06-14): enabled via
      `gh api -X PUT .../vulnerability-alerts` and `.../automated-security-fixes`.
- [ ] **Code scanning default setup OFF if CodeQL workflow is used** (avoid
      double analysis): Settings → Code security → Code scanning. Do this after
      `codeql.yml` lands on `main`.
- [ ] **OpenSSF Best Practices badge**: register the project at
      <https://www.bestpractices.dev/>, then add the returned badge:
      `[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<ID>/badge)](https://www.bestpractices.dev/projects/<ID>)`
      to the README badge row. (Scorecard is automated; this one needs a
      one-time self-assessment.)
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
