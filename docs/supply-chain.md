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
with exactly the packages listed there, resolved from the lock's fixed
snapshot.ubuntu.com timestamp; the build fails closed if any version
is unavailable, proves the linked libbpf version and compiler from the binary,
and must be byte-identical to the lock's recorded reproduction when the
validator tree is unchanged. A stable tag additionally refuses any validator
whose sha256 differs from its release candidate's, because the qualification
campaigns ran exactly those bytes. Changing the lock means a new release
candidate.

Prereleases publish only their exact `X.Y.Z-rc.N` image tag. Stable aliases
(`X.Y`, `latest`) are reachable only through the stable release channel.

### Validator lock maintenance

`validator/build-inputs.lock` pins exact package versions, several of them from
the `noble-updates` pocket (e.g. `libc6-dev`, `zlib1g-dev`, `libelf-dev`,
`binutils`, `gcc-13`). Ubuntu's archive keeps only the newest version in each
pocket, so resolving them from the moving archive would fail at the next
stable-release update (SRU) of any of them, and would let unpinned transitive
packages (`linux-libc-dev` headers, `libisl23`/`libmpc3`/`libmpfr6`) drift.
The lock therefore also names `apt_snapshot`, a fixed snapshot.ubuntu.com
timestamp: the builder drops the image's archive sources and resolves every
package from that snapshot of `noble`, `noble-updates` and `noble-security`.
A future `apt_snapshot` is refused: snapshot.ubuntu.com answers it with the
newest state so far, i.e. the moving archive.

The builder image has no `ca-certificates`, so the runner's CA bundle
(`/etc/ssl/certs/ca-certificates.crt`, or `BPFCOMPAT_SNAPSHOT_CA_BUNDLE`) is
mounted read-only and apt verifies TLS to `snapshot.ubuntu.com` against it
(`apt_tls: tls-verified-host-ca` in the build record). Without a bundle the
build falls back to `apt_tls: signature-only`: TLS peer verification is off for
`snapshot.ubuntu.com` only. In both modes apt verifies the snapshot's
`InRelease` signature against the digest-pinned image's
`ubuntu-archive-keyring` and every index and package hash; without TLS an
attacker could at most replay another genuine Ubuntu-signed index, which the
exact-version check or the recorded byte-identity check then refuses, and that
is no weaker than the image's default plain-http archive sources. If the
snapshot cannot provide a locked version, or any index cannot be fetched after
three attempts, `scripts/build-validator-pinned.sh` fails closed.

Eleven pinned builds against snapshot `20261014T154800Z` on 2026-10-15, in both
TLS modes, reproduced the qualified v0.4.0-rc.4 validator (`e0e7fcf8...`)
byte-for-byte, each in 21-97 seconds.

To move to newer packages, choose a newer snapshot, update the `pkg=` versions
and the `reproduces=` line from a pinned build, and cut a new release
candidate: that changes the shipped validator.

`dist/validator-build-inputs.json` is the validator's build record. It is
attested with the candidate provenance and, from v0.4.0-rc.5 on, shipped as a
release asset listed in `SHA256SUMS`, so it outlives the workflow run
artifact's retention.

### Third-party license bundle and relink kit

From v0.4.0-rc.5 (not in v0.3.7 or v0.4.0-rc.4), the same build produces two
more release assets, both listed in `SHA256SUMS`, attested, and reproducible
byte for byte from the same inputs:

- `bpfcompat-third-party-licenses.tar.gz`: the license, notice and patent texts
  (verbatim) of every Go module linked into the shipped CLIs, taken from each
  binary's own build information; the Go toolchain's `LICENSE` and `PATENTS`;
  and, for the validator, the Debian copyright file of every package that owns
  a link input or a header the compile read, with the full texts they refer to.
  `INVENTORY.json` records versions, provenance and sha256 of each text, and
  keeps observed facts, recorded decisions and open questions apart.
- `bpfcompat-validator-relink-kit-linux-amd64.tar.gz`: the validator's `main.o`,
  the Makefile recipe split into compile and link commands, the linker's member
  trace and map, every link input and header with its owning package, the build
  record and locks, the validator's own C sources and `relink.sh`. The build
  refuses unless relinking `main.o` reproduces the shipped validator byte for
  byte.

`distribution/policy.json` records the open distribution decisions. Two of them
add assets when decided: `bpfcompat-validator-link-inputs-linux-amd64.tar.gz`
(the static archives and start files the validator was linked from) and
`bpfcompat-validator-native-sources.tar` (the exact Ubuntu source packages in
`distribution/native-sources.lock`, hash-verified). A stable build refuses while
any decision listed in `blocks_stable` is undecided. None of this elects a
license or states that any license condition is met.

The installer and the GitHub Action install the license bundle when the
release's `SHA256SUMS` lists it, and the container image carries the Go texts
in `/usr/share/doc/bpfcompat/`. The installer served from `main` already does
this; the GitHub Action and the container image do from v0.4.0-rc.5.

### Verifying a signed release

```bash
VER=v0.3.7   # the exact release tag you downloaded
cosign verify-blob \
  --certificate SHA256SUMS.crt --signature SHA256SUMS.sig \
  --certificate-identity "https://github.com/Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/$VER" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

The identity names the exact tag, as `scripts/install.sh` does, so a signature
made by another tag's release run (for example a prerelease) is refused. The
tag-bound attestation checks are in
[verifying-releases.md](verifying-releases.md).

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
