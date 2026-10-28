# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a
1.0 release is cut.

## [Unreleased]

### Security
- The GitHub Action no longer pastes inputs into its `run:` scripts. Every
  input reaches the scripts through `env:` and is read as quoted data, so a
  value containing quotes, `$(...)`, backticks or newlines can no longer run as
  shell code in the calling job. A CI guard
  (`scripts/check-action-input-interpolation.sh`) and an end-to-end injection
  test keep it that way.
  - Values containing `$VAR`, backticks or `\` used to be expanded by bash as
    a side effect; they are now passed literally.

### Fixed
- A release-pinned GitHub Action now runs the validator it downloaded and
  verified, by path and pinned digest. Before, a validator installed in
  `/usr/local/libexec` or `/usr/libexec` on a self-hosted runner (for example
  by an earlier `install.sh`) was selected instead of the attested one. A
  workflow that sets `BPFCOMPAT_VALIDATOR_BIN` or `BPFCOMPAT_VALIDATOR_SHA256`
  keeps its own settings unchanged, with a warning. Every fallback to a source
  build while pinned to a release is now a `::warning::` annotation; such a run
  still uses the CLI's normal validator search order.
- Command mode requires the guest kernel release. If `uname -r` fails or
  prints nothing, the command is not started and the target is
  `INFRA_ERROR`; before, the target could be `COMPATIBLE` or `INCOMPATIBLE`
  with no record of which kernel ran, and a required target could pass.
- A missing local `--artifact` path is no longer treated as a registry
  reference, unless it reads like one: a relative path without a `./`, `../`,
  `/` or `~` prefix that does not end in `.bpf.o` and that either has a
  host-like first component (it contains `.` or `:`, or is `localhost`) or
  contains `@sha256:`. A path with one of those prefixes is never pulled.
  - Before, any non-existent path that happened to parse as an image reference
    (`/home/u/prog.bpf.o`, `build/prog.bpf.o`, `./prog.bpf.o`) was pulled from
    Docker Hub. That leaked the local path and failed with a registry error.
  - It now fails locally with `artifact "<path>": no such file`. This covers
    `test`, `test-command`, `suite`, the API and `pkg/bpfcompat.Validate`.
  - The CLI now classifies remote refs like the Action's `artifact` input:
    the first path component must be a registry host (contains `.` or `:`, or
    is `localhost`), or the ref must pin an `@sha256:` digest.
  - The Action treats an `artifact` input that looks remote (see
    `docs/compatibility-contract.md`, including dot-directories such as
    `.output/`) as remote even when a workspace file of that name exists;
    prefix workspace files with `./`.

### Added
- A compact README strip highlights the merged Falco and Inspektor Gadget
  upstream CI integrations and links to their public evidence.
- Releases carry the third-party license material of their binaries as signed
  assets listed in `SHA256SUMS`: `bpfcompat-third-party-licenses.tar.gz`
  (verbatim license, notice and patent texts of every linked Go module, the Go
  toolchain and the validator's native components, with an `INVENTORY.json`
  generated from the shipped binaries) and
  `bpfcompat-validator-relink-kit-linux-amd64.tar.gz` (the validator's `main.o`,
  link commands, linker trace and map, inputs with owning packages, sources and
  `relink.sh`). `validator-build-inputs.json` is now a release asset too.
  - `install.sh` and the GitHub Action install the license bundle, verified
    with the binaries, when a release lists it; releases without it install
    as before. The container image carries the CLI's texts in
    `/usr/share/doc/bpfcompat/`.
  - Open distribution decisions are recorded in `distribution/policy.json`;
    the assets elect no license and claim no compliance, and a stable build
    refuses while a stable-blocking decision is undecided.

### Changed
- **Breaking:** implicit Docker Hub short refs in tag form, such as
  `org/name:tag`, are no longer pulled. Spell them with the host, e.g.
  `docker.io/org/name:tag`; the "no such file" error suggests that spelling.
  Digest-pinned short refs (`org/name@sha256:…`) are still pulled.

## [0.4.0-rc.4] - 2026-10-14

### Added
- Reports record which distribution actually booted:
  `environment.observed_os_id` and `observed_os_version_id` (the guest's
  `/etc/os-release`), the profile's `requested_distro` and
  `requested_distro_version`, and `distro_match`.
  - A guest of another distribution or major release is treated exactly like
    a kernel-family mismatch: the run is `INFRA_ERROR`/incomplete, never
    `INCOMPATIBLE`. `bpfcompat diff` marks the cell not established and
    refuses a `distro_match` that contradicts its own inputs. The public page
    counts it under *Required infra*.
  - An unset `distro_match` is unknown, not a mismatch, so older reports
    compare exactly as before.
  - This closes the `rhel-8-4.18` identity gap. The bring-your-own slot
    accepted any EL8 rebuild on a 4.18 kernel as RHEL, and the image found in
    it reports `ol 8.10` (Oracle Linux 8, UEK R7 5.15).
  - All fields are additive (schema v0.1 stability contract).

### Changed
- `oracle-linux-9-uek7-5.15` now validates the kernel series its id names.
  - Its OL9U7 template boots UEK8 6.12, so until now every run of this profile
    tested 6.12 under a 5.15 label (flagged per run as a kernel-family
    mismatch since #143).
  - The profile now installs a pinned UEK R7 kernel
    (`5.15.0-325.221.6.1.el9uek`) from Oracle's OL9 UEKR7 repository.
  - The id is unchanged, so no matrix migration is needed. Results for it now
    describe 5.15, where before they described 6.12.
  - The 6.12-on-EL9 case stays covered by
    `oracle-linux-9-uek7-5.15-k6.12.0-204.92.4.4.el9uek`. That profile's id
    names the image lineage and its `-k` suffix the exact kernel.
  - A catalog test now requires every `install_kernel` and every recorded
    baseline kernel to belong to the profile's declared `kernel_family`, and
    the freshness crawler mapping to track that family.
- Compatibility campaigns (`latest-kernel-compatibility.yml`) and every job of
  the release-candidate canaries (`release-candidate-canary`,
  `external-consumer-canary`, `consumer-canary`) now run on the pinned
  `ubuntu-24.04` runner image instead of the moving `ubuntu-latest` label, so
  one candidate's observations do not straddle GitHub's Ubuntu 26.04
  migration; tests guard both pins (#188, #193).

### Fixed
- The CentOS Stream 9 kernel 725 exact-kernel profile fetches the exact signed
  RPMs from the official CentOS Koji archive, since the rolling mirror retired
  them (HTTP 404), and verifies them against the pinned CentOS SHA256 signing
  key. Forward-ported from the v0.3.8 maintenance line (d1a053c, 8f82099).
  Kernel identity and mandatory guest signature verification are unchanged.

### Security
- **Go toolchain 1.25.14 -> 1.26.9.** Eleven standard-library advisories
  published 2026-10-08 (GO-2026-6610 through GO-2026-6617 and related, in
  `net/http`, `net/textproto`, `crypto/tls` and `os`) are fixed only in
  go1.26.9 and go1.27.2; Go 1.25 receives no fix. `go.mod`, `release.yaml`
  `minimum_go`, every product workflow, the Dockerfile builder (tag and
  digest moved together to `golang:1.26.9-bookworm@sha256:d9c68c2c…`) and the
  Hetzner bootstrap now use 1.26.9. `govulncheck` reports no findings.
- CI, the native ARM64 smoke and the release build now prove which toolchain
  compiled each shipped binary (`scripts/check-binary-toolchain.sh`, reading
  the embedded build info), instead of trusting the `go` directive alone.
- golangci-lint v2.6.2 (built with go1.25) refuses to load a go1.26 module;
  CI moves to v2.12.2, the smallest release built with Go 1.26. Linting stays
  diff-scoped, so the newer linters' findings in untouched code do not gate.
- `check-release-consistency.sh` now also checks literal `go-version:` pins in
  product workflows, and checks the research-v1 workflows against the frozen
  research contract (`scripts/research/materialize-v1.sh` `EXPECTED_GO`)
  instead of `minimum_go`.

### Changed
- Intentionally retained at Go 1.25.14: the three `research-*-v1` workflows
  and `scripts/research/materialize-v1.sh`. They reproduce the frozen,
  DOI-archived research-v1 dataset with the exact toolchain it was produced
  with; they are `workflow_dispatch`-only, `contents: read`, and ship nothing.
  `examples/ebpf-go-loader` keeps `go 1.25.0` as its minimum language version
  and is built by CI with the pinned 1.26.9 toolchain.
- Go 1.26 behavior relevant to bpfcompat: `net/url.Parse` rejects malformed
  hosts with unbracketed colons (`urlstrictcolons`), which tightens runtime
  fetch, freshness-crawler and agent URL parsing; crypto APIs ignore
  caller-supplied randomness (bpfcompat already uses `crypto/rand` and
  deterministic Ed25519); the Green Tea GC is the default. Release-style
  amd64/arm64 builds remain byte-reproducible.

### Fixed
- **Public compatibility matrix lane no longer aborts on one failed image
  download.** Five of the seven weekly `compatibility-matrix-publish` runs
  between 2026-08-18 and 2026-10-06 failed in the prefetch step (HTTP 502 for
  the renamed CentOS Stream image; one HTTP/2 `PROTOCOL_ERROR`), before any VM
  booted, so no report existed and the published page silently kept the last
  successful week. `vm/scripts/fetch-cloud-image.sh` now retries transient
  failures, downloads to a `.part` file so a failed fetch never masquerades as
  a cached image, and reports the URL with its HTTP status; the new
  `scripts/prefetch-matrix-images.sh` attempts every image and writes a
  per-image summary that the lane uploads as evidence. Validation proceeds and
  a target whose image is missing is recorded by bpfcompat as `INFRA_ERROR`,
  never as a pass or fail.
- The published matrix page now reports required targets as pass / fail /
  infra separately, shows the run verdict, and flags incomplete runs; an
  infrastructure error was previously folded into the failure count. Both
  contrast artifacts are validated even if the first fails, and the page is
  redeployed from a failed run when `scripts/check-matrix-reports.sh` proves
  the reports are this run's evidence (v0.1 schema, started after the job,
  exactly the matrix's profiles, the artifact bytes built in the run). The
  job itself still fails; the page shows the honest incomplete state instead
  of staying on the last green week. Without valid reports nothing is
  deployed.
- The consumer canary's source-build job (the action at `@main`) now runs
  `matrices/canary-source.yaml`, which adds `centos-stream-9-5.14`, the
  RHEL-family profile Inspektor Gadget's upstream lane depends on. The pinned
  stable and candidate jobs keep `matrices/canary.yaml`: they resolve
  profiles from the pinned release, where the old CentOS URL is already known
  to be dead.
- Removed references to the public demo instance from the README, quickstart
  and ebpf.io listing data; the hosted demo is not maintained. Reworded the
  weekly-matrix claim to describe what the page actually guarantees.

### Added
- Published the canonical research pilot v1 repository dataset from successful
  workflow run `35393833464`: 70/70 normalized execution records, exact
  environment and execution provenance, raw-report and processed-data SHA-256
  locks, lossless per-case execution shards, and deterministic descriptive
  RQ1–RQ4 tables guarded by a reproduction test. The full Actions artifact is
  content-addressed in the dataset manifest for later durable archival.
- Added the manual-only research pilot v1 execution protocol: seven frozen
  validation cases across ten logical kernel profiles, immutable profile and
  manifest locks, exact-environment derivation from observed kernel plus image
  evidence, raw-report provenance, and normalization into JSONL research
  execution records without converting infrastructure failures into eBPF
  incompatibilities.
- Added a research pilot v1 materialization pipeline that rebuilds the frozen
  BPF objects and project loaders from pinned source revisions, verifies the
  published BPFCompat v0.3.7 execution binaries, records the build toolchain,
  derives canonical validation-contract hashes, and uploads an integrity-checked
  SHA-256 bundle without running the compatibility study itself.
- Froze the prospective research pilot v1 selection: explicit inclusion rules,
  pinned Falco and Cilium source provenance, a ten-profile logical kernel set,
  libbpf/cilium-ebpf/Falco validation-contract specifications, and documented
  Inspektor Gadget deferrals where existing evidence is not yet content-addressed.
- Added CFF citation metadata and a research protocol scaffold defining the
  prospective eBPF compatibility study questions, evidence rules, corpus
  metadata, reproducibility boundary, and academic-readiness roadmap. Existing
  case studies remain exploratory evidence rather than being relabeled as
  preregistered research.
- Consumer canary now covers the **stable** release as well as the candidate.
  `stable-prebuilt` pins the exact commit of the release `release.yaml` calls
  stable and installs no build toolchain, so a regression in
  commit-SHA-to-release resolution fails here instead of forcing a downstream
  consumer into an unexpected source build. Both prebuilt jobs first assert
  that the runner has no libbpf headers, which is what makes "the job passed"
  mean "prebuilt binaries were used" rather than "something compiled".
  `candidate-prebuilt` (formerly `prebuilt`) keeps the prerelease path and its
  attestation verification unchanged; `source-build` keeps the documented
  dependency set honest.
- `scripts/check-canary-pins.sh` binds those pins to `release.yaml` and runs
  inside the release-consistency gate. Bumping `stable_version` without
  repinning the canary — or mislabelling a pin's `# vX.Y.Z` comment — now fails
  CI instead of silently leaving the documented consumer path untested.

### Fixed
- Fixed the CentOS Stream 9 and 10 cloud image URLs: cloud.centos.org renamed
  the `latest` images to `CentOS-Stream-GenericCloud-<N>-latest.x86_64.qcow2`
  and the old `GenericCloud-x86_64-<N>-latest` names return HTTP 502, so every
  CentOS Stream target failed with an infrastructure error.
- Fixed research pilot v1 normalization to match the actually frozen
  BPFCompat v0.3.7 `ReportV01` schema. The runner now records execution-time
  CLI/validator/loader hashes before the study; normalization derives the
  v0.3.7 verdict and kernel-family match from report fields, validates any
  newer structured fields when present, preserves exact observed environments
  for requested-kernel mismatches, and fails closed on provenance drift.
- Release-asset verification regression coverage now exercises the cases the
  contract actually depends on: extra `SHA256SUMS` entries for assets that were
  never downloaded must pass (the v0.3.6 arm64 failure), while a missing,
  duplicated, or malformed entry, a missing asset or manifest, a traversing
  asset name, a failed attestation, and a runner with no usable `gh` must all
  fail closed.
- The canary pin guard's remote tag lookup, used on the shallow checkouts some
  gate lanes run, now resolves lightweight tags as well as annotated ones. Only
  an annotated tag advertises a peeled `refs/tags/<t>^{}` ref, so asking for
  that ref alone would have reported the next lightweight release tag as
  nonexistent and failed the release gate for a tag that exists.

## [0.4.0-rc.3] - 2026-07-30

### Changed
- Split release creation into a tag-triggered candidate workflow and a
  separately dispatched promotion workflow that re-verifies exact candidate
  evidence after a 15-minute production wait.
- Replaced the external-reviewer release contract with an explicit
  solo-maintainer operator confirmation and documented its residual
  account-compromise risk.
- Protected `v*` release tags from updates and deletion while retaining strict
  pull-request checks with zero required human approvals.

## [0.4.0-rc.2] - 2026-07-30

### Fixed
- Isolated release-consistency fixtures from the tag workflow environment so
  candidate tags do not make stable-metadata regression fixtures fail.
- Removed the release-consistency checker's undeclared `ripgrep` dependency;
  tag release jobs now use the baseline `grep` tool available on hosted
  runners.

## [0.4.0-rc.1] - 2026-07-29

### Added
- Added a mandatory tagged-release candidate gate that exercises the exact
  release CLI and validator in a pinned Ubuntu VM with both a compatible
  artifact and a classified incompatible artifact.
- Added native ARM64 execution of the exact attested release candidate before
  draft staging or container promotion.
- Added command-mode provenance for the exact loader binary and invocation, a
  release metadata consistency gate, and an explicit production support
  boundary for the CLI, Action, and disposable VM validator.
- Added the original OCI reference to JSON, Markdown, and Action evidence while
  retaining the extracted ELF SHA-256 as the immutable content identity.
- Added scheduled hosted-runner compatibility evidence and a pull-request gate
  that freezes experimental runtime, agent, API, registry, and SaaS surfaces
  unless a maintainer explicitly approves a maintenance or security change.

### Changed
- Unified binary, container, signing, attestation, VM verification, and release
  publication into one release promotion workflow.
- Removed dormant release-creation code and write permission from the scheduled
  compatibility-site workflow; published releases now have one exclusive
  writer, and reruns refuse to mutate an already-public release.
- Made the upstream-kernel experiment manual-only until it has a reliable
  virtualization runner; the supported latest-vendor-kernel lane now runs on a
  GitHub-hosted KVM runner.
- Container targets now default to CLI help instead of starting the frozen
  experimental API server.
- Required CI and tagged releases now enforce a 50.0% total Go statement
  coverage floor so coverage cannot silently regress during graduation.

### Security
- Release downloads now require a release-workflow GitHub attestation or an
  exact-workflow Sigstore signature in addition to checksums; partial Action
  downloads verify an explicit asset allowlist instead of the entire checksum
  manifest.
- VM image downloads now have cancellation, timeout, and size limits; cached
  images are rehashed on every run, and the release-gate Ubuntu image is pinned
  to immutable vendor bytes.
- OCI pulls now have a deadline, extracted eBPF layers and archive expansion
  are size-bounded, and incomplete output is removed on failure.
- Run inputs, cloud-init seed data, downloads, and extracted artifacts now use
  owner-only directories and files.
- `BPFCOMPAT_VALIDATOR_SHA256` is now enforced before a guest validator is
  used.

## [0.3.7] - 2026-08-26

### Fixed
- **GitHub Action: prebuilt-binary verification no longer fails on assets it
  never downloads.** v0.3.6 began publishing `bpfcompat-linux-arm64`, so the
  release `SHA256SUMS` listed three artifacts while the action fetches only the
  two amd64 ones. The bare `sha256sum -c SHA256SUMS` then reported
  `bpfcompat-linux-arm64: FAILED open or read` and, because verification is a
  hard error rather than a fallback, aborted the action on **every amd64
  runner** — the "Run bpfcompat" step never executed. Any workflow pinned to
  the v0.3.6 commit was affected; consumers that pinned a tag object SHA
  instead silently fell back to building from source and so did not see it.
  Verification now covers exactly the downloaded assets and stays fail-closed:
  a missing, duplicated, or malformed `SHA256SUMS` entry is still an error.
  Covered by `scripts/action-prebuilt-checksums_test.sh`, which extracts the
  logic from `action.yml` and exercises the corrupt/missing/duplicate cases.

### Security
- Moved the CI and release toolchain from Go 1.25.12 to 1.25.14, which
  govulncheck now flags on the older patch release. Release binaries for this
  tag are built with 1.25.14.

## [0.3.6] - 2026-07-26

### Added
- Published the CLI as multi-architecture `linux/amd64` and `linux/arm64`
  release assets and published a matching multi-architecture container image.
- Added a scheduled external-consumer canary covering Falco, Inspektor Gadget,
  and KubeArmor integration paths.

### Security
- Made installer checksum/signature verification fail closed when verification
  is available.

## [0.3.5] - 2026-07-26

### Added
- Added the one-command installer, GHCR image, and installed-validator
  discovery.

## [0.3.4] - 2026-07-26

### Added
- Added command-mode guest disk resizing for loaders that build or install
  dependencies inside constrained cloud images.

## [0.3.3] - 2026-07-26

### Added
- Added the canonical generated support matrix and documentation-drift guard.
- Added Ubuntu and RHEL-family kernel-sweep profiles, consumer canaries, and
  integration templates for common loader architectures.

### Fixed
- Accepted remote OCI references in the GitHub Action without treating them as
  workspace-relative paths.

## [0.3.2] - 2026-07-16

### Fixed
- **Release pipeline: pin the cosign CLI to v2.** The v0.3.1 tag build failed
  at the signing step because the cosign installer fetched the new cosign v3,
  which ignores `--output-signature`/`--output-certificate` in favor of the
  bundle format. As a result **v0.3.1 has no release binaries** — it remains a
  valid Go module version, but Action/tag consumers should use v0.3.2, which
  is content-identical plus this pipeline fix.

## [0.3.1] - 2026-07-16

### Added
- Project governance and sustainability documents: Code of Conduct,
  governance, maintainers, roadmap, adopters, funding, and sponsor ledger.
- GitHub Sponsors repository funding configuration and sponsor badge.
- Structured adopter issue form for confirmed use and public evaluations.
- Sponsor brief and explicit review ownership for external outreach and project
  accountability.
- Docs: bpfcompat now runs upstream — `falcosecurity/libs` merged a scheduled
  compatibility lane that validates Falco's real loader (`scap-open`) per
  kernel via command mode (falcosecurity/libs#3024); README, the Falco case
  study, and `docs/command-validation.md` document it.

### Fixed
- **GitHub Action: commit-SHA pins now use prebuilt release binaries.** The
  prebuilt resolution only matched `v*` tag refs, so pinning the action by
  full commit SHA (the recommended practice for third-party actions) silently
  fell back to building the validator from source — failing on runners
  without `libbpf-dev`. A 40-hex action ref is now resolved to the release
  tag pointing at that commit via the GitHub API (authenticated with the
  workflow's `github.token`) and the release's checksum-verified binaries are
  used; any API failure or unknown SHA still falls back to the source build,
  and `prebuilt: never` still forces it.
- **VM runner: fail fast when a cidata-seed distro lacks `cloud-localds`.**
  RHEL-family, Amazon Linux, Oracle, and SUSE guests need a cidata seed ISO;
  without `cloud-image-utils` installed the runner previously fell back to a
  vvfat config drive those images never boot from (0-byte serial, SSH
  timeout reported as an infra error). This is now a clear pre-boot error
  naming the missing tool; set `BPFCOMPAT_ALLOW_VVFAT_SEED=1` to restore the
  old fallback.

### Security
- Release binaries are built with Go 1.25.12, picking up the fix for
  GO-2026-5856 (Encrypted Client Hello privacy leak in `crypto/tls`).

## [0.3.0] - 2026-07-02

### Added
- **Command/binary validation mode**: `bpfcompat test-command` (and
  `test --command`) runs *your own* loader binary/command inside each matrix
  kernel VM; the per-kernel verdict is its exit code and the bundled validator
  is not used. Guest env exposes `$BPFCOMPAT_BIN`, `$BPFCOMPAT_ARTIFACT`,
  `$BPFCOMPAT_REMOTE_ROOT`. See `docs/command-validation.md`.
- **Library of known-tricky vendor kernels** (`matrices/quirk-library.yaml` +
  `docs/kernel-quirk-library.md`): 11 evidenced kernels where "version ≠
  feature support" bites (ring-buffer boundary, enterprise backports, no-BTF,
  vendor rebases, program-variant bands).
- **GitHub Action command mode**: new `command`, `command-binary`, and
  `command-expect-exit` inputs (`artifact` becomes optional when `command` is
  set); free-text inputs pass through the step environment, never inline
  interpolation. A bare `matrix` name (e.g. `quirk-library`) resolves to the
  `matrices/` directory shipped with the action.
- **Public compatibility matrix**: `compatibility-matrix-publish` now runs
  weekly on a hosted runner and deploys the quirk-library matrix (validated
  against a ringbuf/simple-pass contrast pair) to GitHub Pages:
  <https://kernel-guard.github.io/bpfcompat/>.
- **ebpf-go validation recipe**: `examples/ebpf-go-loader` (standalone module,
  static ~50-line cilium/ebpf loader) + `docs/ebpf-go-validation.md` — a libbpf
  load-pass does not guarantee an ebpf-go load-pass on the same kernel.
- GitHub Marketplace purchase webhook (ingestion-only, HMAC-verified JSONL
  ledger) with a Cloudflare Tunnel on-ramp.
- `examples/preload-gate`: a complete, runnable example of using the
  `pkg/bpfcompat` library — `ValidateBeforeLoad` as a bpfman-style pre-load gate
  (real load on the node's own kernel, no VM). README gains a "Library mode"
  section with the example and a real pass/blocked run.

### Changed
- Experimental tracks (virtme-ng lane, Firecracker backend, Web UI/API, runtime
  decisioning) consolidated into `docs/experimental.md`; the README leads with
  the CI gate, command mode, and the quirk library.
- README no longer claims modern_bpf is validated "exactly as Falco's loader
  runs it" — reworded to "mirrors libpman's loader contract", pointing at
  command mode as the way to run the real loader binary.

### Security
- Shell-quote interpolated values in guest command strings.
- Harden data-derived file paths and check writable `Close()` errors.

### Fixed
- README install snippet pinned the stale `v0.1.6` release; bumped to `v0.2.0`.
- Readable contrast in the `test-command` README screenshot.

## [0.2.0] - 2026-06-27

### Added
- aarch64 VM support: the QEMU executor now supplies aarch64 UEFI firmware
  (AAVMF pflash; `BPFCOMPAT_AARCH64_UEFI_CODE`/`_VARS`) and uses TCG software
  emulation for a guest whose arch differs from the host (KVM only accelerates a
  same-arch guest). This makes aarch64 cloud-image profiles actually boot.
- RHCOS evidence matrix expanded to 6 artifacts × 3 OpenShift releases on x86_64
  plus a real aarch64 boot (OpenShift 4.16, `5.14.0-427.50.1.el9_4.aarch64`).
  New: `aegis` BPF-LSM shows a real backport boundary (rejected on RHEL 9.2,
  load+attach all hooks on 9.4); profiles `rhcos-4.16-arm64`, matrices
  `rhcos-arm64.yaml`; `make rhcos-image RHCOS_VERSION=` stages per-version/arch.
- RHCOS evidence matrix: profiles for OpenShift 4.14 / 4.16 / 4.18 (`matrices/rhcos.yaml`)
  and a recorded multi-version, multi-artifact run in `docs/evidence-rhcos.md` —
  baseline load and ring-buffer load+attach pass on every release (RHEL 9.2 and
  9.4 backported 5.14 kernels), and a CO-RE failure is correctly rejected on
  every release (the discriminator). `make rhcos-image` takes `RHCOS_VERSION` to
  stage per-version images. x86_64 only; opt-in via `BPFCOMPAT_ENABLE_RHCOS=1`.
- CoreOS (Ignition) boot support. CoreOS-family images boot via Ignition, not
  cloud-init, so the executor now writes a minimal Ignition config (SSH key for
  the `core` user) and passes it to QEMU via `-fw_cfg name=opt/com.coreos/config`
  (see `internal/vm/ignition.go`). Fedora CoreOS is now runnable and proven —
  FCOS stable boots and the validator load/attaches inside the guest (verified
  on kernel `7.0.11-200.fc44`); fetch the image with `make vm-image-fcos`. RHEL
  CoreOS (`rhcos`) shares this boot path; because its image ships with an
  OpenShift release rather than a public URL, the operator stages it with
  `make rhcos-image RHCOS_IMAGE=... ` (or `RHCOS_IMAGE_URL=...`) and opts in with
  `BPFCOMPAT_ENABLE_RHCOS=1`. Left off, `rhcos` stays unsupported so it is never
  claimed runnable without a real image.
- Embeddable library mode (`pkg/bpfcompat`). `ValidateBeforeLoad` /
  `ValidateBytes` do a real load of a compiled eBPF object against the local
  running kernel — no VM, no network — for use as a pre-load gate (e.g.
  bpfman); `Validate` exposes the full VM matrix engine. Host-kernel loading is
  gated behind the `hostload` build tag (default builds return
  `ErrHostLoadNotEnabled`), the static validator is embedded via `go:embed`
  (amd64/arm64; staged by `make pkg-embed-validator`, built by
  `make lib-hostload`), and an internal provider seam keeps the public API
  stable for a future in-process CGO validator. Pre-1.0 / experimental; see
  `pkg/bpfcompat/README.md`.
- Auto-type programs libbpf can't classify by section name: when a program is
  left `BPF_PROG_TYPE_UNSPEC` after open because its ELF section name isn't one
  libbpf recognizes, the validator sets the type the artifact's own loader
  assigns. Today this covers socket-filter programs in `socket`-prefixed
  sections (e.g. Inspektor Gadget's `socket1`), which otherwise fail to load
  with "missing BPF prog type". Reported per program in the run notes. (This
  clears the program-type blocker; a framework-coupled gadget can still fail
  later for its own reasons — e.g. `trace_dns` then hits a CO-RE relocation
  against Inspektor Gadget's socket-enricher API type `gadget_socket_value`,
  which the IG loader supplies at runtime and a standalone load does not.)
- Manifest-declared program-type override: `program_types:` entries
  (`{program: <name-or-section>, type: <bpf-type>}`) set a program's BPF type
  explicitly before load, the general form of the auto-typing above — for any
  program libbpf can't classify, not just socket-filter. Surfaced to the
  validator as `--set-prog-type <program|section>=<type>`; takes precedence
  over auto-typing and is reported per override in the run notes.
- Generic inner-map prototype map fixup: a manifest `maps[].inner_map`
  (`type`/`key_size`/`value_size`/`max_entries`) installs an inner-map template
  on a `HASH_OF_MAPS`/`ARRAY_OF_MAPS` before load, so objects whose own loader
  sets up the inner map at runtime can be validated faithfully. Previously only
  an inner *ringbuf* could be declared. Surfaced to the validator as
  `--set-map-inner-map <map>=<type>:<key>:<value>:<entries>`. Proven against
  KubeArmor's `system_monitor.bpf.o` (`kubearmor_visibility`), which then loads
  across Ubuntu 5.4/5.15, Debian 6.1, Ubuntu 6.8, and AlmaLinux 8 (4.18).
- OCI gadget loading: `--artifact` now accepts an OCI image in addition to a
  local `.bpf.o` ELF — a registry reference (e.g.
  `ghcr.io/inspektor-gadget/gadget/trace_open:latest`), an OCI layout
  directory, or an OCI/docker image archive. bpfcompat extracts the eBPF object
  layer (Inspektor Gadget's `application/vnd.gadget.ebpf.program.v1+binary`
  media type, with an ELF-magic fallback) and validates it like any other
  artifact. This lets gadget authors point the validator straight at a
  published gadget. (Requested by Inspektor Gadget maintainer.)
- `--quick`: run the built-in quick-check kernel set (old LTS → recent) instead
  of `--matrix`, for a fast local "does it load?" check with no matrix file —
  e.g. `bpfcompat test --artifact ghcr.io/org/gadget:tag --quick`.
- Auto-size runtime-sized maps: the validator now gives a default `max_entries`
  to maps that ship with `max_entries=0` and whose type requires a positive
  size (hash/array/percpu/LRU/stack-trace/LPM/prog-array), matching what the
  real loader does at runtime. Types where 0 is meaningful (perf-event-array,
  ring/user ringbuf, the `*_STORAGE` local-storage maps) are never touched, and
  manifest `max_entries` fixups take precedence. Reported per map in the run
  notes. Together with the two items above this makes zero-config gadget
  validation work — e.g. Inspektor Gadget's `trace_open` loads with no manifest
  (its runtime-sized `ig_build_id` map is auto-sized).
- Supply-chain trust signals: GitHub CodeQL static analysis
  (`.github/workflows/codeql.yml`), OpenSSF Scorecard
  (`.github/workflows/scorecard.yml`), and Dependabot
  (`.github/dependabot.yml`, Go modules + pinned actions). README gains CI,
  CodeQL, Scorecard, and license badges; `docs/supply-chain.md` documents the
  controls and the maintainer-side repo settings (branch protection, secret
  scanning, OpenSSF Best Practices registration). SBOM + cosign keyless signing
  already shipped in `release-artifacts.yml`.
- Zero-infrastructure CI on-ramp: `.github/workflows/bpfcompat-example-hosted.yml`
  runs the full QEMU VM compatibility gate on a stock GitHub-hosted
  `ubuntu-latest` runner. GitHub-hosted Linux runners now expose `/dev/kvm`, so
  no self-hosted runner is required for the default lane. The README now leads
  with this path and with the Falco `modern_bpf` 5-kernel proof.
- `bpfcompat kernel-freshness`: compares the kernel release each VM profile
  last validated (`vm/kernel-baselines.yaml`) against the per-distro kernel
  inventory published weekly by falcosecurity/kernel-crawler, flagging
  profiles whose matrix evidence is behind what the distro currently ships.
  `--update-from-report` refreshes the baselines from a matrix report;
  `--fail-on-stale` turns staleness into an exit-code signal. A scheduled
  non-blocking workflow (`kernel-freshness.yml`) runs the comparison weekly
  after kernel-crawler's own refresh. Suggested by Federico Di Pierro.
- Dense kernel-sweep lane: profiles can set `install_kernel` (plus
  `kernel_packages` pool URLs) to install a specific kernel release inside
  the guest, pin it as the grub default, reboot into it, and verify
  `uname -r` before validation — one vendor cloud image then covers a
  whole release series instead of only the kernel it shipped with.
  Packages install from direct archive-pool `.deb` URLs because apt only
  indexes the current ABI; superseded releases stay in the pool but
  disappear from the indexes. `bpfcompat kernel-sweep --profile <id>
  --count N` generates the derived profiles and matrix from the
  kernel-crawler inventory. Ubuntu only for now.

### Changed
- QEMU executor falls back to TCG software emulation when `/dev/kvm` is absent
  (`-accel tcg -cpu max`) instead of failing the launch, so VM validation stays
  correct on runners without hardware virtualization (just slower). Hosted-KVM
  runners keep `-enable-kvm -cpu host`.

## [0.1.6] - 2026-06-21

### Added
- **Enterprise & backported-kernel coverage (14/14 proven).** New AlmaLinux 8 /
  Rocky 8 (4.18) profiles plus a real reference run validating
  `load_attach` across the RHEL 8/9/10 ABI (AlmaLinux/Rocky/CentOS-Stream),
  Oracle UEK 7/8, Amazon Linux 2 (5.10 and the no-BTF 4.14) and 2023, and
  openSUSE Leap — documented in `docs/case-study-enterprise-kernels.md`.
- **SLSA build provenance + SBOM attestations** on tag releases
  (keyless OIDC via Sigstore/Rekor), with a verification guide
  (`docs/verifying-releases.md`).
- **Weekly stability gate** (`.github/workflows/stability-gate.yml`) producing an
  archived READY/NOT-READY readiness report.
- **Self-hosted health watchdog** for the demo (`scripts/healthcheck.sh` +
  `packaging/systemd/bpfcompat-healthcheck.{service,timer}`) and a runbook
  monitoring section.
- **Docs:** evidence-schema reference (`docs/evidence-schema.md`), self-hosted-first
  quickstart + trust model (`docs/quickstart.md`), and the Falco modern_bpf
  reference matrix (`docs/case-study-falco-modern-bpf.md`).
- **Demo UI:** Carbon design tokens matching the marketing site, light/dark
  toggle, example matrix on load, live "watch it boot" matrix, shareable compat
  badge (`/badge/<run_id>.svg`) + OG social cards on `/results`, one-click live
  example, and an in-page How-it-works/FAQ/source footer.

### Fixed
- EL/Amazon/SUSE guests now seed cloud-init via a CIDATA ConfigDrive ISO instead
  of the SMBIOS-net seed their cloud-init ignores (fixes EL8 boot/SSH); bootstrap
  installs `cloud-image-utils`. Enabled Amazon Linux 2 (4.14) validation.
- Redacted absolute host audit paths (`trace_path`, `event_stream_path`) from
  public runtime decision/select/fetch responses.
- Validate UI blocks submitting with no artifact instead of a raw 400.

## [0.1.5] - 2026-06-11

### Fixed
- `action.yml` was invalid YAML from v0.1.4 (unquoted colon in the
  `validation-mode` description), which broke every consumer of the
  published action at job setup. The description is now quoted and CI
  parses `action.yml` plus all workflow files on every push so a broken
  tag cannot ship again.

### Added
- Manifest `program_variants:` groups for loaders that ship multiple
  programs per event and select one at load time: variants gate on a BPF
  helper (`requires_helper: bpf_loop` or numeric id) or on an isolated
  `probe: trial_load` with `probe_companions:` kept autoloaded (mirroring
  Falco's helper-gated exit programs and trial-probed BPF iterators). The
  chosen/disabled variant per kernel is recorded in the validator JSON and
  report notes. With these plus map fixups, Falco's modern_bpf probe passes
  as shipped on Ubuntu 22.04 (5.15), with `recvmmsg_old_x`/`sendmmsg_old_x`
  selected and `dump_task` correctly detected unsupported.
- Image integrity for reproducible matrices: every cached image gets a
  sha256 sidecar recorded on first use and surfaced as a target note
  (`base image sha256: …`); profiles can pin `image.sha256` to fail runs on
  mismatching downloads. `docs/image-pipeline.md` documents the full image/
  profile pipeline: sources, caching, audits, generated lanes, and how to
  add a profile.

### Fixed
- The validator no longer truncates verifier output: libbpf emits a failed
  program's whole log as one print call, and the old 2 KiB per-call buffer
  cut the verdict off the end. Isolated per-program probes on objects with
  statically initialized prog-array slots are reported as `skipped` instead
  of misleading EBADF failures.

## [0.1.4] - 2026-06-11

### Added
- Web gate now includes a sticky readiness snapshot, clearer target/BPF/gate
  workflow, explicit load-only/load+attach test intent, and a collection-first
  suite preview with generated CLI and GitHub Action snippets.
- Result view now leads with the gate decision and required/optional pass/fail
  matrix before technical JSON, history, compare, or runtime evidence.
- Production Runtime Agent Alpha reviewed-load path now supports operator
  approval pins for decision ID and artifact SHA-256, manifest-intent
  enforcement, preflight checks for both, and persisted evidence in
  `last-load.json` plus the agent load ledger.
- Manifest `maps:` fixups for runtime-sized maps: `max_entries` (integer or
  `cpus`) and `inner_ringbuf_bytes` mirror what an artifact's own loader does
  before load, so skeleton-style probes that compile maps with
  `max_entries=0` (for example Falco's `modern_bpf`) can be validated
  as shipped. Per-fixup outcomes are recorded in the validator JSON and
  report notes.
- `suites/example-collection.yaml`: a realistic collection (two exec-tracer
  variants, two upstream OSS programs, one behavior case) against the MVP
  matrix; the README now leads with the collection/suite workflow and splits
  the documentation map into user guide vs internal evidence.
- The GitHub Action downloads checksum-verified prebuilt binaries from the
  release matching its pinned tag (new `prebuilt` input, default `auto`)
  instead of compiling Go and the static validator on every CI run;
  `release-artifacts.yml` builds and attaches `bpfcompat-linux-amd64`,
  `bpfcompat-validator-static-linux-amd64`, and `SHA256SUMS` to tag releases.

### Changed
- Packaged `bpfcompat-agent-load.service` now fails closed by default unless
  reviewed approval pins and a valid manifest are supplied.
- Agent load policy documentation now treats host loading as a reviewed,
  local-policy-controlled path rather than part of the public web/API demo.

## [0.1.2] - 2026-06-05

### Added — web UX and Marketplace
- Main web UI now centers the Samy/Falco workflow: select targets, provide a
  BPF object or suite, choose test intent, run the gate, then read a clear
  pass/fail matrix before opening drill-down evidence.
- Collection/suite mode explains the CI-first path and generates a GitHub
  Action snippet for self-hosted Linux/KVM runners.
- Compatibility results now show required/optional count tiles and
  color-coded pass/fail status pills.
- Advanced history, compare, and runtime decision proof is lazy-loaded only
  when the advanced evidence drawer is opened.
- Responsive CSS improves the main workflow on narrow/mobile screens.

### Added — security hardening (P0)
- Added Apache-2.0 `LICENSE` and `SECURITY.md` disclosure policy.
- HTTP server now sets `ReadHeaderTimeout`, `ReadTimeout`, `IdleTimeout`, and
  `MaxHeaderBytes` so slow-loris or oversized-header clients can't park
  resources.
- New `decodeJSONBody` helper caps JSON request bodies at 1 MiB via
  `http.MaxBytesReader`, rejects unknown fields, and refuses trailing JSON
  smuggling.
- `TokenGrant` gained optional `NotBefore` and `ExpiresAt` fields so
  cloud-registry credentials can be time-bounded at rest.
- Cloud-registry audit log and runtime-decision log now rotate by size
  (`BPFCOMPAT_REGISTRY_AUDIT_MAX_BYTES` /
  `BPFCOMPAT_RUNTIME_DECISIONS_MAX_BYTES`) and retain a bounded number of
  shards (`BPFCOMPAT_REGISTRY_AUDIT_MAX_FILES` /
  `BPFCOMPAT_RUNTIME_DECISIONS_MAX_FILES`). Listing endpoints merge across
  shards.
- Structured logging via `log/slog` with per-request ID middleware. The
  request ID is read from `X-Request-Id` (or generated) and propagated
  through context + response header + every log line.
- Prometheus metrics surface gated by `BPFCOMPAT_API_ENABLE_METRICS`.
  Exposed at `/metrics` behind read auth.

### Added — production polish (P1)
- `bpfcompat version [--json]` subcommand and ldflags-injected build identity.
- `/livez` and `/readyz` Kubernetes-style probes.
- Graceful shutdown drains in-flight validate jobs
  (`BPFCOMPAT_API_SHUTDOWN_DRAIN_TIMEOUT`); new submissions get 503 during
  drain.
- `BPFCOMPAT_API_TRUSTED_PROXIES` configures CIDR allowlist for
  X-Forwarded-For. `client_ip` is logged on every request when configured.
- Validator binary resolution now searches
  `/usr/libexec/bpfcompat/bpfcompat-validator` first, with
  `BPFCOMPAT_VALIDATOR_BIN` override and optional `BPFCOMPAT_VALIDATOR_SHA256`
  integrity check.
- API routes registered under both `/api/v1/<route>` (canonical) and the
  legacy `/api/<route>` alias. The legacy alias is scheduled for removal in
  a future minor release.
- OpenAPI 3.1 spec checked in at `docs/openapi.yaml` and served from
  `/api/openapi.yaml` (and `/api/v1/openapi.yaml`).
- CI workflow (`.github/workflows/ci.yml`) running `go vet`, `go test -race
  -cover`, `golangci-lint`, `govulncheck`, and `go build`.
- `.golangci.yml` enforces errcheck/gosec/staticcheck/errorlint/contextcheck/
  bodyclose/noctx and friends.
- Release workflow (`.github/workflows/release-artifacts.yml`) produces
  CycloneDX SBOMs and cosign-signed binaries on tag pushes.
- Per-response CSP `nonce-<base64>` on the UI route; JSON routes get a
  `default-src 'none'` baseline.
- Fuzz tests for the manifest, matrix, and JWT parsers; route normalizer.

### Added — engineering excellence (P2)
- `Dockerfile` (distroless final stage, non-root) and `.dockerignore`.
- `CHANGELOG.md` and `CONTRIBUTING.md`.

### Changed
- Default `Strict-Transport-Security` header is now only emitted when TLS is
  enabled. Plain-HTTP deployments no longer mislead clients with a header
  they can't honor.
- `enforceWriteIdentityTenantProject` and `enforceWriteIdentityTenant` now
  reject JWTs that carry no `tenant` or `projects` claim. **Breaking** for
  any deployment relying on the prior lenient behaviour; reissue tokens with
  explicit scope claims before upgrading.
- JWKS and OIDC discovery URLs must be `https://`. **Breaking** for any
  deployment misconfigured with plaintext JWKS sources.

### Security
- Critical: shell command injection in the VM validation flow via uploaded
  filename → guest-VM RCE. Filename allowlist now strict (`^[A-Za-z0-9._-]+$`).
- High: unauthenticated read endpoints (`/api/validate/status`,
  `/api/history/*`, `/api/runtime/probe`, `/api/runtime/decisions`) now
  require auth; `shortID` switched to `crypto/rand`.
- High: SSRF guard on `artifact_uri` fetch rejects loopback / RFC1918 /
  link-local / CGNAT / cloud-metadata IPs by default. Override via
  `BPFCOMPAT_FETCH_ALLOW_INTERNAL_HOSTS=true` (intentionally opt-in).
- Medium: cloud-registry tokens can be stored hashed at rest via
  `TokenHash` + `TokenHashSalt`. `HashTokenGrant` helper generates them.
- Medium: error responses now redact filesystem paths when
  `BPFCOMPAT_API_REDACT_RUNTIME_DETAILS` is true (default).
- Low: RSA keys from JWKS rejected if modulus &lt; 2048 bits; `bpftool`
  resolves to an absolute path before sudo invocation; `sudo --` separator
  added in worker command construction.

## [0.1.0-dev]

Initial public-facing development release.
