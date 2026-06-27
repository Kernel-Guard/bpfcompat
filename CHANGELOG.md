# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a
1.0 release is cut.

## [Unreleased]

### Added
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
- **SLSA Build L3 build-provenance + SBOM attestations** on tag releases
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
