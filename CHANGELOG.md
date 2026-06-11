# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a
1.0 release is cut.

## [Unreleased]

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
