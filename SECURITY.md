# Security Policy

## Reporting a Vulnerability

Please **do not** open public GitHub issues for security reports.

Use GitHub private vulnerability reporting for this repository. If that is not
available, contact the maintainer through their GitHub profile with:

- A description of the issue and its potential impact.
- Steps to reproduce, ideally with a minimal proof of concept.
- Affected version (`bpfcompat version`) and deployment context (CLI, API server, container).
- Any suggested remediation.

If you need encrypted transport, request a PGP key through the same private
channel.

## Response Targets

- Initial acknowledgement: within **3 business days** of receipt.
- Triage and severity assignment: within **7 business days**.
- Fix or coordinated disclosure plan: within **30 days** for High/Critical
  severity, **90 days** for Medium/Low. These windows may be extended for
  complex issues; you will be kept informed.

We follow a coordinated-disclosure model: once a fix is available we will agree
on a public-disclosure date with the reporter. Credit is offered (and gladly
given) to reporters who follow this process.

## Supported Versions

Only the latest minor release of `main` is supported with security fixes during
the current pre-1.0 phase. After 1.0, the latest minor release and the previous
minor will be supported.

## Scope

In scope:

- The `bpfcompat` CLI (`cmd/bpfcompat`).
- The `bpfcompat serve` HTTP API and embedded web UI (`internal/api`).
- The `bpfcompat-validator` C/libbpf component (`validator/c-libbpf`).
- The cloud-registry, registry, and audit subsystems (`internal/cloudregistry`,
  `internal/registry`, `internal/runtime`).
- VM execution drivers (`internal/vm`).

Out of scope (please report upstream):

- Vulnerabilities in third-party dependencies pinned in `go.mod` /
  `go.sum` — report upstream and we will pick up the fix on release.
- Vulnerabilities in QEMU, libbpf, the host kernel, or guest cloud images.
- Findings that require the operator to already have root on the host running
  `bpfcompat`.

## Hardening Guidance

Operators deploying `bpfcompat serve` should review:

- [`docs/security-model.md`](docs/security-model.md)
- [`docs/threat-model.md`](docs/threat-model.md)
- [`docs/runtime-execute-policy.md`](docs/runtime-execute-policy.md)

Required production configuration:

- TLS termination (either `--tls-cert`/`--tls-key` on `bpfcompat serve` or via
  a trusted reverse proxy).
- Configure `BPFCOMPAT_API_WRITE_KEY` or JWT identity (`BPFCOMPAT_API_WRITE_JWT_*`).
- Set `BPFCOMPAT_API_REGISTRY_REQUIRE_IDENTITY=true` and
  `BPFCOMPAT_API_WRITE_REQUIRE_IDENTITY=true` for multi-tenant deployments.
- Do **not** set `BPFCOMPAT_FETCH_ALLOW_INTERNAL_HOSTS=true` or
  `BPFCOMPAT_FETCH_ALLOW_FILE_URI=true` outside controlled environments.
- Configure JWKS / OIDC issuer URLs with `https://` only. The server rejects
  plaintext `http://` JWKS sources.
- Rotate cloud-registry tokens using the hashed-at-rest form
  (`TokenHash` + `TokenHashSalt`); see `cloudregistry.HashTokenGrant`.
- If the bootstrap registry token is enabled for a short-lived demo, bound it
  with `BPFCOMPAT_REGISTRY_AUTH_TOKEN_NOT_BEFORE` and
  `BPFCOMPAT_REGISTRY_AUTH_TOKEN_EXPIRES_AT`. Do not use the bootstrap token
  for production SaaS traffic.
- For multi-tenant SaaS deployments, ensure JWT identity tokens carry an
  explicit `tenant` claim or `projects` array. Bare tokens are now rejected.
