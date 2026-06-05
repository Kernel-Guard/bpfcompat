# Control Mapping

This file maps common SOC 2 / ISO 27001 control families to the specific
code paths, env knobs, and operational evidence in this repo. It is
**not** a SOC 2 audit report; it's a cheat sheet so a security reviewer can
locate evidence quickly without grepping the whole tree.

Last reviewed: 2026-05-28.

## CC6.1 — Logical access controls

| Sub-control                      | Where implemented                                              | Evidence                                    |
| ---                              | ---                                                            | ---                                         |
| Authentication required          | `internal/api/write_auth.go::requireWriteAuthorization`        | 401 on unauthenticated requests             |
| MFA-equivalent (mTLS option)     | `internal/api/mtls.go` + `BPFCOMPAT_API_CLIENT_CA_PATH` + `BPFCOMPAT_API_MTLS_IDENTITY_MAP_PATH` | TLS handshake rejects unverified clients; API auth requires an explicit identity-map grant |
| Identity federation              | JWT verification (HS256/RS256/JWKS/OIDC) in `write_auth.go`    | `writeJWTVerificationConfigFromEnv`         |
| Least-privilege scoping          | `Principal.CanRead/CanWrite` + per-action JWT claim gates      | `requireRegistryIdentityForAction`          |

## CC6.2 — Provisioning / deprovisioning

| Sub-control                       | Where implemented                                                   | Evidence                                 |
| ---                               | ---                                                                 | ---                                      |
| Granting access                   | `cloudregistry.Store.WriteAuthConfig` + operator edits to tokens.json | Atomic rename; schema-versioned         |
| Revoking access                   | `bpfcompat admin revoke-token --subject ... --tenant ...`           | Non-zero exit on unknown subject         |
| Token rotation                    | `TokenGrant.NotBefore` / `ExpiresAt`                                | Expiry enforced in `grantValidityWindow` |
| Access review                     | `bpfcompat admin list-tokens --json`                                 | Redacted listing; no plaintext leakage   |

## CC6.6 — Encryption in transit

| Sub-control                       | Where implemented                                              | Evidence                                  |
| ---                               | ---                                                            | ---                                       |
| TLS 1.2 minimum                   | `tlsConfigForServer` sets `MinVersion: VersionTLS12`           | `internal/api/mtls.go`                    |
| HSTS                              | `withSecurityHeaders` emits HSTS only when TLS is on           | `TestServerTLSConfig`                     |
| mTLS for service-to-service       | `BPFCOMPAT_API_CLIENT_CA_PATH` + `RequireAndVerifyClientCert`  | Refuses startup if mTLS configured w/o TLS |

## CC7.2 — System monitoring / detection

| Sub-control                       | Where implemented                                              | Evidence                                       |
| ---                               | ---                                                            | ---                                            |
| Structured audit logs             | `cloudregistry.AppendAudit` writes JSONL with rotation         | `<workdir>/cloud-registry/audit/events.jsonl`  |
| Runtime decision audit            | `runtime/audit.go` writes `runtime_decisions.jsonl`            | Rotation by size + shard count                 |
| Metrics for alerting              | Prometheus exposition under `/metrics` (opt-in)                 | `bpfcompat_*` counters in `internal/api/metrics.go` |
| Request correlation               | `X-Request-Id` + W3C `traceparent` echo                        | `loggerFromContext` surfaces trace ids         |

## CC7.3 — Incident response

| Sub-control                       | Where implemented                                              | Evidence                                  |
| ---                               | ---                                                            | ---                                       |
| Disclosure channel                | `SECURITY.md`                                                  | GitHub private vulnerability reporting    |
| Incident playbook                 | `docs/incident-response-runbook.md`                            | Versioned in repo                         |
| Audit export for forensics        | `bpfcompat admin audit-export --sign-key ... --sig-out ...`    | Ed25519 detached signature                |
| Audit verification                | `bpfcompat admin audit-verify --input ... --sig ...`           | sha256 + signature both checked           |

## CC8.1 — Change management

| Sub-control                       | Where implemented                                              | Evidence                                  |
| ---                               | ---                                                            | ---                                       |
| Code review required              | Branch protection (configured at GitHub repo level)            | Not in repo; check repo settings          |
| CI gate on build/test             | `.github/workflows/ci.yml` (vet, race tests, lint, govulncheck) | Run on every PR                          |
| Provenance for artifacts          | `internal/registry/history.go` hash-chained + signed records   | `VerifyArtifactVersionHistory`            |
| Reproducible builds               | `go build -trimpath -ldflags` in Makefile                      | Version stamped in binary                 |

## CC9.1 — Risk mitigation / vendor mgmt

| Sub-control                       | Where implemented                                              | Evidence                                  |
| ---                               | ---                                                            | ---                                       |
| Dependency vulnerability scanning | `govulncheck` step in CI                                       | `.github/workflows/ci.yml`                |
| SBOM                              | CycloneDX SBOM produced on tag                                 | `.github/workflows/release-artifacts.yml` |
| Artifact signing                  | cosign on tagged release artifacts                             | Same workflow                             |
| Threat modeling                   | `docs/threat-model.md`                                         | Versioned in repo                         |

## Notes for auditors

- `tokens.json` is operator-managed; the repo never commits real tokens.
- Audit retention defaults to 64 MiB × 10 shards; tune via
  `BPFCOMPAT_REGISTRY_AUDIT_MAX_BYTES` / `BPFCOMPAT_REGISTRY_AUDIT_MAX_FILES`
  and `BPFCOMPAT_RUNTIME_DECISIONS_MAX_BYTES` / `BPFCOMPAT_RUNTIME_DECISIONS_MAX_FILES`.
- mTLS client certificates must match an explicit identity-map grant; rotate
  certs via your CA workflow and restart the API when the CA bundle changes.
- All env knobs are catalogued in `docs/env-reference.md` (auto-generated
  from `internal/envref/envref.go`; CI fails on drift).
