# Threat Model

This document is the STRIDE-style threat model for the `bpfcompat` API
server, validator, and registry. It complements `docs/security-model.md`
(which captures policy) and `docs/security-review-report.md` if/when
generated. Re-read after any change that touches authentication,
artifact handling, the runtime-execute path, or the cloud registry.

## Assets

| Asset                              | Why it matters                                                  |
| ---                                | ---                                                             |
| Validator artifacts (`.bpf.o`)     | Untrusted code; loaded into kernels of test guests              |
| Artifact registry hash chain       | Provides supply-chain provenance; tampering breaks trust        |
| `tokens.json` token grants         | Authenticate write/read access                                  |
| Cloud-registry audit log           | Forensic record of all artifact mutations                       |
| Validator binary (`validator`)     | Runs inside guests with elevated privs                          |
| Runtime-execute approval token     | Last-line gate for loading BPF on the host kernel               |
| TLS server cert + key              | Confidentiality + integrity of API traffic                      |
| mTLS client CA bundle              | Trust anchor for service-to-service auth                        |
| Signing keys (artifact + audit)    | Anchor non-repudiation of registry events                       |

## Trust boundaries

1. **Internet ↔ API server** — every HTTP request crosses here. Defenses:
   read/write auth, rate limit, body cap, SSRF guard on fetch endpoints.
2. **API server ↔ VM guests** — artifacts copied in, reports copied out.
   Guests are disposable; the boundary is QEMU/KVM isolation.
3. **API server ↔ host kernel** — only the runtime-execute worker crosses
   this boundary; gated by `BPFCOMPAT_API_ENABLE_RUNTIME_EXECUTE`,
   approval token, policy file, and a dedicated worker user.
4. **API server ↔ remote artifact URI** — `runtime fetch`; SSRF guard
   restricts to public/explicitly allow-listed networks.
5. **Operator ↔ workdir** — `bpfcompat admin` runs on the host that owns
   the workdir; trust is implicitly host-shell-level.

## STRIDE walk

### Spoofing identity

| Threat                                           | Mitigation                                                                                                                              |
| ---                                              | ---                                                                                                                                     |
| Forged API key                                   | Constant-time compare; rotate via `tokens.json` + `admin revoke-token`                                                                  |
| Replayed JWT                                     | NotBefore/ExpiresAt enforced (`grantValidityWindow`); JWKS refresh cooldown bounds key roll latency                                     |
| Spoofed mTLS client                              | `RequireAndVerifyClientCert` + pinned CA pool + explicit `BPFCOMPAT_API_MTLS_IDENTITY_MAP_PATH` authorization mapping                  |
| Audit log forgery (post-export)                  | `bpfcompat admin audit-export --sign-key` produces detached Ed25519 envelope; verifier requires a pinned public key by default          |

### Tampering with data

| Threat                                            | Mitigation                                                                                              |
| ---                                               | ---                                                                                                     |
| Mutated artifact in registry                      | Hash-chained `artifact_versions.jsonl` + Ed25519 signature on every record (`VerifyArtifactVersionHistory`) |
| Modified `tokens.json` mid-operation              | Atomic rename in `WriteAuthConfig`; admin tooling never partially writes                                |
| Modified audit export file                        | sha256 in signature envelope must match recomputed digest                                               |
| Tampered validator binary                         | `BPFCOMPAT_VALIDATOR_SHA256` integrity check before exec                                                |

### Repudiation

| Threat                                | Mitigation                                                                                                                       |
| ---                                   | ---                                                                                                                              |
| "I didn't load that artifact"         | Runtime decisions log (`runtime_decisions.jsonl`) records artifact hash, actor, approval token user, decision                    |
| "I didn't approve that registry push" | Cloud-registry audit log records actor, action, tenant/project, artifact name+version, status                                    |
| "I didn't pull that profile"          | pprof endpoint runs under read auth; access log line includes `request_id`, `trace_id`, identity subject when present            |

### Information disclosure

| Threat                                  | Mitigation                                                                                                                |
| ---                                     | ---                                                                                                                       |
| Token leak via list-tokens              | `admin list-tokens` emits redacted summaries; plaintext field never reaches output (regression test pinned)               |
| pprof exposes goroutine stacks          | `BPFCOMPAT_API_ENABLE_PPROF=false` by default; when on, strict API-key/JWT auth is required and anonymous demo modes are ignored |
| TLS downgrade with mTLS configured      | Server refuses to start if `CLIENT_CA_PATH` set without `TLSCertPath/Key`                                                 |
| SSRF via runtime fetch                  | Private IP block-list + redirect re-validation; opt-in `fetchAllowInternalEnv` only for tests                             |
| Verbose error leaks internal state      | `httpError` sanitizes 5xx detail; sensitive paths log via slog at `Debug`/`Info` rather than wire body                    |

### Denial of service

| Threat                                  | Mitigation                                                                                                                  |
| ---                                     | ---                                                                                                                         |
| Slowloris / unbounded request           | `ReadHeaderTimeout=10s`, `ReadTimeout=5m`, `MaxHeaderBytes=64KB`, JSON body capped at 1 MiB                                 |
| Validate-job flood                      | Active + queued caps (`MAX_ACTIVE_VALIDATE_JOBS`, `MAX_QUEUED_VALIDATE_JOBS`); 429 on overrun                              |
| Audit log unbounded growth              | Rotation: 64 MiB × 10 shards default (`AppendAudit` → `rotateAuditLogIfNeeded`)                                            |
| Cloud-registry burst                    | Per-tenant rate limiter; drops recorded in `bpfcompat_registry_rate_limit_drops_total`                                     |

### Elevation of privilege

| Threat                                 | Mitigation                                                                                                                  |
| ---                                    | ---                                                                                                                         |
| API caller loads BPF on host kernel    | Runtime-execute gated by env, approval token, policy, dedicated worker user                                                 |
| Validator escape from VM               | Guests treated as untrusted; ssh transports artifacts only; no shared filesystem with host                                  |
| Identity assertion from forged headers | `clientIP()` only honors `X-Forwarded-For` for peers inside `BPFCOMPAT_API_TRUSTED_PROXIES`; mTLS CN comes from verified chain |

## Out of scope

- Side-channel attacks against the host kernel or QEMU/KVM.
- Multi-tenant isolation inside a single VM guest (we use disposable guests).
- Confidentiality of the workdir against root on the host (operator trust).
- Network-level DDoS (assumed handled by upstream LB/CDN).

## Review cadence

Re-run this walk:
- After any change to auth, fetch, or runtime-execute paths.
- Before cutting a minor release.
- After any reported vulnerability (per `SECURITY.md`).
