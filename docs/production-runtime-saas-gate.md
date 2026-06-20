# Production Runtime Loading and SaaS Gate

As of: 2026-06-03

This gate defines when the project may claim production-safe runtime loading or production multi-tenant SaaS. Until both tracks pass, use these terms:

- Runtime loading: gated runtime delivery proof
- Hosted app: technical preview/demo
- Multi-tenant SaaS: registry foundation only
- Production claim: blocked until this gate passes

## Reference Basis

- NIST Zero Trust Architecture: https://csrc.nist.gov/pubs/sp/800/207/final
- NIST Secure Software Development Framework: https://csrc.nist.gov/pubs/sp/800/218/final
- Azure multitenancy checklist: https://learn.microsoft.com/en-us/azure/architecture/guide/multitenant/checklist
- SLSA provenance model: https://slsa.dev/spec/v1.2/provenance

## Current State

Already done for technical preview:

- POST API actions require `BPFCOMPAT_API_WRITE_KEY`.
- Public runtime execute API is disabled by default with `BPFCOMPAT_API_ENABLE_RUNTIME_EXECUTE=false`.
- API runtime execute requires an explicit approval token (`BPFCOMPAT_API_RUNTIME_EXECUTE_APPROVAL_TOKEN`) when enabled.
- API runtime execute supports an emergency kill-switch (`BPFCOMPAT_API_RUNTIME_EXECUTE_KILL_SWITCH`) and records denied attempts in runtime decision audit.
- API runtime execute rejects request-level runtime path and privilege overrides.
- Runtime execute negative-path API tests cover cross-tenant token denial, tampered history denial, unsigned history denial, and kill-switch denial.
- API runtime execute delegates host-load step to worker subprocess `bpfcompat runtime worker-execute` (configurable via `BPFCOMPAT_API_RUNTIME_EXECUTE_WORKER_BINARY`).
- Worker subprocess can run as dedicated OS user via `BPFCOMPAT_API_RUNTIME_EXECUTE_WORKER_USER`, with fail-closed identity gate via `BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_WORKER_IDENTITY=true`.
- API runtime execute supports optional policy rules (`BPFCOMPAT_API_RUNTIME_EXECUTE_POLICY_PATH`) with fail-closed requirement mode (`BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_POLICY=true`).
- Runtime API responses redact sensitive runtime details by default with `BPFCOMPAT_API_REDACT_RUNTIME_DETAILS=true`.
- HTTPS, security headers, and a Technical Preview UI banner are enabled on the public demo.
- Runtime fetch/execute enforce signed artifact-history verification by default.
- Runtime decision traces and event streams are persisted for audit.
- Runtime execute allow/deny registry audit events now carry correlation ID plus requester/approver metadata for traceability.
- Pilot Beta agent path exists: `bpfcompat agent plan/apply` probes the customer host, requests `/api/v1/agent/decision`, fetches the selected object with registry authorization, verifies SHA-256, and skips host load unless `--approve-load` is set.
- Production Runtime Agent Alpha packaging exists: `packaging/systemd/bpfcompat-agent.service`, `packaging/systemd/bpfcompat-agent.timer`, and `scripts/install-agent-systemd.sh` install a fetch-only host agent with a dedicated OS user, hardened systemd defaults, a stable `last-apply.json`, and `bpfcompat agent status` health output.
- Reviewed host loading is split into `bpfcompat-agent-load.service`; it is not timer-driven, requires a local default-deny agent load policy by default, and appends to `agent-load-ledger.jsonl`.
- Production runtime drills now exist: `bpfcompat agent rollback`, `bpfcompat agent unload`, and `bpfcompat agent revocation-drill` record operator-testable rollback, unload, and host-identity revocation evidence.
- `/api/v1/agent/decision` selects using the agent-submitted target-host probe and does not load eBPF inside the public API process.
- POST API write path now supports signed JWT identity tokens (`X-API-Identity-Token`) with optional fail-closed identity mode (HS256 or RS256 via JWKS path/URL with cache-refresh key rotation support) and configurable scope/role claim gates.
- Registry endpoints can require JWT identity with `BPFCOMPAT_API_REGISTRY_REQUIRE_IDENTITY=true`, and per-action scope/role claim gates apply to registry operations.

Generated technical evidence is intentionally local and ignored by git. Recreate
the current evidence set with:

```bash
make acceptance
make runtime-selector-proof
make runtime-delivery-proof
make beta-tech-check
make production-tech-check
make production-runtime-drill
make azure-production-boundary-proof
```

Still not production:

- Azure-managed identity and Key Vault boundary proof can be generated, but no production customer tenant identity provider or OIDC-backed user/service-account model is complete yet.
- No isolated runtime worker/agent boundary for production host loading.
- No production KMS/HSM signer operation or monitored signer SLO.
- No full tenant isolation proof across storage, reports, audit, secrets, jobs, and runtime decisions.
- Controlled rollback, unload, and revocation drill evidence exists locally; customer identity-provider, tenant backup/restore, and offboarding drills are still missing.
- ~~No SLSA-style build provenance for `bpfcompat` and validator binaries.~~ Done: SLSA Build L3 build-provenance + SBOM attestations are generated on tag releases (`release-artifacts.yml`); verification in `docs/verifying-releases.md`.

## Runtime Loading Production Gate

Production-safe runtime loading is `PASS` only when every P0 and P1 requirement below has passing evidence.

| Severity | Requirement | Required Evidence | Status |
|---|---|---|---|
| P0 | Runtime execute is never performed by the public API process. | Architecture doc + deployment config showing API -> worker/agent handoff. | complete |
| P0 | Runtime load happens only through an isolated worker/agent boundary. | Worker isolation design + proof run. | partial; customer-owned agent path, fetch-only systemd alpha, separate reviewed load unit, and rollback/unload drills exist |
| P0 | Runtime execute requires authenticated identity, tenant/project authorization, server-side enablement, and explicit operator approval. | Authz tests for allow, deny, and missing approval. | partial |
| P0 | Request bodies cannot supply arbitrary artifact, validator, manifest, output, or filesystem paths for production execution. | API/schema validation tests. | partial |
| P0 | Artifact passes signed metadata verification, SHA-256 verification, policy evaluation, and audit creation before load. | Tampered, unsigned, denied-policy, and valid-load tests. | partial; agent approved-load path now requires local policy by default and writes denied-load audit/ledger evidence |
| P0 | Kill-switch blocks a previously valid runtime execute request. | Kill-switch test result. | complete |
| P0 | Audit records include requester, approver, tenant/project, artifact digest, selected version, policy result, target, execution result, and correlation ID. | Example allow/deny audit records. | partial; agent load ledger now records selected digest, policy result, previous load, rollback/unload/revocation drills |
| P0 | Unauthorized, tampered, unsigned, cross-tenant, and kill-switch-denied execute attempts fail before host load. | Negative-path test suite. | complete |
| P1 | External signer is backed by KMS/HSM or equivalent managed key service. | Signer integration doc + rotation test. | partial; Azure Key Vault ES256 sign/verify can be regenerated with `make azure-production-boundary-proof`, but signer rotation and Managed HSM/customer-KMS operation are not complete |
| P1 | Build provenance exists for `bpfcompat` and validator binaries. | SLSA-style provenance artifact for release build. | not-started |
| P1 | Runtime policy supports allow/deny by tenant, artifact, hook/program type, kernel range, profile, and required signature status. | Policy tests and sample policy file. | partial; API and agent policy paths cover these fields, plus agent allow/revoke identity lists |
| P1 | Per-host worker identity is unique, least-privileged, and revocable. | Identity/RBAC design + revocation test. | partial; Azure VM managed identity and temporary managed-identity revocation checks can be regenerated with `make azure-production-boundary-proof` |
| P1 | Rollback and incident response drills are documented and tested. | Drill notes linked from incident runbook. | partial; controlled local drill evidence exists at `evidence/production-runtime-drills/20260602T223121Z/production-runtime-drill.md`, but a customer incident drill is still required |

Runtime loading gate result: **FAIL**

Blocking reason: runtime execute remains a controlled proof path. The API now hands off host load to a worker subprocess and the Pilot Beta agent keeps loading on the customer host behind a local policy, ledger, and rollback/unload/revocation drills. The local production-runtime drill proves rollback planning, safe unload behavior, and revoked-host denial without live eBPF loading, but production still requires customer-specific identity issuance/rotation and broader field evidence.

## Multi-Tenant SaaS Production Gate

Production SaaS is `PASS` only when every P0 and P1 requirement below has passing evidence.

| Severity | Requirement | Required Evidence | Status |
|---|---|---|---|
| P0 | Tenant model defines tenant, project, user, service account, role, and grant. | Tenant identity model doc. | partial |
| P0 | Every request resolves exactly one tenant context before accessing tenant data. | Request auth middleware tests. | partial |
| P0 | Cross-tenant read/write tests exist and pass. | Negative-path tests for registry, reports, artifacts, audit, and runtime decisions. | partial |
| P0 | Tenant isolation covers artifact blobs, registry metadata, reports, audit events, secrets, runtime decisions, and validation jobs. | Isolation design + storage layout evidence. | partial |
| P0 | Public write APIs use identity-backed auth, not a shared demo API key. | OIDC/API-token design and tests. | partial |
| P0 | Per-tenant quotas exist for uploads, storage, validation jobs, runtime decisions, and write rate. | Quota tests and tenant config sample. | partial |
| P0 | Tenant audit log is exportable and append-only enough for controlled use. | Audit export sample. | partial |
| P0 | Backup/restore is tested for a single tenant. | Restore drill result. | partial; Azure Blob version restore proof exists for artifact storage, but tenant-wide restore is still missing |
| P0 | Tenant deletion/export/offboarding process is documented. | Offboarding checklist. | not-started |
| P1 | Tenant tiers are defined: `demo`, `preview`, `enterprise`. | Tier matrix. | not-started |
| P1 | Noisy-neighbor controls exist for workers, storage, queues, and API rate limits. | Load/abuse test evidence. | not-started |
| P1 | Per-tenant SLO/SLI model exists. | SLO runbook update and dashboard sample. | not-started |
| P1 | Platform admin access is separated from tenant access. | Role matrix and authorization tests. | not-started |
| P1 | Monitoring shows tenant health, error rate, queue depth, storage use, denied requests, and worker failures. | Dashboard/runbook evidence. | not-started |
| P1 | DNS/TLS ownership process avoids dangling DNS/subdomain takeover risk. | Domain lifecycle checklist. | not-started |
| P1 | Security review checklist exists before first external deployment. | Security review checklist. | not-started |

Multi-tenant SaaS gate result: **FAIL**

Blocking reason: the current tenant/project registry is a foundation, but production SaaS still needs identity-backed auth, stronger isolation proof, tenant lifecycle operations, and production observability.

## Public Interface Classification

Current controls:

- `BPFCOMPAT_API_WRITE_KEY`: preview write gate only, not production SaaS authentication.
- `BPFCOMPAT_API_ENABLE_RUNTIME_EXECUTE`: must remain `false` on public demos.
- `BPFCOMPAT_API_REDACT_RUNTIME_DETAILS`: must remain `true` on public demos.
- `tenant/project` registry fields: registry foundation only, not full tenant isolation proof.

Future production interfaces must be designed before implementation:

- identity-backed tenant authorization
- runtime worker request and approval schema
- runtime policy decision schema
- tenant audit export format
- provenance verification result schema

## Minimum Evidence Before Production Claims

The project may claim production-safe runtime loading only after:

- runtime loading gate result is `PASS`
- kill-switch test passes
- tampered/unsigned/cross-tenant execute tests fail before host load
- external signer rotation is tested
- runtime allow and deny audit records are archived

The project may claim production multi-tenant SaaS only after:

- SaaS gate result is `PASS`
- cross-tenant tests pass
- tenant backup/restore and offboarding drills are complete
- identity-backed auth replaces shared demo write key
- tenant SLO/dashboard evidence exists
