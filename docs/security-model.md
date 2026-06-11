# Security Model (MVP)

## Scope

The default MVP path validates untrusted `.bpf.o` artifacts inside disposable VMs.
An explicit opt-in runtime command can execute a selected artifact on the host kernel for controlled operator testing.
This is a gated runtime delivery proof, not a production runtime loading service.

## Runner policy

- Default runner is `vm`.
- `--runner host` is blocked by default.
- A hidden internal override flag (`--unsafe-allow-host-runner`) only relaxes `bpfcompat test` argument validation.
- CLI host execution is available only via `bpfcompat runtime execute` and requires explicit `--allow-host-load`.
- Pilot Beta customer-owned loading is available through `bpfcompat agent apply --approve-load`. `bpfcompat agent plan` and `bpfcompat agent apply` without `--approve-load` only probe/select/fetch/verify and do not load eBPF.
- Production Runtime Agent Alpha packaging provides a fetch-only systemd timer/service (`packaging/systemd/bpfcompat-agent.*`) with a dedicated OS user and hardened unit defaults. It runs `bpfcompat agent apply` without host-load approval by default.
- Reviewed agent host loading is isolated into `bpfcompat-agent-load.service`; it is not scheduled, runs only on operator start, requires a local agent load policy by default, and appends load attempts to the agent load ledger.
- `/api/v1/agent/decision` is a control-plane selection endpoint: it accepts the agent's target-host probe, selects a signed compatibility-verified artifact, returns registry download metadata, and never performs host loading inside the public API process.
- API runtime execution is disabled by default with `BPFCOMPAT_API_ENABLE_RUNTIME_EXECUTE=false`, requires POST API authentication, requires tenant/project registry authorization, and requires an explicit approval token (`BPFCOMPAT_API_RUNTIME_EXECUTE_APPROVAL_TOKEN`) if enabled.
- POST API authentication supports API key or signed JWT identity token (`X-API-Identity-Token`) with optional fail-closed mode (`BPFCOMPAT_API_WRITE_REQUIRE_IDENTITY=true`) and verifier config via `BPFCOMPAT_API_WRITE_JWT_HS256_SECRET` and/or `BPFCOMPAT_API_WRITE_JWT_JWKS_PATH`/`BPFCOMPAT_API_WRITE_JWT_JWKS_URL`; OIDC discovery can be driven by `BPFCOMPAT_API_WRITE_JWT_OIDC_ISSUER_URL` with HTTPS-only JWKS/OIDC transport in production; JWKS lookups are cached with refresh retry for key rotation; optional scope/role claim gates are available for global write paths, per-action write paths, and runtime-execute-specific write paths; registry endpoints can also require identity (`BPFCOMPAT_API_REGISTRY_REQUIRE_IDENTITY=true`) and use the same per-action claim gates.
- Optional demo mode can permit unauthenticated validation only (`BPFCOMPAT_API_ALLOW_ANONYMOUS_VALIDATE=true`), public read-only endpoints (`BPFCOMPAT_API_ALLOW_ANONYMOUS_READ=true`), and public runtime select/fetch proof (`BPFCOMPAT_API_ALLOW_ANONYMOUS_RUNTIME_DELIVERY=true`), while compare/registry writes/runtime execute remain authenticated or disabled.
- API runtime execution delegates host loading to a separate worker process (`bpfcompat runtime worker-execute`) and does not call host load directly inside the HTTP handler.
- API runtime execution can be pinned to a dedicated OS user with `BPFCOMPAT_API_RUNTIME_EXECUTE_WORKER_USER` and can fail closed when worker identity is missing via `BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_WORKER_IDENTITY=true`.
- API runtime execution can enforce allow/deny policy rules via `BPFCOMPAT_API_RUNTIME_EXECUTE_POLICY_PATH` (optional) and fail closed when missing with `BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_POLICY=true`.
- Agent approved loading enforces local allow/deny policy via `BPFCOMPAT_AGENT_LOAD_POLICY_PATH` / `--load-policy` and fails closed by default with `BPFCOMPAT_AGENT_REQUIRE_LOAD_POLICY=true`.
- Packaged reviewed host loading also requires operator-reviewed approval pins (`BPFCOMPAT_AGENT_EXPECTED_DECISION_ID`, `BPFCOMPAT_AGENT_EXPECTED_SHA256`, `BPFCOMPAT_AGENT_REQUIRE_APPROVAL_PINS=true`) so a load cannot silently switch to a different selected decision or artifact digest after review.
- Packaged reviewed host loading requires a valid manifest (`BPFCOMPAT_AGENT_MANIFEST_PATH`, `BPFCOMPAT_AGENT_REQUIRE_MANIFEST=true`) so host loads are tied to explicit program and attach intent.
- Agent rollback, unload, and revocation drills are available through `bpfcompat agent rollback`, `bpfcompat agent unload`, and `bpfcompat agent revocation-drill`; each can append evidence to the local load ledger.
- API runtime execute can be emergency-blocked with `BPFCOMPAT_API_RUNTIME_EXECUTE_KILL_SWITCH=true`; denied attempts are written to runtime decision audit.
- API runtime execute rejects request-level overrides for workdir/output path/manifest path/validator path/sudo options/timeout and enforces verified-history by default.

This preserves VM isolation as the normal operational path while keeping host execution behind an explicit safety gate.

## Isolation expectations

- Validation happens inside QEMU/KVM guests.
- Artifacts and manifests are copied into the guest for validator execution.
- Reports/logs are copied back to host output directories.
- Guest networking is explicit (default NICs disabled with `-nic none`) and then re-enabled only via an explicit user-mode backend and localhost SSH forwarding for orchestration.
- VM CPU and memory settings are bounded in the runner to avoid unbounded guest resource usage.
- Runtime remote artifact fetch enforces a byte-size guard (`BPFCOMPAT_FETCH_MAX_BYTES`) and SHA-256 verification. HTTP(S) fetches block loopback, link-local, private, metadata, multicast, and CGNAT destinations by default; trusted internal mirrors require explicit `BPFCOMPAT_FETCH_ALLOW_INTERNAL_HOSTS=true`. `file://` artifact URIs are disabled by default and require `BPFCOMPAT_FETCH_ALLOW_FILE_URI=true` for local proof runs.
- Artifact version history records are chained (`prev_record_sha256`) and signed with Ed25519 metadata for tamper evidence (`bpfcompat history verify`).
- `runtime fetch` and `runtime execute` require clean signed history verification by default (`--require-verified-history=true` / API `require_verified_history=true`).
- Signing supports local key mode and external signer mode (`BPFCOMPAT_SIGNING_MODE=external-cmd`) for KMS/HSM-backed integrations.
- Hostile artifact checks are exercised by `scripts/hostile-artifact-suite.sh` with archived VM evidence under `evidence/hostile-suite/<timestamp>/`.

## Non-goals for MVP

- This model does not claim full sandbox-hardening.
- Network restrictions and additional guest hardening are handled in later phases.
- This model does not claim production-safe runtime loading or production multi-tenant SaaS.
- Production claims are blocked until `docs/production-runtime-saas-gate.md` passes.
