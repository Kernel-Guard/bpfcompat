# Web UI + API (Phase 1/2 + Registry MVP)

`bpfcompat serve` provides a local web interface and HTTP API for:

1. uploading `.bpf.o` artifacts or `.bpf.c` source,
2. selecting distro/kernel target profiles,
3. running VM-backed validation,
4. exporting compatibility report JSON through API responses,
5. tracking artifact version history,
6. comparing compatibility between artifact versions.

The web UI is intentionally optimized for the primary compatibility workflow:

1. name the artifact,
2. upload or compile one BPF object,
3. select target kernels,
4. run the compatibility gate,
5. read the pass/fail matrix first, then open drill-down evidence only when
   needed.

For projects that ship collections of BPF objects/programs, use suite mode in
the CLI or GitHub Action. The web UI remains a single-artifact demo and local
inspection surface.

## Start

```bash
make build
make validator-static
BPFCOMPAT_API_WRITE_KEY=dev-write-key ./bin/bpfcompat serve --addr :8080 --workdir .bpfcompat --matrix matrices/mvp.yaml
```

For local demos:

```bash
make serve
```

(`make serve` auto-sets `BPFCOMPAT_API_WRITE_KEY=dev-write-key` if unset.)

Open:

- `http://127.0.0.1:8080`
- `http://127.0.0.1:8080/results` (mobile-friendly latest result snapshot)

## Endpoints

- `GET /results`
- `GET /demo-result`
- `GET /api/health`
- `GET /api/config`
- `GET /api/profiles`
- `POST /api/validate` (multipart form)
- `GET /api/history/artifacts?artifact_name=<name>&limit=<n>`
- `GET /api/history/runs?limit=<n>`
- `GET /api/history/run-report?run_id=<run-id>`
- `POST /api/compare`
- `GET /api/runtime/probe`
- `GET /api/runtime/decisions?limit=<n>&workdir=<path>`
- `POST /api/runtime/select`
- `POST /api/runtime/fetch`
- `POST /api/runtime/execute` (JSON body, explicit `allow_host_load=true` required)
- `GET /api/registry/projects?tenant=<tenant>[&project=<project>&limit=<n>]`
- `POST /api/registry/projects`
- `POST /api/registry/artifacts/upload` (multipart form)
- `GET /api/registry/artifacts?tenant=<tenant>&project=<project>[&artifact_name=<name>&limit=<n>]`
- `GET /api/registry/artifacts/download?tenant=<tenant>&project=<project>&artifact_name=<name>&version=<v>`
- `GET /api/registry/history/verify?tenant=<tenant>&project=<project>`
- `GET /api/registry/audit/events?tenant=<tenant>[&project=<project>&limit=<n>]`

`GET /api/runtime/probe` query options (all optional):

- `prefer_privileged=true|false`
- `use_sudo=true|false`
- `sudo_non_interactive=true|false`

Runtime policy object (optional for select/fetch/execute):

```json
{
  "policy": {
    "require_summary_pass": true,
    "min_required_passed": 1,
    "max_required_failed": 0,
    "require_attach_support": true,
    "deny_classification_codes": ["UNKNOWN"],
    "allow_classification_codes": ["MISSING_BTF", "UNSUPPORTED_MAP_TYPE"]
  }
}
```

Runtime probe object (optional for select/fetch/execute):

```json
{
  "probe": {
    "prefer_privileged": true,
    "use_sudo": true,
    "sudo_non_interactive": true
  }
}
```

Runtime `select`/`fetch`/`execute` responses include:

- `correlation_id` for cross-linking API responses with runtime decision trace and registry audit events
- operation payload (`selection`, `fetch`, `execution`)
- optional `host_probe` and `selection` context where applicable
- optional `history_verification` summary (when strict history verification is enabled; default for fetch/execute)
- `audit` metadata with `decision_id`, trace file path, and event stream path
- optional `audit_error` when operation succeeds but audit persistence fails

`GET /api/profiles` includes execution-readiness hints:

- `source_mode`: `url` or `manual-local`
- `source_url`: profile image URL when available
- `transport`: execution transport (`ssh` or `unsupported`)
- `transport_supported`: whether current validator executor can run this profile
- `transport_note`: reason when transport is unsupported

UI behavior for unsupported transports:

- profiles with `transport_supported=false` are not selected by default
- "Select All" only selects transport-supported profiles

Runtime `fetch` and `execute` request fields:

- `require_verified_history` (optional, default `true`):
  - when `true`, operation fails closed if signed history verification is not clean
  - when verification fails, API returns `412 Precondition Failed`

Runtime `execute` additional required fields:

- `tenant`
- `project`

Runtime `execute` auth requirements:

- write auth (one of):
  - API key: `X-API-Key`
  - JWT identity token: `X-API-Identity-Token` (`HS256` or `RS256`), configured by:
    - `BPFCOMPAT_API_WRITE_JWT_HS256_SECRET` (HS256)
    - `BPFCOMPAT_API_WRITE_JWT_JWKS_PATH` (RS256 JWKS file path)
    - `BPFCOMPAT_API_WRITE_JWT_JWKS_URL` (RS256 JWKS URL)
    - `BPFCOMPAT_API_WRITE_JWT_JWKS_CACHE_TTL` (default `5m`)
    - `BPFCOMPAT_API_WRITE_JWT_JWKS_HTTP_TIMEOUT` (default `5s`)
    - `BPFCOMPAT_API_WRITE_JWT_OIDC_ISSUER_URL` (optional issuer discovery URL)
    - `BPFCOMPAT_API_WRITE_JWT_OIDC_DISCOVERY_CACHE_TTL` (default `10m`)
    - `BPFCOMPAT_API_WRITE_JWT_REQUIRED_SCOPES` (optional global required scopes)
    - `BPFCOMPAT_API_WRITE_JWT_REQUIRED_ROLES` (optional global required roles)
    - `BPFCOMPAT_API_WRITE_JWT_REQUIRED_SCOPES_<ACTION>` (optional per-action scopes)
    - `BPFCOMPAT_API_WRITE_JWT_REQUIRED_ROLES_<ACTION>` (optional per-action roles)
    - `BPFCOMPAT_API_RUNTIME_EXECUTE_JWT_REQUIRED_SCOPES` (optional runtime-execute-only scopes)
    - `BPFCOMPAT_API_RUNTIME_EXECUTE_JWT_REQUIRED_ROLES` (optional runtime-execute-only roles)
    - `BPFCOMPAT_API_WRITE_REQUIRE_IDENTITY=true` (fail closed)
    - optional issuer/audience checks: `BPFCOMPAT_API_WRITE_JWT_ISSUER`, `BPFCOMPAT_API_WRITE_JWT_AUDIENCE`
- execute approval token (`X-Execute-Approval-Token`)
- registry scope token in `Authorization: Bearer <token>` authorized for the request `tenant/project`
- for runtime execute, keep registry auth in `Authorization` and send write identity via `X-API-Key` or `X-API-Identity-Token`
- RS256 JWKS verification caches keys by source and performs a forced refresh retry on signature/key mismatch to handle key rotation.
- if explicit OIDC issuer URL is not set and `BPFCOMPAT_API_WRITE_JWT_ISSUER` is an `https` URL, discovery falls back to that issuer. JWKS/OIDC URL verification requires HTTPS in production.
- JWT write auth checks `scope`/`scp` claims and `roles`/`role` claims when required-scope/role env gates are configured.
- action-specific claim gates support actions `COMPARE`, `RUNTIME_SELECT`, `RUNTIME_FETCH`, `RUNTIME_EXECUTE`, `VALIDATE`, `REGISTRY_PROJECT_READ`, `REGISTRY_PROJECT_LIST`, `REGISTRY_PROJECT_UPSERT`, `REGISTRY_ARTIFACT_UPLOAD`, `REGISTRY_ARTIFACT_LIST`, `REGISTRY_ARTIFACT_DOWNLOAD`, `REGISTRY_HISTORY_VERIFY`, and `REGISTRY_AUDIT_LIST`.
- optional anonymous validate mode: `BPFCOMPAT_API_ALLOW_ANONYMOUS_VALIDATE=true` allows `POST /api/validate` without write auth and allows matching validate-status reads (other POST endpoints still require write auth).
- optional anonymous read mode: `BPFCOMPAT_API_ALLOW_ANONYMOUS_READ=true` opens history/status/runtime read endpoints for public demos.
- host load execution is delegated from API to worker process `bpfcompat runtime worker-execute`
- optional worker identity controls:
  - `BPFCOMPAT_API_RUNTIME_EXECUTE_WORKER_USER`
  - `BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_WORKER_IDENTITY=true`
- optional runtime execute policy controls:
  - `BPFCOMPAT_API_RUNTIME_EXECUTE_POLICY_PATH`
  - `BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_POLICY=true`

## Registry auth and tenancy

Registry endpoints use bearer-token auth (`Authorization: Bearer <token>`).  
Token grants are loaded from:

- `.bpfcompat/cloud-registry/auth/tokens.json`

Sample grant file:

```json
{
  "schema_version": "cloud_registry_auth.v0.1",
  "tokens": [
    {
      "token": "acme-admin-token",
      "subject": "acme-admin",
      "tenant": "acme",
      "projects": ["*"],
      "can_read": true,
      "can_write": true
    }
  ]
}
```

Optional bootstrap shortcut for local demos:

```bash
export BPFCOMPAT_REGISTRY_AUTH_TOKEN='<short-lived-bootstrap-token>'
# Optional RFC3339 validity window. Recommended even for short-lived demos.
export BPFCOMPAT_REGISTRY_AUTH_TOKEN_NOT_BEFORE='2026-05-27T00:00:00Z'
export BPFCOMPAT_REGISTRY_AUTH_TOKEN_EXPIRES_AT='2026-05-28T00:00:00Z'
```

Optional identity gate for registry endpoints:

- `BPFCOMPAT_API_REGISTRY_REQUIRE_IDENTITY=true` requires `X-API-Identity-Token` JWT on all registry endpoints.
- registry identity uses the same verifier config as write endpoints (`BPFCOMPAT_API_WRITE_JWT_HS256_SECRET`, `BPFCOMPAT_API_WRITE_JWT_JWKS_PATH`, `BPFCOMPAT_API_WRITE_JWT_JWKS_URL`, `BPFCOMPAT_API_WRITE_JWT_OIDC_ISSUER_URL`).
- per-action scope/role gates apply to registry actions with:
  - `BPFCOMPAT_API_WRITE_JWT_REQUIRED_SCOPES_<ACTION>`
  - `BPFCOMPAT_API_WRITE_JWT_REQUIRED_ROLES_<ACTION>`
- when identity token claims include `tenant` and/or `projects`, they are enforced against requested registry tenant/project scope.

Operational controls (env-configurable):

- Registry API rate limiting (per `subject+tenant+project+action`):
  - `BPFCOMPAT_REGISTRY_RATE_LIMIT_MAX_REQUESTS` (default `120`)
  - `BPFCOMPAT_REGISTRY_RATE_LIMIT_WINDOW_SECONDS` (default `60`)
- Registry project upload quotas:
  - `BPFCOMPAT_REGISTRY_MAX_ARTIFACT_BYTES` (default `67108864`)
  - `BPFCOMPAT_REGISTRY_MAX_ARTIFACT_VERSIONS_PER_NAME` (default `200`)
  - `BPFCOMPAT_REGISTRY_MAX_PROJECT_STORAGE_BYTES` (default `2147483648`)

When a request is denied by authz/rate-limit/quota, a deny audit event is appended to the registry audit stream.

For `runtime_execute`/`runtime_execute_denied`, audit metadata includes:

- `correlation_id`
- `approved_by`
- `requested_by`
- `requested_version`
- `target_profile`
- selected-version context when available
- success context such as `artifact_sha256`, `execution_status`, and `worker_identity`

Project visibility modes:

- `private`: token required for read/write
- `public`: anonymous read allowed for artifact listing/download; write still requires token

## `POST /api/validate` form fields

Required input:

- one of:
  - `artifact_file`
  - `source_file`
  - `source_code`

Optional fields:

- `manifest_file`
- `manifest_text`
- `profiles` (repeated field for selected profile IDs)
- `required_profiles` (repeated field for required IDs among selected)
- `artifact_name`
- `artifact_version`
- `artifact_variant`
- `artifact_uri` (optional canonical remote `http`/`https` URI used later by runtime fetch/execute when local paths are unavailable; `file://` is disabled by default outside explicit local proof runs)
- `timeout` (for example `8m`)
- `concurrency` (for example `2`)
- `clang_flags` (used only with source input mode)

## `POST /api/registry/projects` JSON body

```json
{
  "tenant": "acme",
  "project": "aegis-bpf",
  "visibility": "private",
  "default_matrix_path": "matrices/mvp.yaml"
}
```

## `POST /api/registry/artifacts/upload` form fields

Required:

- `tenant`
- `project`
- `artifact_name`
- `artifact_version`
- `artifact_file`

Optional:

- `artifact_variant`
- `artifact_uri`
- `artifact_sha256` (expected SHA-256 integrity check)
- `manifest_path`
- `source_run_id`
- `report_file` or `report_json` (existing validation report)
- compatibility hints when no report is provided:
  - `summary_status`
  - `required_passed`
  - `required_failed`
  - `total_profiles`
  - `matrix_path`
  - `matrix_name`
  - `supported_profiles` (repeat or comma-separated)
  - `failed_profiles` (repeat or comma-separated)
  - `classification_codes` (repeat or comma-separated)

## `POST /api/compare` JSON body

Either direct report paths:

```json
{
  "base_report": "reports/ringbuf-modern-mvp.json",
  "head_report": "reports/perfbuf-fallback-mvp.json"
}
```

Or artifact-version lookup from registry history:

```json
{
  "artifact_name": "perfbuf_fallback",
  "base_version": "v1",
  "head_version": "v2"
}
```

## Phase 2 storage layout

- run metadata index: `.bpfcompat/registry/runs.jsonl`
- artifact version history index: `.bpfcompat/registry/artifact_versions.jsonl`
- artifact history signing keys: `.bpfcompat/keys/artifact-registry-signing-key.ed25519` + `.pub`
- optional enterprise signer mode: `BPFCOMPAT_SIGNING_MODE=external-cmd` with `BPFCOMPAT_SIGNING_EXTERNAL_CMD`
- runtime decision event stream: `.bpfcompat/registry/runtime_decisions.jsonl`
- per-decision trace files: `.bpfcompat/runtime-audit/decisions/<decision-id>.json`
- per-run metadata: `.bpfcompat/runs/<run-id>/metadata.json`

Cloud-registry storage layout:

- project metadata: `.bpfcompat/cloud-registry/tenants/<tenant>/projects/<project>/project.json`
- project artifact binaries: `.bpfcompat/cloud-registry/tenants/<tenant>/projects/<project>/artifacts/**`
- project signed artifact history: `.bpfcompat/cloud-registry/tenants/<tenant>/projects/<project>/registry/artifact_versions.jsonl`
- project signing keys: `.bpfcompat/cloud-registry/tenants/<tenant>/projects/<project>/keys/*`
- registry audit stream: `.bpfcompat/cloud-registry/audit/events.jsonl`
