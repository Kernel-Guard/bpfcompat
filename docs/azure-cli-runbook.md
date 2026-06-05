# Azure CLI Runbook

This runbook provisions and bootstraps an Azure VM for `bpfcompat` validation work using Azure credits.

## 1) Login and subscription

```bash
az login --use-device-code
az account list --output table
az account set --subscription "<subscription-id>"
```

## 2) Provision VM

Defaults are tuned for nested-virtualization testing:

- size: `Standard_D4_v3`
- region: `westeurope`
- image: `Ubuntu2404`

If your subscription has an allowed-regions policy (common with student credits),
the provisioning script automatically switches to the first policy-allowed region.

```bash
make azure-provision-vm
```

Useful overrides:

```bash
AZ_LOCATION=swedencentral \
AZ_VM_SIZE=Standard_D8_v3 \
AZ_VM_NAME=bpfcompat-lab \
AZ_RESOURCE_GROUP=bpfcompat-rg \
make azure-provision-vm
```

## 3) Bootstrap packages on VM

```bash
export AZ_RESOURCE_GROUP=bpfcompat-rg
export AZ_VM_NAME=bpfcompat-host
make azure-bootstrap-vm
```

This installs: `go`, `clang`, `libbpf-dev`, `qemu-kvm`, `qemu-utils`, `jq`, `make`, and related dependencies.

## 4) Build and run project on VM

SSH into VM using the command printed by `azure-bootstrap-vm`, then run:

```bash
cd ~/bpfcompat
make doctor
make test-vendor
make validator-static
make examples
make acceptance-dev-one
```

For full matrix:

```bash
make vm-images
make acceptance
make runtime-selector-proof
make runtime-delivery-proof
```

## 5) Cost control tips

- Stop VM when idle:
  - `az vm deallocate -g <rg> -n <vm>`
- Start when needed:
  - `az vm start -g <rg> -n <vm>`
- Keep disk size minimal for your workload.
- Use `acceptance-dev-one` for quick checks before full matrix runs.

## 6) Provision production foundation (identity, storage, monitoring, key vault)

Create managed Azure resources for runtime delivery proof hardening:

- private artifact storage account + container
- key vault (RBAC mode)
- VM managed identity + least-privilege bindings
- log analytics workspace + VM CPU alert

```bash
export AZ_RESOURCE_GROUP=bpfcompat-rg-se24
export AZ_VM_NAME=bpfcompat-host24
# optional, to get email notifications:
export AZ_ALERT_EMAIL="<you@example.com>"

make azure-provision-foundation
```

If you need custom names:

```bash
AZ_STORAGE_ACCOUNT=bpfcompatstore01 \
AZ_KEYVAULT_NAME=bpfcompat-kv-01 \
AZ_LOG_WORKSPACE_NAME=bpfcompat-law \
make azure-provision-foundation
```

## 7) Rotate registry secret in Key Vault

```bash
export AZ_KEYVAULT_NAME="<from previous step>"
make azure-rotate-registry-secret
```

Optional custom secret name + TTL:

```bash
AZ_REGISTRY_SECRET_NAME=bpfcompat-registry-token \
AZ_SECRET_TTL_DAYS=14 \
make azure-rotate-registry-secret
```

## 8) Generate Azure production-boundary proof

This verifies/provisions the cloud controls that close the current
production-runtime boundary at preview-proof level:

- Azure Key Vault signing key with sign/verify evidence
- private Blob artifact storage with Azure RBAC-only data-plane access,
  versioning, and restore proof
- unlocked Blob immutability policy when supported
- Azure Monitor diagnostic settings to Log Analytics
- VM managed identity evidence
- temporary managed identity revocation drill

```bash
export AZ_RESOURCE_GROUP=bpfcompat-rg-se24
export AZ_VM_NAME=bpfcompat-host24
make azure-production-boundary-proof
```

Outputs:

- `evidence/azure-production-boundary/<timestamp>/azure-boundary-proof.md`

Boundary: this does not use Managed HSM by default, does not issue customer
Entra app roles, and does not perform live eBPF host loading.

## 9) Configure HTTPS domain endpoint (Caddy)

Prerequisites:

- DNS `A` record exists for your domain/subdomain and points to VM public IP.
- `bpfcompat` API is running on VM at `127.0.0.1:8080`.

```bash
export AZ_RESOURCE_GROUP=bpfcompat-rg-se24
export AZ_VM_NAME=bpfcompat-host24
export BPFCOMPAT_DOMAIN="bpfcompat.<your-domain>"
make azure-configure-tls
```

After completion:

- API health URL: `https://<your-domain>/api/health`
- UI URL: `https://<your-domain>/`

## 10) Demo security hardening env

For public demo deployments, set these before starting `bpfcompat serve`:

```bash
export BPFCOMPAT_API_WRITE_KEY="<strong-random-key>"
export BPFCOMPAT_API_ALLOW_ANONYMOUS_VALIDATE=false # optional; true allows /api/validate and matching status reads without write auth
export BPFCOMPAT_API_ALLOW_ANONYMOUS_READ=false # optional; true opens read-only history/status/runtime endpoints for public demos
export BPFCOMPAT_API_ALLOW_ANONYMOUS_RUNTIME_DELIVERY=false # optional; true opens only runtime select/fetch for public demos
export BPFCOMPAT_API_ENABLE_RUNTIME_EXECUTE=false
export BPFCOMPAT_API_RUNTIME_EXECUTE_APPROVAL_TOKEN="<separate-approval-token>"
export BPFCOMPAT_API_RUNTIME_EXECUTE_KILL_SWITCH=false
export BPFCOMPAT_API_AUTO_SYNC_REGISTRY=false # optional; when true mirror local validate history into cloud-registry
export BPFCOMPAT_API_AUTO_SYNC_TENANT="" # required when auto-sync enabled
export BPFCOMPAT_API_AUTO_SYNC_PROJECT="" # required when auto-sync enabled
export BPFCOMPAT_API_AUTO_SYNC_PROJECT_VISIBILITY=private
export BPFCOMPAT_API_RUNTIME_EXECUTE_WORKER_BINARY="" # optional; defaults to current bpfcompat executable
export BPFCOMPAT_API_RUNTIME_EXECUTE_WORKER_USER="" # optional; set dedicated worker OS user
export BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_WORKER_IDENTITY=false
export BPFCOMPAT_API_RUNTIME_EXECUTE_POLICY_PATH="" # optional; runtime execute policy file
export BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_POLICY=false
export BPFCOMPAT_API_REDACT_RUNTIME_DETAILS=true
export BPFCOMPAT_API_WRITE_JWT_HS256_SECRET="" # optional; HS256 for X-API-Identity-Token
export BPFCOMPAT_API_WRITE_JWT_JWKS_PATH="" # optional; RS256 JWKS file path for X-API-Identity-Token
export BPFCOMPAT_API_WRITE_JWT_JWKS_URL="" # optional; RS256 JWKS URL for X-API-Identity-Token
export BPFCOMPAT_API_WRITE_JWT_JWKS_CACHE_TTL=5m # optional JWKS cache TTL
export BPFCOMPAT_API_WRITE_JWT_JWKS_HTTP_TIMEOUT=5s # optional JWKS URL fetch timeout
export BPFCOMPAT_API_WRITE_JWT_OIDC_ISSUER_URL="" # optional OIDC issuer URL for discovery
export BPFCOMPAT_API_WRITE_JWT_OIDC_DISCOVERY_CACHE_TTL=10m # optional discovery cache TTL
export BPFCOMPAT_API_WRITE_JWT_REQUIRED_SCOPES="" # optional global required scopes
export BPFCOMPAT_API_WRITE_JWT_REQUIRED_ROLES="" # optional global required roles
export BPFCOMPAT_API_WRITE_JWT_REQUIRED_SCOPES_RUNTIME_EXECUTE="" # optional per-action scopes
export BPFCOMPAT_API_WRITE_JWT_REQUIRED_ROLES_RUNTIME_EXECUTE="" # optional per-action roles
export BPFCOMPAT_API_RUNTIME_EXECUTE_JWT_REQUIRED_SCOPES="" # optional extra scopes for runtime execute
export BPFCOMPAT_API_RUNTIME_EXECUTE_JWT_REQUIRED_ROLES="" # optional extra roles for runtime execute
export BPFCOMPAT_API_WRITE_REQUIRE_IDENTITY=false # fail closed on identity token when true
export BPFCOMPAT_API_REGISTRY_REQUIRE_IDENTITY=false # optional; require JWT identity token for all registry endpoints
export BPFCOMPAT_API_WRITE_JWT_ISSUER="" # optional exact iss claim match
export BPFCOMPAT_API_WRITE_JWT_AUDIENCE="" # optional exact aud claim match
```

Behavior:

- POST endpoints require write auth via `X-API-Key` or `X-API-Identity-Token` (JWT HS256/RS256).
- `/api/runtime/execute` is disabled unless explicitly enabled.
- when runtime execute is enabled, `X-Execute-Approval-Token` must match `BPFCOMPAT_API_RUNTIME_EXECUTE_APPROVAL_TOKEN`.
- when `BPFCOMPAT_API_RUNTIME_EXECUTE_KILL_SWITCH=true`, `/api/runtime/execute` is denied even for otherwise valid requests.
- runtime execute requests must include `tenant` and `project` in JSON and a tenant-authorized registry token (`Authorization: Bearer <token>`).
- when using `Authorization` for the registry token, send write auth via `X-API-Key` or `X-API-Identity-Token`.
- runtime execute host-load step is delegated to worker process `bpfcompat runtime worker-execute` (override binary path with `BPFCOMPAT_API_RUNTIME_EXECUTE_WORKER_BINARY`).
- optional: run worker as dedicated OS user with `BPFCOMPAT_API_RUNTIME_EXECUTE_WORKER_USER`; enforce fail-closed worker identity with `BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_WORKER_IDENTITY=true`.
- optional: enforce allow/deny execute policy via `BPFCOMPAT_API_RUNTIME_EXECUTE_POLICY_PATH`; enforce fail-closed policy requirement with `BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_POLICY=true`.
- optional: enforce write identity JWT-only mode with `BPFCOMPAT_API_WRITE_REQUIRE_IDENTITY=true`; token claims `tenant` and `projects` are checked for runtime execute.
- optional: enforce registry JWT identity mode with `BPFCOMPAT_API_REGISTRY_REQUIRE_IDENTITY=true`; token claims `tenant` and `projects` are checked for registry request scope.
- optional: enforce JWT scope/role claims with `BPFCOMPAT_API_WRITE_JWT_REQUIRED_SCOPES` / `BPFCOMPAT_API_WRITE_JWT_REQUIRED_ROLES`.
- optional: enforce endpoint-specific claim gates with `BPFCOMPAT_API_WRITE_JWT_REQUIRED_SCOPES_<ACTION>` / `BPFCOMPAT_API_WRITE_JWT_REQUIRED_ROLES_<ACTION>` for runtime and registry actions.
- optional: enforce stricter runtime-execute JWT claims with `BPFCOMPAT_API_RUNTIME_EXECUTE_JWT_REQUIRED_SCOPES` / `BPFCOMPAT_API_RUNTIME_EXECUTE_JWT_REQUIRED_ROLES`.
- RS256 JWKS verification uses cache + refresh retry semantics to handle key rotation without API restart.
- if `BPFCOMPAT_API_WRITE_JWT_OIDC_ISSUER_URL` is unset and `BPFCOMPAT_API_WRITE_JWT_ISSUER` is an `https` URL, OIDC discovery uses that issuer value. JWKS/OIDC URL verification requires HTTPS in production.
- probe/execute responses redact hostnames and filesystem paths by default.
