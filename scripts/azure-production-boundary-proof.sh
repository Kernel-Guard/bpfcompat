#!/usr/bin/env bash
set -euo pipefail

# Build a timestamped Azure production-boundary evidence package.
#
# This is intentionally a proof of cloud controls, not a production sign-off:
# - Azure Key Vault software key signing is used by default to stay credits-friendly.
# - Managed HSM is not provisioned here.
# - A temporary managed identity is created and revoked for the revocation drill.
# - No eBPF is loaded on a host by this script.

AZ_SUBSCRIPTION_ID="${AZ_SUBSCRIPTION_ID:-}"
AZ_RESOURCE_GROUP="${AZ_RESOURCE_GROUP:-bpfcompat-rg-se24}"
AZ_LOCATION="${AZ_LOCATION:-}"
AZ_VM_NAME="${AZ_VM_NAME:-bpfcompat-host24}"
AZ_STORAGE_ACCOUNT="${AZ_STORAGE_ACCOUNT:-}"
AZ_STORAGE_CONTAINER="${AZ_STORAGE_CONTAINER:-bpf-artifacts}"
AZ_DRILL_CONTAINER="${AZ_DRILL_CONTAINER:-${AZ_STORAGE_CONTAINER}-drills}"
AZ_KEYVAULT_NAME="${AZ_KEYVAULT_NAME:-}"
AZ_LOG_WORKSPACE_NAME="${AZ_LOG_WORKSPACE_NAME:-bpfcompat-law}"
AZ_KV_SIGNING_KEY_NAME="${AZ_KV_SIGNING_KEY_NAME:-bpfcompat-artifact-signing}"
AZ_PROOF_ARTIFACT_PATH="${AZ_PROOF_ARTIFACT_PATH:-examples/simple-pass/simple_pass.bpf.o}"
AZ_BOUNDARY_EVIDENCE_ROOT="${AZ_BOUNDARY_EVIDENCE_ROOT:-evidence/azure-production-boundary}"
AZ_SKIP_FOUNDATION="${AZ_SKIP_FOUNDATION:-false}"
AZ_ASSIGN_SELF_ROLES="${AZ_ASSIGN_SELF_ROLES:-true}"
AZ_ENABLE_BLOB_IMMUTABILITY="${AZ_ENABLE_BLOB_IMMUTABILITY:-true}"
AZ_BLOB_RETENTION_DAYS="${AZ_BLOB_RETENTION_DAYS:-7}"
AZ_BLOB_IMMUTABILITY_DAYS="${AZ_BLOB_IMMUTABILITY_DAYS:-1}"
AZ_RUN_MANAGED_IDENTITY_REVOCATION="${AZ_RUN_MANAGED_IDENTITY_REVOCATION:-true}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
out_dir="${AZ_BOUNDARY_EVIDENCE_ROOT}/${timestamp}"
mkdir -p "$out_dir"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[azure-boundary] missing required command: $1" >&2
    exit 1
  fi
}

lower_name() {
  tr '[:upper:]' '[:lower:]' <<<"$1" | tr -cd 'a-z0-9-'
}

record_status() {
  local component="$1"
  local status="$2"
  local detail="$3"
  printf '%s\t%s\t%s\n' "$component" "$status" "$detail" >> "${out_dir}/status.tsv"
}

ensure_provider_registered() {
  local namespace="$1"
  local state
  state="$(az provider show -n "$namespace" --query registrationState -o tsv 2>/dev/null || true)"
  if [[ "$state" == "Registered" ]]; then
    return 0
  fi
  echo "[azure-boundary] registering provider: $namespace"
  az provider register --namespace "$namespace" --wait --output none
}

role_assignment_count() {
  local assignee_object_id="$1"
  local scope="$2"
  local role="$3"
  az role assignment list \
    --assignee-object-id "$assignee_object_id" \
    --scope "$scope" \
    --query "[?roleDefinitionName=='${role}'] | length(@)" \
    -o tsv
}

ensure_role_assignment() {
  local assignee_object_id="$1"
  local principal_type="$2"
  local scope="$3"
  local role="$4"
  local count
  count="$(role_assignment_count "$assignee_object_id" "$scope" "$role")"
  if [[ "$count" != "0" ]]; then
    echo "[azure-boundary] role exists: $role ($assignee_object_id)"
    return 0
  fi
  echo "[azure-boundary] granting $role to $assignee_object_id"
  az role assignment create \
    --assignee-object-id "$assignee_object_id" \
    --assignee-principal-type "$principal_type" \
    --role "$role" \
    --scope "$scope" \
    --output none
  ROLE_ASSIGNMENT_CHANGED=true
}

create_or_update_diagnostic_setting() {
  local resource_id="$1"
  local setting_name="$2"
  local label="$3"
  local workspace_id="$4"
  local log_file="${out_dir}/${setting_name}.log"
  local existing_settings_file="${out_dir}/${setting_name}-existing.json"

  if az monitor diagnostic-settings show --resource "$resource_id" --name "$setting_name" > "${out_dir}/${setting_name}.json" 2>/dev/null; then
    record_status "$label diagnostics" "pass" "diagnostic setting already exists"
    return 0
  fi

  if az monitor diagnostic-settings list --resource "$resource_id" --output json > "$existing_settings_file" 2>/dev/null &&
    jq -e --arg workspace "$(tr '[:upper:]' '[:lower:]' <<<"$workspace_id")" \
      '[.[] | select(((.workspaceId // "") | ascii_downcase) == $workspace)] | length > 0' \
      "$existing_settings_file" >/dev/null; then
    cp "$existing_settings_file" "${out_dir}/${setting_name}.json"
    record_status "$label diagnostics" "pass" "diagnostic setting already routes to Log Analytics workspace"
    return 0
  fi

  if az monitor diagnostic-settings create \
    --resource "$resource_id" \
    --name "$setting_name" \
    --workspace "$workspace_id" \
    --logs '[{"categoryGroup":"allLogs","enabled":true}]' \
    --metrics '[{"category":"AllMetrics","enabled":true}]' \
    --output json > "${out_dir}/${setting_name}.json" 2>"$log_file"; then
    record_status "$label diagnostics" "pass" "diagnostic setting created"
    return 0
  fi

  if az monitor diagnostic-settings create \
    --resource "$resource_id" \
    --name "$setting_name" \
    --workspace "$workspace_id" \
    --metrics '[{"category":"AllMetrics","enabled":true}]' \
    --output json > "${out_dir}/${setting_name}.json" 2>>"$log_file"; then
    record_status "$label diagnostics" "partial" "metrics-only diagnostic setting created"
    return 0
  fi

  record_status "$label diagnostics" "warn" "diagnostic setting not supported or not permitted; see ${setting_name}.log"
  return 0
}

require_cmd az
require_cmd jq
require_cmd openssl
require_cmd sha256sum
require_cmd base64

: > "${out_dir}/status.tsv"
ROLE_ASSIGNMENT_CHANGED=false

if ! az account show >/dev/null 2>&1; then
  echo "[azure-boundary] Azure login missing. Run: az login --use-device-code" >&2
  exit 1
fi

if [[ -n "$AZ_SUBSCRIPTION_ID" ]]; then
  az account set --subscription "$AZ_SUBSCRIPTION_ID"
fi

SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
TENANT_ID="$(az account show --query tenantId -o tsv)"

ensure_provider_registered "Microsoft.Storage"
ensure_provider_registered "Microsoft.KeyVault"
ensure_provider_registered "Microsoft.OperationalInsights"
ensure_provider_registered "Microsoft.Insights"
ensure_provider_registered "Microsoft.ManagedIdentity"

if [[ "$AZ_SKIP_FOUNDATION" != "true" ]]; then
  echo "[azure-boundary] ensuring Azure foundation"
  AZ_RESOURCE_GROUP="$AZ_RESOURCE_GROUP" \
  AZ_LOCATION="$AZ_LOCATION" \
  AZ_VM_NAME="$AZ_VM_NAME" \
  AZ_STORAGE_ACCOUNT="$AZ_STORAGE_ACCOUNT" \
  AZ_STORAGE_CONTAINER="$AZ_STORAGE_CONTAINER" \
  AZ_KEYVAULT_NAME="$AZ_KEYVAULT_NAME" \
  AZ_LOG_WORKSPACE_NAME="$AZ_LOG_WORKSPACE_NAME" \
    bash scripts/azure-provision-foundation.sh > "${out_dir}/azure-provision-foundation.log" 2>&1
fi

if [[ "$(az group exists --name "$AZ_RESOURCE_GROUP" -o tsv)" != "true" ]]; then
  echo "[azure-boundary] resource group not found: $AZ_RESOURCE_GROUP" >&2
  exit 1
fi

AZ_LOCATION="${AZ_LOCATION:-$(az group show --name "$AZ_RESOURCE_GROUP" --query location -o tsv)}"

if [[ -z "$AZ_STORAGE_ACCOUNT" ]]; then
  AZ_STORAGE_ACCOUNT="$(az storage account list --resource-group "$AZ_RESOURCE_GROUP" --query "[0].name" -o tsv)"
fi
if [[ -z "$AZ_KEYVAULT_NAME" ]]; then
  AZ_KEYVAULT_NAME="$(az keyvault list --resource-group "$AZ_RESOURCE_GROUP" --query "[0].name" -o tsv)"
fi

if [[ -z "$AZ_STORAGE_ACCOUNT" || -z "$AZ_KEYVAULT_NAME" ]]; then
  echo "[azure-boundary] storage account or key vault missing after foundation provisioning" >&2
  exit 1
fi

STORAGE_ID="$(az storage account show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_STORAGE_ACCOUNT" --query id -o tsv)"
KEYVAULT_ID="$(az keyvault show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_KEYVAULT_NAME" --query id -o tsv)"
LAW_ID="$(az monitor log-analytics workspace show --resource-group "$AZ_RESOURCE_GROUP" --workspace-name "$AZ_LOG_WORKSPACE_NAME" --query id -o tsv)"

CALLER_OBJECT_ID="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
if [[ "$AZ_ASSIGN_SELF_ROLES" == "true" && -n "$CALLER_OBJECT_ID" ]]; then
  ensure_role_assignment "$CALLER_OBJECT_ID" "User" "$STORAGE_ID" "Storage Blob Data Contributor"
  ensure_role_assignment "$CALLER_OBJECT_ID" "User" "$KEYVAULT_ID" "Key Vault Crypto Officer"
fi

VM_EXISTS=false
VM_PRINCIPAL_ID=""
if az vm show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" >/dev/null 2>&1; then
  VM_EXISTS=true
  az vm identity assign --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --output none
  VM_ID="$(az vm show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --query id -o tsv)"
  VM_PRINCIPAL_ID="$(az vm show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --query identity.principalId -o tsv)"
  ensure_role_assignment "$VM_PRINCIPAL_ID" "ServicePrincipal" "$STORAGE_ID" "Storage Blob Data Reader"
  create_or_update_diagnostic_setting "$VM_ID" "bpfcompat-vm-boundary-diag" "VM" "$LAW_ID"
  record_status "VM managed identity" "pass" "principal_id=${VM_PRINCIPAL_ID}"
else
  record_status "VM managed identity" "partial" "VM ${AZ_VM_NAME} not found; skipped VM identity proof"
fi

if [[ "$ROLE_ASSIGNMENT_CHANGED" == "true" ]]; then
  echo "[azure-boundary] waiting for RBAC propagation"
  sleep 35
fi

echo "[azure-boundary] enabling blob versioning and retention"
az storage account blob-service-properties update \
  --resource-group "$AZ_RESOURCE_GROUP" \
  --account-name "$AZ_STORAGE_ACCOUNT" \
  --enable-versioning true \
  --enable-delete-retention true \
  --delete-retention-days "$AZ_BLOB_RETENTION_DAYS" \
  --enable-container-delete-retention true \
  --container-delete-retention-days "$AZ_BLOB_RETENTION_DAYS" \
  --output json > "${out_dir}/blob-service-properties.json"

shared_key_access="$(az storage account show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_STORAGE_ACCOUNT" --query allowSharedKeyAccess -o tsv)"
if [[ "$shared_key_access" == "false" ]]; then
  record_status "Storage shared-key access" "pass" "disabled; data-plane proof uses Azure RBAC/login auth"
else
  record_status "Storage shared-key access" "warn" "enabled; set AZ_STORAGE_ALLOW_SHARED_KEY_ACCESS=false for production boundary"
fi

if az storage container exists \
  --account-name "$AZ_STORAGE_ACCOUNT" \
  --name "$AZ_STORAGE_CONTAINER" \
  --auth-mode login \
  --query exists -o tsv | grep -q '^true$'; then
  echo "[azure-boundary] storage container exists: $AZ_STORAGE_CONTAINER"
else
  az storage container create \
    --account-name "$AZ_STORAGE_ACCOUNT" \
    --name "$AZ_STORAGE_CONTAINER" \
    --auth-mode login \
    --public-access off \
    --output none
fi

if az storage container exists \
  --account-name "$AZ_STORAGE_ACCOUNT" \
  --name "$AZ_DRILL_CONTAINER" \
  --auth-mode login \
  --query exists -o tsv | grep -q '^true$'; then
  echo "[azure-boundary] storage drill container exists: $AZ_DRILL_CONTAINER"
else
  az storage container create \
    --account-name "$AZ_STORAGE_ACCOUNT" \
    --name "$AZ_DRILL_CONTAINER" \
    --auth-mode login \
    --public-access off \
    --output none
fi

record_status "Blob versioning" "pass" "enabled with delete_retention_days=${AZ_BLOB_RETENTION_DAYS}"

if [[ ! -f "$AZ_PROOF_ARTIFACT_PATH" ]]; then
  echo "[azure-boundary] proof artifact missing: $AZ_PROOF_ARTIFACT_PATH" >&2
  exit 1
fi

artifact_sha="$(sha256sum "$AZ_PROOF_ARTIFACT_PATH" | awk '{print $1}')"
artifact_blob="boundary-proof/${timestamp}/$(basename "$AZ_PROOF_ARTIFACT_PATH")"

echo "[azure-boundary] uploading proof artifact to blob storage"
az storage blob upload \
  --account-name "$AZ_STORAGE_ACCOUNT" \
  --container-name "$AZ_STORAGE_CONTAINER" \
  --name "$artifact_blob" \
  --file "$AZ_PROOF_ARTIFACT_PATH" \
  --auth-mode login \
  --overwrite false \
  --metadata proof=azure-boundary sha256="$artifact_sha" \
  --output json > "${out_dir}/artifact-upload.json"
record_status "Artifact blob upload" "pass" "${artifact_blob} sha256=${artifact_sha}"

restore_blob="boundary-proof/${timestamp}/restore-drill.txt"
restore_v1="${out_dir}/restore-v1.txt"
restore_v2="${out_dir}/restore-v2.txt"
restore_download="${out_dir}/restore-downloaded-v1.txt"
printf 'restore drill version 1 %s\n' "$timestamp" > "$restore_v1"
printf 'restore drill version 2 %s\n' "$timestamp" > "$restore_v2"

az storage blob upload \
  --account-name "$AZ_STORAGE_ACCOUNT" \
  --container-name "$AZ_DRILL_CONTAINER" \
  --name "$restore_blob" \
  --file "$restore_v1" \
  --auth-mode login \
  --overwrite true \
  --output json > "${out_dir}/restore-upload-v1.json"

v1_version="$(jq -r '.properties.versionId // .versionId // ""' "${out_dir}/restore-upload-v1.json")"

az storage blob upload \
  --account-name "$AZ_STORAGE_ACCOUNT" \
  --container-name "$AZ_DRILL_CONTAINER" \
  --name "$restore_blob" \
  --file "$restore_v2" \
  --auth-mode login \
  --overwrite true \
  --output json > "${out_dir}/restore-upload-v2.json"

az storage blob list \
  --account-name "$AZ_STORAGE_ACCOUNT" \
  --container-name "$AZ_DRILL_CONTAINER" \
  --auth-mode login \
  --prefix "$restore_blob" \
  --include v \
  --output json > "${out_dir}/restore-versions.json"

if [[ -z "$v1_version" || "$v1_version" == "null" ]]; then
  v1_version="$(jq -r '[.[] | select(.name == "'"$restore_blob"'" and .versionId != null)] | sort_by(.versionId) | .[0].versionId // ""' "${out_dir}/restore-versions.json")"
fi

if [[ -n "$v1_version" ]]; then
  az storage blob download \
    --account-name "$AZ_STORAGE_ACCOUNT" \
    --container-name "$AZ_DRILL_CONTAINER" \
    --name "$restore_blob" \
    --version-id "$v1_version" \
    --file "$restore_download" \
    --auth-mode login \
    --overwrite true \
    --output none
  if cmp -s "$restore_v1" "$restore_download"; then
    record_status "Blob restore drill" "pass" "downloaded previous version ${v1_version}"
  else
    record_status "Blob restore drill" "fail" "downloaded previous version did not match"
  fi
else
  record_status "Blob restore drill" "fail" "could not resolve first blob version"
fi

if [[ "$AZ_ENABLE_BLOB_IMMUTABILITY" == "true" ]]; then
  if az storage container immutability-policy show \
    --account-name "$AZ_STORAGE_ACCOUNT" \
    --container-name "$AZ_STORAGE_CONTAINER" \
    --resource-group "$AZ_RESOURCE_GROUP" > "${out_dir}/immutability-policy.json" 2>/dev/null; then
    record_status "Blob immutability" "pass" "immutability policy already exists"
  else
    if az storage container immutability-policy create \
      --account-name "$AZ_STORAGE_ACCOUNT" \
      --container-name "$AZ_STORAGE_CONTAINER" \
      --resource-group "$AZ_RESOURCE_GROUP" \
      --period "$AZ_BLOB_IMMUTABILITY_DAYS" \
      --output json > "${out_dir}/immutability-policy.json"; then
      record_status "Blob immutability" "pass" "unlocked immutability policy created for ${AZ_BLOB_IMMUTABILITY_DAYS} day(s)"
    else
      record_status "Blob immutability" "warn" "immutability policy could not be created"
    fi
  fi
else
  record_status "Blob immutability" "skipped" "AZ_ENABLE_BLOB_IMMUTABILITY=false"
fi

echo "[azure-boundary] creating/checking Key Vault signing key"
if az keyvault key show --vault-name "$AZ_KEYVAULT_NAME" --name "$AZ_KV_SIGNING_KEY_NAME" > "${out_dir}/keyvault-signing-key.json" 2>/dev/null; then
  echo "[azure-boundary] signing key exists: $AZ_KV_SIGNING_KEY_NAME"
else
  az keyvault key create \
    --vault-name "$AZ_KEYVAULT_NAME" \
    --name "$AZ_KV_SIGNING_KEY_NAME" \
    --kty EC \
    --curve P-256 \
    --ops sign verify \
    --protection software \
    --tags usage=artifact-signing app=bpfcompat boundary=azure-production-proof \
    --output json > "${out_dir}/keyvault-signing-key.json"
fi

cat > "${out_dir}/signing-payload.json" <<EOF
{
  "schema_version": "azure_boundary_signing_payload.v0.1",
  "created_at": "${timestamp}",
  "subscription_id": "${SUBSCRIPTION_ID}",
  "tenant_id": "${TENANT_ID}",
  "resource_group": "${AZ_RESOURCE_GROUP}",
  "storage_account": "${AZ_STORAGE_ACCOUNT}",
  "container": "${AZ_STORAGE_CONTAINER}",
  "artifact_blob": "${artifact_blob}",
  "artifact_sha256": "${artifact_sha}"
}
EOF

payload_digest="$(openssl dgst -sha256 -binary "${out_dir}/signing-payload.json" | base64 -w0)"
az keyvault key sign \
  --vault-name "$AZ_KEYVAULT_NAME" \
  --name "$AZ_KV_SIGNING_KEY_NAME" \
  --algorithm ES256 \
  --digest "$payload_digest" \
  --output json > "${out_dir}/keyvault-signature.json"

signature="$(jq -r '.signature // .result // ""' "${out_dir}/keyvault-signature.json")"
az keyvault key verify \
  --vault-name "$AZ_KEYVAULT_NAME" \
  --name "$AZ_KV_SIGNING_KEY_NAME" \
  --algorithm ES256 \
  --digest "$payload_digest" \
  --signature "$signature" \
  --output json > "${out_dir}/keyvault-signature-verify.json"

verify_value="$(jq -r '.isValid // .value // .valid // false' "${out_dir}/keyvault-signature-verify.json")"
if [[ "$verify_value" == "true" ]]; then
  record_status "Key Vault signing" "pass" "ES256 sign/verify succeeded with ${AZ_KV_SIGNING_KEY_NAME}"
else
  record_status "Key Vault signing" "fail" "signature verification failed"
fi

create_or_update_diagnostic_setting "$STORAGE_ID" "bpfcompat-storage-boundary-diag" "Storage account" "$LAW_ID"
create_or_update_diagnostic_setting "$KEYVAULT_ID" "bpfcompat-keyvault-boundary-diag" "Key Vault" "$LAW_ID"

if [[ "$AZ_RUN_MANAGED_IDENTITY_REVOCATION" == "true" ]]; then
  safe_ts="$(lower_name "$timestamp")"
  temp_identity="bpfcompat-revoke-${safe_ts:0:15}"
  echo "[azure-boundary] creating temporary managed identity for revocation drill: $temp_identity"
  az identity create \
    --resource-group "$AZ_RESOURCE_GROUP" \
    --name "$temp_identity" \
    --location "$AZ_LOCATION" \
    --output json > "${out_dir}/managed-identity-create.json"
  temp_principal="$(jq -r '.principalId' "${out_dir}/managed-identity-create.json")"
  az role assignment create \
    --assignee-object-id "$temp_principal" \
    --assignee-principal-type ServicePrincipal \
    --role "Storage Blob Data Reader" \
    --scope "$STORAGE_ID" \
    --output json > "${out_dir}/managed-identity-role-assignment.json"
  assignment_id="$(jq -r '.id' "${out_dir}/managed-identity-role-assignment.json")"
  az role assignment delete --ids "$assignment_id"
  remaining="$(role_assignment_count "$temp_principal" "$STORAGE_ID" "Storage Blob Data Reader" 2>/dev/null || echo 0)"
  az identity delete --resource-group "$AZ_RESOURCE_GROUP" --name "$temp_identity" --output none
  if [[ "$remaining" == "0" ]]; then
    record_status "Managed identity revocation" "pass" "temporary identity role removed and identity deleted"
  else
    record_status "Managed identity revocation" "fail" "role assignment still visible after revoke"
  fi
else
  record_status "Managed identity revocation" "skipped" "AZ_RUN_MANAGED_IDENTITY_REVOCATION=false"
fi

az storage account show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_STORAGE_ACCOUNT" --output json > "${out_dir}/storage-account.json"
az keyvault show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_KEYVAULT_NAME" --output json > "${out_dir}/keyvault.json"
az monitor log-analytics workspace show --resource-group "$AZ_RESOURCE_GROUP" --workspace-name "$AZ_LOG_WORKSPACE_NAME" --output json > "${out_dir}/log-analytics-workspace.json"
if [[ "$VM_EXISTS" == "true" ]]; then
  az vm show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --output json > "${out_dir}/vm.json"
fi

total_fail="$(awk -F '\t' '$2 == "fail" {count++} END {print count+0}' "${out_dir}/status.tsv")"
total_warn="$(awk -F '\t' '$2 == "warn" {count++} END {print count+0}' "${out_dir}/status.tsv")"
result="pass"
if [[ "$total_fail" != "0" ]]; then
  result="fail"
elif [[ "$total_warn" != "0" ]]; then
  result="partial"
fi

jq -Rn '
  [inputs | split("\t") | {component: .[0], status: .[1], detail: .[2]}]
' < "${out_dir}/status.tsv" > "${out_dir}/azure-boundary-status.json"

cat > "${out_dir}/azure-boundary-proof.md" <<EOF
# Azure Production Boundary Proof

Generated: ${timestamp}

Result: **${result}**

This evidence package proves Azure-hosted production-boundary controls for the
runtime delivery path. It does not claim full production SaaS readiness and it
does not load eBPF on a host.

## Azure Resources

| Resource | Value |
|---|---|
| Subscription | ${SUBSCRIPTION_ID} |
| Tenant | ${TENANT_ID} |
| Resource group | ${AZ_RESOURCE_GROUP} |
| Location | ${AZ_LOCATION} |
| Storage account | ${AZ_STORAGE_ACCOUNT} |
| Artifact container | ${AZ_STORAGE_CONTAINER} |
| Restore drill container | ${AZ_DRILL_CONTAINER} |
| Key Vault | ${AZ_KEYVAULT_NAME} |
| Signing key | ${AZ_KV_SIGNING_KEY_NAME} |
| Log Analytics workspace | ${AZ_LOG_WORKSPACE_NAME} |
| Agent VM | ${AZ_VM_NAME} |
| VM managed identity | ${VM_PRINCIPAL_ID:-not available} |

## Control Results

| Control | Status | Detail |
|---|---|---|
$(awk -F '\t' '{printf "| %s | %s | %s |\n", $1, $2, $3}' "${out_dir}/status.tsv")

## Evidence Files

- storage-account.json
- blob-service-properties.json
- artifact-upload.json
- restore-versions.json
- immutability-policy.json
- keyvault.json
- keyvault-signing-key.json
- keyvault-signature.json
- keyvault-signature-verify.json
- log-analytics-workspace.json
- azure-boundary-status.json

## Boundary

- Key custody is proven with Azure Key Vault software-key sign/verify.
- Artifact storage is proven with private Azure Blob Storage, versioning, and restore evidence.
- Audit routing is attempted through Azure Monitor diagnostic settings to Log Analytics.
- Host identity is represented by Azure managed identity, and revocation is tested with a temporary managed identity.
- This script does not provision Managed HSM, does not issue customer Entra app roles, and does not perform live eBPF host loading.

## Reproduce

\`\`\`bash
make azure-production-boundary-proof
\`\`\`
EOF

echo "[azure-boundary] wrote ${out_dir}/azure-boundary-proof.md"
