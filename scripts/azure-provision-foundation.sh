#!/usr/bin/env bash
set -euo pipefail

# Provision production-foundation Azure resources for bpfcompat:
# - Storage account + private artifact container
# - Key Vault (RBAC mode)
# - Log Analytics workspace
# - VM managed identity + least-privilege role bindings
# - CPU metric alert with optional email action group
#
# Required:
#   - Azure CLI installed (`az`)
#   - Logged in (`az login`)
#   - Existing resource group (or script will create it)
#
# Optional env overrides:
#   AZ_SUBSCRIPTION_ID               (default: current active subscription)
#   AZ_RESOURCE_GROUP                (default: bpfcompat-rg-se24)
#   AZ_LOCATION                      (default: RG location or swedencentral)
#   AZ_VM_NAME                       (default: bpfcompat-host24)
#   AZ_STORAGE_ACCOUNT               (default: derived deterministic name)
#   AZ_STORAGE_CONTAINER             (default: bpf-artifacts)
#   AZ_STORAGE_ALLOW_SHARED_KEY_ACCESS (default: false)
#   AZ_KEYVAULT_NAME                 (default: derived deterministic name)
#   AZ_LOG_WORKSPACE_NAME            (default: bpfcompat-law)
#   AZ_ACTION_GROUP_NAME             (default: bpfcompat-ops)
#   AZ_ACTION_GROUP_SHORT_NAME       (default: bpfops)
#   AZ_ALERT_EMAIL                   (default: empty; when set, alert email receiver is created)
#   AZ_CPU_ALERT_NAME                (default: bpfcompat-vm-cpu-high)
#   AZ_CPU_ALERT_THRESHOLD           (default: 85)

AZ_SUBSCRIPTION_ID="${AZ_SUBSCRIPTION_ID:-}"
AZ_RESOURCE_GROUP="${AZ_RESOURCE_GROUP:-bpfcompat-rg-se24}"
AZ_LOCATION="${AZ_LOCATION:-}"
AZ_VM_NAME="${AZ_VM_NAME:-bpfcompat-host24}"
AZ_STORAGE_ACCOUNT="${AZ_STORAGE_ACCOUNT:-}"
AZ_STORAGE_CONTAINER="${AZ_STORAGE_CONTAINER:-bpf-artifacts}"
AZ_STORAGE_ALLOW_SHARED_KEY_ACCESS="${AZ_STORAGE_ALLOW_SHARED_KEY_ACCESS:-false}"
AZ_KEYVAULT_NAME="${AZ_KEYVAULT_NAME:-}"
AZ_LOG_WORKSPACE_NAME="${AZ_LOG_WORKSPACE_NAME:-bpfcompat-law}"
AZ_ACTION_GROUP_NAME="${AZ_ACTION_GROUP_NAME:-bpfcompat-ops}"
AZ_ACTION_GROUP_SHORT_NAME="${AZ_ACTION_GROUP_SHORT_NAME:-bpfops}"
AZ_ALERT_EMAIL="${AZ_ALERT_EMAIL:-}"
AZ_CPU_ALERT_NAME="${AZ_CPU_ALERT_NAME:-bpfcompat-vm-cpu-high}"
AZ_CPU_ALERT_THRESHOLD="${AZ_CPU_ALERT_THRESHOLD:-85}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[azure-provision-foundation] missing required command: $1" >&2
    exit 1
  fi
}

ensure_provider_registered() {
  local namespace="$1"
  local state
  state="$(az provider show -n "$namespace" --query registrationState -o tsv 2>/dev/null || true)"
  if [[ "$state" == "Registered" ]]; then
    return 0
  fi
  echo "[azure-provision-foundation] registering provider: $namespace"
  az provider register --namespace "$namespace" --wait --output none
}

normalize_storage_name() {
  local raw="$1"
  raw="$(tr '[:upper:]' '[:lower:]' <<<"$raw")"
  raw="$(tr -cd 'a-z0-9' <<<"$raw")"
  if [[ "${#raw}" -lt 3 ]]; then
    raw="${raw}bpf"
  fi
  echo "${raw:0:24}"
}

normalize_kv_name() {
  local raw="$1"
  raw="$(tr '[:upper:]' '[:lower:]' <<<"$raw")"
  raw="$(tr -cd 'a-z0-9-' <<<"$raw")"
  raw="${raw#-}"
  raw="${raw%-}"
  if [[ -z "$raw" ]]; then
    raw="bpfcompat-kv"
  fi
  raw="${raw:0:24}"
  raw="${raw%-}"
  echo "$raw"
}

require_cmd az
require_cmd jq

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
    return 0
  fi
  echo "[azure-provision-foundation] granting $role to $assignee_object_id"
  az role assignment create \
    --assignee-object-id "$assignee_object_id" \
    --assignee-principal-type "$principal_type" \
    --role "$role" \
    --scope "$scope" \
    --output none
  ROLE_ASSIGNMENT_CHANGED=true
}

if ! az account show >/dev/null 2>&1; then
  echo "[azure-provision-foundation] Azure login missing. Run: az login --use-device-code" >&2
  exit 1
fi

if [[ -n "$AZ_SUBSCRIPTION_ID" ]]; then
  az account set --subscription "$AZ_SUBSCRIPTION_ID"
fi

SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
SUFFIX="$(tr -d '-' <<<"$SUBSCRIPTION_ID" | cut -c1-6)"
RG_SLUG="$(tr '[:upper:]' '[:lower:]' <<<"$AZ_RESOURCE_GROUP" | tr -cd 'a-z0-9' | cut -c1-8)"
ROLE_ASSIGNMENT_CHANGED=false

ensure_provider_registered "Microsoft.Storage"
ensure_provider_registered "Microsoft.KeyVault"
ensure_provider_registered "Microsoft.OperationalInsights"
ensure_provider_registered "Microsoft.Insights"

if [[ -z "$AZ_STORAGE_ACCOUNT" ]]; then
  AZ_STORAGE_ACCOUNT="$(normalize_storage_name "bpf${RG_SLUG}${SUFFIX}")"
fi
if [[ -z "$AZ_KEYVAULT_NAME" ]]; then
  AZ_KEYVAULT_NAME="$(normalize_kv_name "bpfkv-${RG_SLUG}-${SUFFIX}")"
fi

if [[ "$(az group exists --name "$AZ_RESOURCE_GROUP" -o tsv)" == "true" ]]; then
  if [[ -z "$AZ_LOCATION" ]]; then
    AZ_LOCATION="$(az group show --name "$AZ_RESOURCE_GROUP" --query location -o tsv)"
  fi
else
  AZ_LOCATION="${AZ_LOCATION:-swedencentral}"
  echo "[azure-provision-foundation] creating resource group: $AZ_RESOURCE_GROUP ($AZ_LOCATION)"
  az group create --name "$AZ_RESOURCE_GROUP" --location "$AZ_LOCATION" --output none
fi

echo "[azure-provision-foundation] resource_group=$AZ_RESOURCE_GROUP location=$AZ_LOCATION"

if az storage account show --name "$AZ_STORAGE_ACCOUNT" --resource-group "$AZ_RESOURCE_GROUP" >/dev/null 2>&1; then
  echo "[azure-provision-foundation] storage account exists: $AZ_STORAGE_ACCOUNT"
else
  echo "[azure-provision-foundation] creating storage account: $AZ_STORAGE_ACCOUNT"
  az storage account create \
    --name "$AZ_STORAGE_ACCOUNT" \
    --resource-group "$AZ_RESOURCE_GROUP" \
    --location "$AZ_LOCATION" \
    --sku Standard_LRS \
    --kind StorageV2 \
    --https-only true \
    --min-tls-version TLS1_2 \
    --allow-blob-public-access false \
    --allow-shared-key-access "$AZ_STORAGE_ALLOW_SHARED_KEY_ACCESS" \
    --output none
fi

az storage account update \
  --name "$AZ_STORAGE_ACCOUNT" \
  --resource-group "$AZ_RESOURCE_GROUP" \
  --https-only true \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false \
  --allow-shared-key-access "$AZ_STORAGE_ALLOW_SHARED_KEY_ACCESS" \
  --output none

STORAGE_SCOPE="$(az storage account show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_STORAGE_ACCOUNT" --query id -o tsv)"
CALLER_OBJECT_ID="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
if [[ "$AZ_STORAGE_ALLOW_SHARED_KEY_ACCESS" == "true" ]]; then
  STORAGE_KEY="$(az storage account keys list --resource-group "$AZ_RESOURCE_GROUP" --account-name "$AZ_STORAGE_ACCOUNT" --query "[0].value" -o tsv)"
  CONTAINER_EXISTS="$(az storage container exists --name "$AZ_STORAGE_CONTAINER" --account-name "$AZ_STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --query exists -o tsv)"
else
  if [[ -z "$CALLER_OBJECT_ID" ]]; then
    echo "[azure-provision-foundation] unable to resolve signed-in user object id for RBAC storage container setup" >&2
    exit 1
  fi
  ensure_role_assignment "$CALLER_OBJECT_ID" "User" "$STORAGE_SCOPE" "Storage Blob Data Contributor"
  if [[ "$ROLE_ASSIGNMENT_CHANGED" == "true" ]]; then
    echo "[azure-provision-foundation] waiting for storage RBAC propagation"
    sleep 35
  fi
  CONTAINER_EXISTS="$(az storage container exists --name "$AZ_STORAGE_CONTAINER" --account-name "$AZ_STORAGE_ACCOUNT" --auth-mode login --query exists -o tsv)"
fi
if [[ "$CONTAINER_EXISTS" == "true" ]]; then
  echo "[azure-provision-foundation] storage container exists: $AZ_STORAGE_CONTAINER"
else
  echo "[azure-provision-foundation] creating storage container: $AZ_STORAGE_CONTAINER"
  if [[ "$AZ_STORAGE_ALLOW_SHARED_KEY_ACCESS" == "true" ]]; then
    az storage container create \
      --name "$AZ_STORAGE_CONTAINER" \
      --account-name "$AZ_STORAGE_ACCOUNT" \
      --account-key "$STORAGE_KEY" \
      --public-access off \
      --output none
  else
    az storage container create \
      --name "$AZ_STORAGE_CONTAINER" \
      --account-name "$AZ_STORAGE_ACCOUNT" \
      --auth-mode login \
      --public-access off \
      --output none
  fi
fi

if az keyvault show --name "$AZ_KEYVAULT_NAME" --resource-group "$AZ_RESOURCE_GROUP" >/dev/null 2>&1; then
  echo "[azure-provision-foundation] key vault exists: $AZ_KEYVAULT_NAME"
else
  echo "[azure-provision-foundation] creating key vault: $AZ_KEYVAULT_NAME"
  az keyvault create \
    --name "$AZ_KEYVAULT_NAME" \
    --resource-group "$AZ_RESOURCE_GROUP" \
    --location "$AZ_LOCATION" \
    --enable-rbac-authorization true \
    --retention-days 90 \
    --enable-purge-protection true \
    --output none
fi

if az monitor log-analytics workspace show --resource-group "$AZ_RESOURCE_GROUP" --workspace-name "$AZ_LOG_WORKSPACE_NAME" >/dev/null 2>&1; then
  echo "[azure-provision-foundation] log analytics workspace exists: $AZ_LOG_WORKSPACE_NAME"
else
  echo "[azure-provision-foundation] creating log analytics workspace: $AZ_LOG_WORKSPACE_NAME"
  az monitor log-analytics workspace create \
    --resource-group "$AZ_RESOURCE_GROUP" \
    --workspace-name "$AZ_LOG_WORKSPACE_NAME" \
    --location "$AZ_LOCATION" \
    --sku PerGB2018 \
    --output none
fi

VM_EXISTS="false"
if az vm show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" >/dev/null 2>&1; then
  VM_EXISTS="true"
fi

ACTION_GROUP_ID=""
if [[ -n "$AZ_ALERT_EMAIL" ]]; then
  if az monitor action-group show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_ACTION_GROUP_NAME" >/dev/null 2>&1; then
    echo "[azure-provision-foundation] action group exists: $AZ_ACTION_GROUP_NAME"
  else
    echo "[azure-provision-foundation] creating action group with email receiver: $AZ_ALERT_EMAIL"
    az monitor action-group create \
      --resource-group "$AZ_RESOURCE_GROUP" \
      --name "$AZ_ACTION_GROUP_NAME" \
      --short-name "$AZ_ACTION_GROUP_SHORT_NAME" \
      --action email bpfcompatops "$AZ_ALERT_EMAIL" \
      --output none
  fi
  ACTION_GROUP_ID="$(az monitor action-group show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_ACTION_GROUP_NAME" --query id -o tsv)"
else
  echo "[azure-provision-foundation] AZ_ALERT_EMAIL not set; skipping email action-group creation"
fi

if [[ "$VM_EXISTS" == "true" ]]; then
  VM_ID="$(az vm show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --query id -o tsv)"
  LAW_ID="$(az monitor log-analytics workspace show --resource-group "$AZ_RESOURCE_GROUP" --workspace-name "$AZ_LOG_WORKSPACE_NAME" --query id -o tsv)"

  echo "[azure-provision-foundation] assigning system-managed identity to VM"
  az vm identity assign --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --output none
  PRINCIPAL_ID="$(az vm show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --query identity.principalId -o tsv)"

  KV_SCOPE="$(az keyvault show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_KEYVAULT_NAME" --query id -o tsv)"

  storage_binding_count="$(az role assignment list \
    --assignee-object-id "$PRINCIPAL_ID" \
    --scope "$STORAGE_SCOPE" \
    --query "[?roleDefinitionName=='Storage Blob Data Reader'] | length(@)" \
    -o tsv)"
  if [[ "$storage_binding_count" == "0" ]]; then
    echo "[azure-provision-foundation] granting VM identity Storage Blob Data Reader"
    az role assignment create \
      --assignee-object-id "$PRINCIPAL_ID" \
      --assignee-principal-type ServicePrincipal \
      --role "Storage Blob Data Reader" \
      --scope "$STORAGE_SCOPE" \
      --output none
  fi

  kv_binding_count="$(az role assignment list \
    --assignee-object-id "$PRINCIPAL_ID" \
    --scope "$KV_SCOPE" \
    --query "[?roleDefinitionName=='Key Vault Secrets User'] | length(@)" \
    -o tsv)"
  if [[ "$kv_binding_count" == "0" ]]; then
    echo "[azure-provision-foundation] granting VM identity Key Vault Secrets User"
    az role assignment create \
      --assignee-object-id "$PRINCIPAL_ID" \
      --assignee-principal-type ServicePrincipal \
      --role "Key Vault Secrets User" \
      --scope "$KV_SCOPE" \
      --output none
  fi

  echo "[azure-provision-foundation] configuring VM diagnostic settings to Log Analytics"
  if az monitor diagnostic-settings show --resource "$VM_ID" --name bpfcompat-vm-diag >/dev/null 2>&1; then
    echo "[azure-provision-foundation] diagnostic setting exists: bpfcompat-vm-diag"
  else
    if ! az monitor diagnostic-settings create \
      --name bpfcompat-vm-diag \
      --resource "$VM_ID" \
      --workspace "$LAW_ID" \
      --metrics '[{"category":"AllMetrics","enabled":true}]' \
      --output none; then
      echo "[azure-provision-foundation] warning: VM diagnostic settings could not be created; continuing"
    fi
  fi

  if az monitor metrics alert show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_CPU_ALERT_NAME" >/dev/null 2>&1; then
    echo "[azure-provision-foundation] metric alert exists: $AZ_CPU_ALERT_NAME"
  else
    echo "[azure-provision-foundation] creating VM CPU metric alert: $AZ_CPU_ALERT_NAME"
    alert_args=(
      --resource-group "$AZ_RESOURCE_GROUP"
      --name "$AZ_CPU_ALERT_NAME"
      --scopes "$VM_ID"
      --condition "avg Percentage CPU > ${AZ_CPU_ALERT_THRESHOLD}"
      --description "bpfcompat VM CPU usage exceeded ${AZ_CPU_ALERT_THRESHOLD}%"
      --window-size 5m
      --evaluation-frequency 1m
      --severity 2
      --output none
    )
    if [[ -n "$ACTION_GROUP_ID" ]]; then
      alert_args+=(--action "$ACTION_GROUP_ID")
    fi
    az monitor metrics alert create "${alert_args[@]}"
  fi
else
  echo "[azure-provision-foundation] VM not found ($AZ_VM_NAME); skipped VM identity, diagnostics, and metric alert setup"
fi

echo
echo "[azure-provision-foundation] done"
echo "  resource_group:        $AZ_RESOURCE_GROUP"
echo "  location:              $AZ_LOCATION"
echo "  vm_name:               $AZ_VM_NAME"
echo "  storage_account:       $AZ_STORAGE_ACCOUNT"
echo "  storage_container:     $AZ_STORAGE_CONTAINER"
echo "  key_vault:             $AZ_KEYVAULT_NAME"
echo "  log_workspace:         $AZ_LOG_WORKSPACE_NAME"
if [[ -n "$AZ_ALERT_EMAIL" ]]; then
  echo "  action_group_email:    $AZ_ALERT_EMAIL"
fi
echo
echo "Next:"
echo "  export AZ_RESOURCE_GROUP=$AZ_RESOURCE_GROUP"
echo "  export AZ_VM_NAME=$AZ_VM_NAME"
echo "  export AZ_KEYVAULT_NAME=$AZ_KEYVAULT_NAME"
echo "  export AZ_STORAGE_ACCOUNT=$AZ_STORAGE_ACCOUNT"
