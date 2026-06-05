#!/usr/bin/env bash
set -euo pipefail

# Rotate registry auth token in Azure Key Vault.
#
# Required env:
#   AZ_KEYVAULT_NAME
#
# Optional:
#   AZ_REGISTRY_SECRET_NAME          (default: bpfcompat-registry-auth-token)
#   AZ_SECRET_TTL_DAYS               (default: 30)
#   AZ_ROTATED_SECRET_VALUE          (default: generated random token)
#   AZ_ROTATE_ASSIGN_SELF_ROLE       (default: true; auto-assign Key Vault Secrets Officer on RBAC denial)

AZ_KEYVAULT_NAME="${AZ_KEYVAULT_NAME:-}"
AZ_REGISTRY_SECRET_NAME="${AZ_REGISTRY_SECRET_NAME:-bpfcompat-registry-auth-token}"
AZ_SECRET_TTL_DAYS="${AZ_SECRET_TTL_DAYS:-30}"
AZ_ROTATED_SECRET_VALUE="${AZ_ROTATED_SECRET_VALUE:-}"
AZ_ROTATE_ASSIGN_SELF_ROLE="${AZ_ROTATE_ASSIGN_SELF_ROLE:-true}"

if [[ -z "$AZ_KEYVAULT_NAME" ]]; then
  echo "[azure-rotate-registry-secret] set AZ_KEYVAULT_NAME first" >&2
  exit 1
fi

if ! command -v az >/dev/null 2>&1; then
  echo "[azure-rotate-registry-secret] azure cli is required (az not found)" >&2
  exit 1
fi

if ! az account show >/dev/null 2>&1; then
  echo "[azure-rotate-registry-secret] Azure login missing. Run: az login --use-device-code" >&2
  exit 1
fi

if [[ -z "$AZ_ROTATED_SECRET_VALUE" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    AZ_ROTATED_SECRET_VALUE="$(openssl rand -base64 48 | tr -d '\n' | tr '/+' '_-')"
  else
    echo "[azure-rotate-registry-secret] openssl not found and AZ_ROTATED_SECRET_VALUE not provided" >&2
    exit 1
  fi
fi

if ! [[ "$AZ_SECRET_TTL_DAYS" =~ ^[0-9]+$ ]]; then
  echo "[azure-rotate-registry-secret] AZ_SECRET_TTL_DAYS must be an integer" >&2
  exit 1
fi

EXPIRES_AT="$(date -u -d "+${AZ_SECRET_TTL_DAYS} days" +"%Y-%m-%dT%H:%M:%SZ")"

set +e
set_output="$(
  az keyvault secret set \
    --vault-name "$AZ_KEYVAULT_NAME" \
    --name "$AZ_REGISTRY_SECRET_NAME" \
    --value "$AZ_ROTATED_SECRET_VALUE" \
    --expires "$EXPIRES_AT" \
    --output none 2>&1
)"
set_rc=$?
set -e

if [[ $set_rc -ne 0 ]]; then
  if [[ "$AZ_ROTATE_ASSIGN_SELF_ROLE" == "true" && "$set_output" == *"ForbiddenByRbac"* ]]; then
    echo "[azure-rotate-registry-secret] missing Key Vault data-plane role; assigning Key Vault Secrets Officer to signed-in user"
    caller_object_id="$(az ad signed-in-user show --query id -o tsv)"
    kv_scope="$(az keyvault show --name "$AZ_KEYVAULT_NAME" --query id -o tsv)"

    officer_bindings="$(az role assignment list \
      --assignee-object-id "$caller_object_id" \
      --scope "$kv_scope" \
      --query "[?roleDefinitionName=='Key Vault Secrets Officer'] | length(@)" \
      -o tsv)"
    if [[ "$officer_bindings" == "0" ]]; then
      az role assignment create \
        --assignee-object-id "$caller_object_id" \
        --assignee-principal-type User \
        --role "Key Vault Secrets Officer" \
        --scope "$kv_scope" \
        --output none
    fi
    echo "[azure-rotate-registry-secret] waiting for RBAC propagation"
    sleep 20
    az keyvault secret set \
      --vault-name "$AZ_KEYVAULT_NAME" \
      --name "$AZ_REGISTRY_SECRET_NAME" \
      --value "$AZ_ROTATED_SECRET_VALUE" \
      --expires "$EXPIRES_AT" \
      --output none
  else
    echo "$set_output" >&2
    exit "$set_rc"
  fi
fi

LATEST_VERSION="$(az keyvault secret show \
  --vault-name "$AZ_KEYVAULT_NAME" \
  --name "$AZ_REGISTRY_SECRET_NAME" \
  --query id -o tsv | awk -F'/' '{print $NF}')"

echo "[azure-rotate-registry-secret] rotated successfully"
echo "  vault:         $AZ_KEYVAULT_NAME"
echo "  secret_name:   $AZ_REGISTRY_SECRET_NAME"
echo "  expires_at:    $EXPIRES_AT"
echo "  version:       $LATEST_VERSION"
echo
echo "Recommended next step:"
echo "  restart bpfcompat service (if reading this token via env/bootstrap flow)"
