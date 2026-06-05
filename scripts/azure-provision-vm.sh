#!/usr/bin/env bash
set -euo pipefail

# Provision an Azure VM suitable for nested-virtualization-based VM validation.
#
# Required:
#   - Azure CLI installed (`az`)
#   - Logged in (`az login`)
#
# Optional env overrides:
#   AZ_SUBSCRIPTION_ID                (default: current active subscription)
#   AZ_RESOURCE_GROUP                 (default: bpfcompat-rg)
#   AZ_LOCATION                       (default: westeurope)
#   AZ_VM_NAME                        (default: bpfcompat-host)
#   AZ_VM_SIZE                        (default: Standard_D4_v3)
#   AZ_IMAGE                          (default: Ubuntu2404)
#   AZ_ADMIN_USER                     (default: azureuser)
#   AZ_SSH_PUBLIC_KEY                 (default: ~/.ssh/id_ed25519.pub)
#   AZ_OS_DISK_GB                     (default: 128)
#   AZ_OPEN_PORTS                     (default: "22 8080")
#   AZ_SECURITY_TYPE                  (default: empty; set e.g. Standard if supported)

AZ_RESOURCE_GROUP="${AZ_RESOURCE_GROUP:-bpfcompat-rg}"
AZ_LOCATION="${AZ_LOCATION:-westeurope}"
AZ_VM_NAME="${AZ_VM_NAME:-bpfcompat-host}"
AZ_VM_SIZE="${AZ_VM_SIZE:-Standard_D4_v3}"
AZ_IMAGE="${AZ_IMAGE:-Ubuntu2404}"
AZ_ADMIN_USER="${AZ_ADMIN_USER:-azureuser}"
AZ_SSH_PUBLIC_KEY="${AZ_SSH_PUBLIC_KEY:-$HOME/.ssh/id_ed25519.pub}"
AZ_OS_DISK_GB="${AZ_OS_DISK_GB:-128}"
AZ_OPEN_PORTS="${AZ_OPEN_PORTS:-22 8080}"
AZ_SUBSCRIPTION_ID="${AZ_SUBSCRIPTION_ID:-}"
AZ_SECURITY_TYPE="${AZ_SECURITY_TYPE:-}"

if ! command -v az >/dev/null 2>&1; then
  echo "[azure-provision-vm] azure cli is required (az not found)" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "[azure-provision-vm] jq is required" >&2
  exit 1
fi

if ! az account show >/dev/null 2>&1; then
  echo "[azure-provision-vm] Azure login missing. Run: az login --use-device-code" >&2
  exit 1
fi

if [[ -n "$AZ_SUBSCRIPTION_ID" ]]; then
  az account set --subscription "$AZ_SUBSCRIPTION_ID"
fi

allowed_locations_json="$(az policy assignment list \
  --query "[?name=='sys.regionrestriction'].parameters.listOfAllowedLocations.value | [0]" \
  -o json 2>/dev/null || true)"
if [[ -n "$allowed_locations_json" && "$allowed_locations_json" != "null" ]]; then
  if ! jq -e --arg loc "$AZ_LOCATION" '.[] | ascii_downcase == ($loc | ascii_downcase)' \
      <<<"$allowed_locations_json" >/dev/null 2>&1; then
    fallback_location="$(jq -r '.[0] // empty' <<<"$allowed_locations_json")"
    if [[ -n "$fallback_location" ]]; then
      echo "[azure-provision-vm] location $AZ_LOCATION is not allowed by policy; using $fallback_location"
      AZ_LOCATION="$fallback_location"
    fi
  fi
fi

if [[ ! -f "$AZ_SSH_PUBLIC_KEY" ]]; then
  echo "[azure-provision-vm] ssh public key not found at $AZ_SSH_PUBLIC_KEY" >&2
  echo "[azure-provision-vm] generate one with: ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''" >&2
  exit 1
fi

if [[ "$(az group exists --name "$AZ_RESOURCE_GROUP" -o tsv)" == "true" ]]; then
  existing_rg_location="$(az group show --name "$AZ_RESOURCE_GROUP" --query location -o tsv)"
  if [[ -n "$existing_rg_location" && "${existing_rg_location,,}" != "${AZ_LOCATION,,}" ]]; then
    echo "[azure-provision-vm] resource group $AZ_RESOURCE_GROUP already exists in $existing_rg_location; using that location"
    AZ_LOCATION="$existing_rg_location"
  fi
fi

echo "[azure-provision-vm] creating/updating resource group: $AZ_RESOURCE_GROUP ($AZ_LOCATION)"
az group create \
  --name "$AZ_RESOURCE_GROUP" \
  --location "$AZ_LOCATION" \
  --output none

if az vm show --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" >/dev/null 2>&1; then
  echo "[azure-provision-vm] vm already exists: $AZ_VM_NAME"
else
  echo "[azure-provision-vm] creating vm: $AZ_VM_NAME ($AZ_VM_SIZE)"
  vm_create_args=(
    --resource-group "$AZ_RESOURCE_GROUP"
    --name "$AZ_VM_NAME"
    --image "$AZ_IMAGE"
    --size "$AZ_VM_SIZE"
    --admin-username "$AZ_ADMIN_USER"
    --authentication-type ssh
    --ssh-key-values "$AZ_SSH_PUBLIC_KEY"
    --public-ip-sku Standard
    --os-disk-size-gb "$AZ_OS_DISK_GB"
    --output none
  )
  if [[ -n "$AZ_SECURITY_TYPE" ]]; then
    vm_create_args+=(--security-type "$AZ_SECURITY_TYPE")
  fi
  az vm create \
    "${vm_create_args[@]}"
fi

rule_index=0
for port in $AZ_OPEN_PORTS; do
  if [[ "$port" == "22" ]]; then
    echo "[azure-provision-vm] tcp/22 is already handled by default NSG rules; skipping explicit open-port"
    continue
  fi
  priority=$((2000 + rule_index))
  rule_index=$((rule_index + 1))
  echo "[azure-provision-vm] opening tcp/$port"
  if ! az vm open-port \
    --resource-group "$AZ_RESOURCE_GROUP" \
    --name "$AZ_VM_NAME" \
    --port "$port" \
    --priority "$priority" \
    --output none; then
    echo "[azure-provision-vm] warning: open-port failed for tcp/$port; continuing"
  fi
done

PUBLIC_IP="$(az vm show -d --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --query publicIps -o tsv)"

echo
echo "[azure-provision-vm] done"
echo "  resource_group: $AZ_RESOURCE_GROUP"
echo "  vm_name:        $AZ_VM_NAME"
echo "  vm_size:        $AZ_VM_SIZE"
echo "  public_ip:      $PUBLIC_IP"
echo
echo "Next:"
echo "  export AZ_RESOURCE_GROUP=$AZ_RESOURCE_GROUP"
echo "  export AZ_VM_NAME=$AZ_VM_NAME"
echo "  export AZ_ADMIN_USER=$AZ_ADMIN_USER"
echo "  export AZ_PUBLIC_IP=$PUBLIC_IP"
echo "  bash scripts/azure-bootstrap-vm.sh"
