#!/usr/bin/env bash
set -euo pipefail

# Bootstrap required toolchain on an existing Azure VM.
#
# Required env:
#   AZ_RESOURCE_GROUP
#   AZ_VM_NAME
#
# Optional:
#   AZ_ADMIN_USER                     (default: azureuser)
#   AZ_PUBLIC_IP                      (used for final SSH hint)

AZ_RESOURCE_GROUP="${AZ_RESOURCE_GROUP:-}"
AZ_VM_NAME="${AZ_VM_NAME:-}"
AZ_ADMIN_USER="${AZ_ADMIN_USER:-azureuser}"
AZ_PUBLIC_IP="${AZ_PUBLIC_IP:-}"

if [[ -z "$AZ_RESOURCE_GROUP" || -z "$AZ_VM_NAME" ]]; then
  echo "[azure-bootstrap-vm] set AZ_RESOURCE_GROUP and AZ_VM_NAME first" >&2
  exit 1
fi

if ! command -v az >/dev/null 2>&1; then
  echo "[azure-bootstrap-vm] azure cli is required (az not found)" >&2
  exit 1
fi

if ! az account show >/dev/null 2>&1; then
  echo "[azure-bootstrap-vm] Azure login missing. Run: az login --use-device-code" >&2
  exit 1
fi

echo "[azure-bootstrap-vm] installing packages on VM via az vm run-command"
az vm run-command invoke \
  --resource-group "$AZ_RESOURCE_GROUP" \
  --name "$AZ_VM_NAME" \
  --command-id RunShellScript \
  --scripts '
set -eu
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y \
  build-essential \
  ca-certificates \
  curl \
  git \
  jq \
  make \
  pkg-config \
  clang \
  llvm \
  libbpf-dev \
  libelf-dev \
  zlib1g-dev \
  zstd \
  qemu-system-x86 \
  qemu-utils \
  qemu-kvm \
  openssh-client

if ! command -v go >/dev/null 2>&1; then
  sudo apt-get install -y golang
fi

if [ -e /dev/kvm ]; then
  echo "kvm_device=present"
else
  echo "kvm_device=missing"
fi
' \
  --output jsonc

if [[ -z "$AZ_PUBLIC_IP" ]]; then
  AZ_PUBLIC_IP="$(az vm show -d --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --query publicIps -o tsv)"
fi

echo
echo "[azure-bootstrap-vm] done"
echo "SSH:"
echo "  ssh ${AZ_ADMIN_USER}@${AZ_PUBLIC_IP}"
echo
echo "Then on VM:"
echo "  git clone <your-repo-url> ~/bpfcompat"
echo "  cd ~/bpfcompat"
echo "  make doctor"
echo "  make test-vendor"
echo "  make validator-static"
echo "  make examples"
echo "  make acceptance-dev-one"
