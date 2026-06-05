#!/usr/bin/env bash
set -euo pipefail

# Configure HTTPS reverse proxy for bpfcompat on Azure VM using Caddy.
#
# Required env:
#   AZ_RESOURCE_GROUP
#   AZ_VM_NAME
#   BPFCOMPAT_DOMAIN                 (DNS A record must point to VM public IP)
#
# Optional:
#   AZ_BACKEND_ADDR                  (default: 127.0.0.1:8080)
#   AZ_ENABLE_HTTP_REDIRECT          (default: true)

AZ_RESOURCE_GROUP="${AZ_RESOURCE_GROUP:-}"
AZ_VM_NAME="${AZ_VM_NAME:-}"
BPFCOMPAT_DOMAIN="${BPFCOMPAT_DOMAIN:-}"
AZ_BACKEND_ADDR="${AZ_BACKEND_ADDR:-127.0.0.1:8080}"
AZ_ENABLE_HTTP_REDIRECT="${AZ_ENABLE_HTTP_REDIRECT:-true}"

if [[ -z "$AZ_RESOURCE_GROUP" || -z "$AZ_VM_NAME" || -z "$BPFCOMPAT_DOMAIN" ]]; then
  echo "[azure-configure-tls] set AZ_RESOURCE_GROUP, AZ_VM_NAME, and BPFCOMPAT_DOMAIN first" >&2
  exit 1
fi

if ! command -v az >/dev/null 2>&1; then
  echo "[azure-configure-tls] azure cli is required (az not found)" >&2
  exit 1
fi

if ! az account show >/dev/null 2>&1; then
  echo "[azure-configure-tls] Azure login missing. Run: az login --use-device-code" >&2
  exit 1
fi

PUBLIC_IP="$(az vm show -d --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --query publicIps -o tsv)"
if [[ -z "$PUBLIC_IP" ]]; then
  echo "[azure-configure-tls] unable to resolve VM public IP" >&2
  exit 1
fi

echo "[azure-configure-tls] VM public IP: $PUBLIC_IP"
echo "[azure-configure-tls] ensure DNS A record is set:"
echo "  $BPFCOMPAT_DOMAIN -> $PUBLIC_IP"

echo "[azure-configure-tls] opening inbound ports 80 and 443 on VM NSG"
az vm open-port --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --port 80 --priority 1800 --output none || true
az vm open-port --resource-group "$AZ_RESOURCE_GROUP" --name "$AZ_VM_NAME" --port 443 --priority 1801 --output none || true

if [[ "$AZ_ENABLE_HTTP_REDIRECT" == "true" ]]; then
  CADDY_BLOCK="${BPFCOMPAT_DOMAIN} {
  encode gzip zstd
  header Strict-Transport-Security \"max-age=31536000; includeSubDomains\"
  reverse_proxy ${AZ_BACKEND_ADDR}
}"
else
  CADDY_BLOCK="http://${BPFCOMPAT_DOMAIN} {
  reverse_proxy ${AZ_BACKEND_ADDR}
}"
fi

echo "[azure-configure-tls] installing caddy and configuring reverse proxy"
az vm run-command invoke \
  --resource-group "$AZ_RESOURCE_GROUP" \
  --name "$AZ_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
set -eu
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
if [ ! -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg ]; then
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
fi
if [ ! -f /etc/apt/sources.list.d/caddy-stable.list ]; then
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
fi
sudo apt-get update -y
sudo apt-get install -y caddy
sudo tee /etc/caddy/Caddyfile >/dev/null <<'EOF_CADDY'
${CADDY_BLOCK}
EOF_CADDY
sudo systemctl daemon-reload
sudo systemctl enable caddy
sudo systemctl restart caddy
sudo systemctl --no-pager --full status caddy | head -n 40
" \
  --output jsonc

echo
echo "[azure-configure-tls] done"
if [[ "$AZ_ENABLE_HTTP_REDIRECT" == "true" ]]; then
  echo "  URL: https://${BPFCOMPAT_DOMAIN}"
else
  echo "  URL: http://${BPFCOMPAT_DOMAIN}"
fi
