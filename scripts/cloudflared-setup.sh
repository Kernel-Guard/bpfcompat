#!/usr/bin/env bash
# Set up a Cloudflare Tunnel that publishes api.kernelguard.net and forwards to
# a local bpfcompat serve process (127.0.0.1:8080). Run this ON the box that
# runs `bpfcompat serve`. It is intentionally interactive at the login step
# (browser auth) and otherwise idempotent-ish — re-running reuses an existing
# tunnel of the same name.
#
# Prereqs on the box:
#   - cloudflared installed (https://pkg.cloudflare.com / GitHub releases)
#   - bpfcompat serve running on 127.0.0.1:8080 with
#     BPFCOMPAT_GITHUB_MARKETPLACE_WEBHOOK_SECRET set (see
#     packaging/systemd/bpfcompat-serve.env.example)
#
# Usage:
#   ./scripts/cloudflared-setup.sh
#
# Override the defaults via env:
#   TUNNEL_NAME   (default: bpfcompat-api)
#   HOSTNAME      (default: api.kernelguard.net)
#   BACKEND       (default: http://127.0.0.1:8080)
set -euo pipefail

TUNNEL_NAME="${TUNNEL_NAME:-bpfcompat-api}"
HOSTNAME="${HOSTNAME:-api.kernelguard.net}"
BACKEND="${BACKEND:-http://127.0.0.1:8080}"
CFG_DIR="/etc/cloudflared"

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "[cloudflared-setup] cloudflared not found — install it first:" >&2
  echo "  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/" >&2
  exit 1
fi

echo "[cloudflared-setup] 1/5 authenticating to Cloudflare (pick the kernelguard.net zone in the browser)"
cloudflared tunnel login

echo "[cloudflared-setup] 2/5 creating tunnel ${TUNNEL_NAME} (reused if it already exists)"
if ! cloudflared tunnel list | awk '{print $2}' | grep -qx "${TUNNEL_NAME}"; then
  cloudflared tunnel create "${TUNNEL_NAME}"
fi

TUNNEL_ID="$(cloudflared tunnel list | awk -v n="${TUNNEL_NAME}" '$2==n {print $1}' | head -n1)"
if [[ -z "${TUNNEL_ID}" ]]; then
  echo "[cloudflared-setup] could not resolve tunnel id for ${TUNNEL_NAME}" >&2
  exit 1
fi
echo "[cloudflared-setup]   tunnel id: ${TUNNEL_ID}"

echo "[cloudflared-setup] 3/5 routing DNS ${HOSTNAME} -> tunnel (creates the proxied CNAME in Cloudflare)"
cloudflared tunnel route dns "${TUNNEL_NAME}" "${HOSTNAME}"

echo "[cloudflared-setup] 4/5 writing ${CFG_DIR}/config.yml"
sudo mkdir -p "${CFG_DIR}"
# The credentials file is created by `tunnel create` under ~/.cloudflared; move
# it where the system service can read it.
CRED_SRC="${HOME}/.cloudflared/${TUNNEL_ID}.json"
if [[ -f "${CRED_SRC}" ]]; then
  sudo cp "${CRED_SRC}" "${CFG_DIR}/${TUNNEL_ID}.json"
  sudo chmod 0600 "${CFG_DIR}/${TUNNEL_ID}.json"
fi
sudo tee "${CFG_DIR}/config.yml" >/dev/null <<EOF
tunnel: ${TUNNEL_ID}
credentials-file: ${CFG_DIR}/${TUNNEL_ID}.json

ingress:
  - hostname: ${HOSTNAME}
    service: ${BACKEND}
  - service: http_status:404
EOF

echo "[cloudflared-setup] 5/5 installing + starting the cloudflared system service"
sudo cloudflared service install || true
sudo systemctl enable --now cloudflared

echo "[cloudflared-setup] done. Verify:"
echo "  curl -i https://${HOSTNAME}/livez                       # 200 = tunnel + server up"
echo "  curl -i -X POST https://${HOSTNAME}/github/marketplace/webhook  # 401 = webhook live & verifying"
