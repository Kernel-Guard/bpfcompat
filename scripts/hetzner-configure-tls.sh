#!/usr/bin/env bash
set -euo pipefail

# Configure the HTTPS reverse proxy (Caddy + Let's Encrypt) and host firewall on
# a Hetzner bare-metal host for the bpfcompat demo. Runs over plain SSH.
#
# Hetzner bare metal has no cloud-firewall/NSG, so this uses ufw on the host:
# only 22/80/443 are opened; the demo backend stays bound to 127.0.0.1:8080 and
# is never exposed directly.
#
# Required env:
#   HETZNER_HOST                      public IP or hostname (DNS A record must already point here)
#   BPFCOMPAT_DOMAIN                  demo domain, e.g. demo.kernelguard.net
#
# Optional:
#   HETZNER_USER                      ssh user (default: root)
#   HETZNER_SSH_KEY                   path to ssh private key
#   BPFCOMPAT_BACKEND_ADDR            reverse-proxy target (default: 127.0.0.1:8080)

HETZNER_HOST="${HETZNER_HOST:-}"
BPFCOMPAT_DOMAIN="${BPFCOMPAT_DOMAIN:-}"
HETZNER_USER="${HETZNER_USER:-root}"
HETZNER_SSH_KEY="${HETZNER_SSH_KEY:-}"
BPFCOMPAT_BACKEND_ADDR="${BPFCOMPAT_BACKEND_ADDR:-127.0.0.1:8080}"

if [[ -z "$HETZNER_HOST" || -z "$BPFCOMPAT_DOMAIN" ]]; then
  echo "[hetzner-configure-tls] set HETZNER_HOST and BPFCOMPAT_DOMAIN first" >&2
  exit 1
fi

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=20)
if [[ -n "$HETZNER_SSH_KEY" ]]; then
  SSH_OPTS+=(-i "$HETZNER_SSH_KEY")
fi

echo "[hetzner-configure-tls] ensure DNS A record is set:"
echo "  ${BPFCOMPAT_DOMAIN} -> ${HETZNER_HOST}"

CADDY_BLOCK="${BPFCOMPAT_DOMAIN} {
  encode gzip zstd
  header Strict-Transport-Security \"max-age=31536000; includeSubDomains\"
  reverse_proxy ${BPFCOMPAT_BACKEND_ADDR}
}"

# shellcheck disable=SC2087  # heredoc is intentionally expanded locally to inject CADDY_BLOCK
ssh "${SSH_OPTS[@]}" "${HETZNER_USER}@${HETZNER_HOST}" bash -s <<EOF
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[remote] host firewall: allow 22/80/443 only (backend stays on 127.0.0.1)"
sudo apt-get update -y
sudo apt-get install -y ufw
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
sudo ufw status verbose | head -n 20

echo "[remote] installing caddy"
sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
if [ ! -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg ]; then
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
fi
if [ ! -f /etc/apt/sources.list.d/caddy-stable.list ]; then
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
fi
sudo apt-get update -y
sudo apt-get install -y caddy

echo "[remote] writing /etc/caddy/Caddyfile"
sudo tee /etc/caddy/Caddyfile >/dev/null <<'EOF_CADDY'
${CADDY_BLOCK}
EOF_CADDY
sudo systemctl daemon-reload
sudo systemctl enable caddy
sudo systemctl restart caddy
sudo systemctl --no-pager --full status caddy | head -n 30
EOF

cat <<MSG

[hetzner-configure-tls] done
  URL:    https://${BPFCOMPAT_DOMAIN}
  Health: https://${BPFCOMPAT_DOMAIN}/api/health

If using Cloudflare, keep the A record "DNS only" (grey cloud) so Caddy can
complete the Let's Encrypt HTTP-01 challenge on first request.
MSG
