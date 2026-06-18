#!/usr/bin/env bash
set -euo pipefail

# Bootstrap a Hetzner bare-metal (dedicated / Server Auction) host for the
# bpfcompat public demo. Hetzner has no `az vm run-command` equivalent, so this
# runs over plain SSH. Bare metal is required because Hetzner Cloud does NOT
# expose nested virtualization (no /dev/kvm); the demo boots real QEMU/KVM
# guests, so this script hard-fails if /dev/kvm is absent.
#
# Required env:
#   HETZNER_HOST                      public IP or hostname of the server
#
# Optional:
#   HETZNER_USER                      ssh user (default: root; Hetzner rescue/initial install gives root)
#   HETZNER_SSH_KEY                   path to ssh private key (default: ssh-agent / ~/.ssh default)
#   BPFCOMPAT_REPO_URL                git URL to clone (default: https://github.com/Kernel-Guard/bpfcompat.git)
#   BPFCOMPAT_REPO_REF                branch/tag/commit to check out (default: main)

HETZNER_HOST="${HETZNER_HOST:-}"
HETZNER_USER="${HETZNER_USER:-root}"
HETZNER_SSH_KEY="${HETZNER_SSH_KEY:-}"
BPFCOMPAT_REPO_URL="${BPFCOMPAT_REPO_URL:-https://github.com/Kernel-Guard/bpfcompat.git}"
BPFCOMPAT_REPO_REF="${BPFCOMPAT_REPO_REF:-main}"

if [[ -z "$HETZNER_HOST" ]]; then
  echo "[hetzner-bootstrap-vm] set HETZNER_HOST first" >&2
  exit 1
fi

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=20)
if [[ -n "$HETZNER_SSH_KEY" ]]; then
  SSH_OPTS+=(-i "$HETZNER_SSH_KEY")
fi

echo "[hetzner-bootstrap-vm] bootstrapping ${HETZNER_USER}@${HETZNER_HOST}"

# shellcheck disable=SC2087  # heredoc is intentionally expanded locally for repo url/ref
ssh "${SSH_OPTS[@]}" "${HETZNER_USER}@${HETZNER_HOST}" bash -s <<EOF
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[remote] installing toolchain + qemu/kvm"
sudo apt-get update -y
sudo apt-get install -y \
  build-essential ca-certificates curl git jq make pkg-config \
  clang llvm libbpf-dev libelf-dev zlib1g-dev zstd \
  qemu-system-x86 qemu-utils qemu-kvm openssh-client

if ! command -v go >/dev/null 2>&1; then
  sudo apt-get install -y golang
fi

# Bare metal MUST expose /dev/kvm. If it is missing the box is not suitable for
# the demo (no native virt) -- fail loudly rather than silently fall back to TCG.
if [ ! -e /dev/kvm ]; then
  echo "[remote] FATAL: /dev/kvm missing -- this host cannot run KVM guests." >&2
  echo "[remote] Confirm you ordered a bare-metal server (not Hetzner Cloud) with VT-x/AMD-V." >&2
  exit 1
fi
echo "[remote] kvm_device=present"

echo "[remote] creating bpfcompat-demo service user (in kvm group)"
if ! getent group bpfcompat-demo >/dev/null; then
  sudo groupadd --system bpfcompat-demo
fi
if ! id -u bpfcompat-demo >/dev/null 2>&1; then
  sudo useradd --system --gid bpfcompat-demo --groups kvm \
    --home-dir /var/lib/bpfcompat-demo --shell /usr/sbin/nologin bpfcompat-demo
else
  sudo usermod -aG kvm bpfcompat-demo
fi
sudo install -d -m 0750 -o bpfcompat-demo -g bpfcompat-demo /var/lib/bpfcompat-demo

echo "[remote] cloning ${BPFCOMPAT_REPO_URL} @ ${BPFCOMPAT_REPO_REF}"
sudo rm -rf /opt/bpfcompat-src
sudo git clone "${BPFCOMPAT_REPO_URL}" /opt/bpfcompat-src
cd /opt/bpfcompat-src
sudo git checkout "${BPFCOMPAT_REPO_REF}"

echo "[remote] building bpfcompat + static validator + examples"
sudo make build
sudo make validator-static
sudo make examples

echo "[remote] installing /usr/local/bin/bpfcompat"
sudo install -m 0755 ./bin/bpfcompat /usr/local/bin/bpfcompat

echo "[remote] installing demo serve systemd unit + env stub"
sudo install -d -m 0750 /etc/bpfcompat
if [ ! -f /etc/bpfcompat/serve.env ]; then
  sudo install -m 0600 packaging/systemd/bpfcompat-serve.env.example /etc/bpfcompat/serve.env
  echo "[remote] created /etc/bpfcompat/serve.env -- set BPFCOMPAT_API_WRITE_KEY before enabling"
fi
sudo install -m 0644 packaging/systemd/bpfcompat-serve.service /etc/systemd/system/bpfcompat-serve.service
sudo systemctl daemon-reload

echo "[remote] bpfcompat version:"
/usr/local/bin/bpfcompat version || /usr/local/bin/bpfcompat --version || true
EOF

cat <<MSG

[hetzner-bootstrap-vm] done. Next:
  1. Set the write key on the server:
       ssh ${HETZNER_USER}@${HETZNER_HOST} \\
         "sudo sed -i 's|^BPFCOMPAT_API_WRITE_KEY=.*|BPFCOMPAT_API_WRITE_KEY='\$(openssl rand -hex 32)'|' /etc/bpfcompat/serve.env"
  2. Enable the demo server (binds 127.0.0.1:8080):
       ssh ${HETZNER_USER}@${HETZNER_HOST} "sudo systemctl enable --now bpfcompat-serve.service"
       ssh ${HETZNER_USER}@${HETZNER_HOST} "systemctl --no-pager status bpfcompat-serve.service"
  3. Point DNS A record at ${HETZNER_HOST}, then run:
       HETZNER_HOST=${HETZNER_HOST} BPFCOMPAT_DOMAIN=demo.kernelguard.net make hetzner-configure-tls
MSG
