#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_MATRIX="${BPFCOMPAT_OUT_MATRIX:-matrices/firecracker-dev-one.yaml}"
PROFILE_DIR="${BPFCOMPAT_PROFILE_DIR:-vm/profiles}"
PROFILE_ID="${BPFCOMPAT_FIRECRACKER_PROFILE_ID:-firecracker-dev-one}"
KERNEL_PATH="${BPFCOMPAT_FIRECRACKER_KERNEL:-}"
ARCH="${BPFCOMPAT_FIRECRACKER_ARCH:-$(uname -m)}"

if [[ -z "$KERNEL_PATH" ]]; then
  KERNEL_PATH="$(find .bpfcompat/firecracker-assets -maxdepth 1 -type f -name 'vmlinux-*' 2>/dev/null | sort -V | tail -n1 || true)"
fi

if [[ -z "$KERNEL_PATH" || ! -f "$KERNEL_PATH" ]]; then
  echo "missing Firecracker kernel image; run make firecracker-kernel-install or set BPFCOMPAT_FIRECRACKER_KERNEL" >&2
  exit 1
fi

kernel_version="$(basename "$KERNEL_PATH" | sed -E 's/^vmlinux-//')"
if [[ -z "$kernel_version" ]]; then
  kernel_version="unknown"
fi

mkdir -p "$PROFILE_DIR" "$(dirname "$OUT_MATRIX")"

cat > "${PROFILE_DIR}/${PROFILE_ID}.yaml" <<EOF
id: ${PROFILE_ID}
distro: firecracker-ci-kernel
version: "${kernel_version}"
kernel_family: "${kernel_version}"
arch: ${ARCH}
runner: firecracker
firecracker:
  kernel_image_path: "${KERNEL_PATH}"
  boot_args: "console=ttyS0 reboot=k panic=1 pci=off init=/init"
boot:
  memory_mb: 1024
  cpus: 1
validator:
  path: "/bpfcompat/bin/bpfcompat-validator"
capabilities:
  expected_btf: true
EOF

cat > "$OUT_MATRIX" <<EOF
name: firecracker-dev-one
profiles:
  - id: ${PROFILE_ID}
    required: false
EOF

echo "generated Firecracker profile ${PROFILE_DIR}/${PROFILE_ID}.yaml"
echo "generated Firecracker matrix ${OUT_MATRIX}"
