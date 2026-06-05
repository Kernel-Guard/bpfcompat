#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

missing=0

find_cmd() {
  local name="$1"
  local env_name="$2"
  local explicit="${!env_name:-}"
  if [[ -n "$explicit" && -x "$explicit" ]]; then
    printf '%s' "$explicit"
    return 0
  fi
  if command -v "$name" >/dev/null; then
    command -v "$name"
    return 0
  fi
  if [[ -x "bin/$name" ]]; then
    printf '%s' "$ROOT_DIR/bin/$name"
    return 0
  fi
  return 1
}

check_cmd() {
  local name="$1"
  local env_name="$2"
  if ! find_cmd "$name" "$env_name" >/dev/null; then
    echo "missing ${name}" >&2
    missing=1
  fi
}

check_file() {
  local label="$1"
  local path="$2"
  if [[ -z "$path" ]]; then
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    echo "missing ${label}: ${path}" >&2
    missing=1
  fi
}

check_cmd firecracker BPFCOMPAT_FIRECRACKER_BIN
check_cmd busybox BPFCOMPAT_BUSYBOX_BIN
check_cmd cpio BPFCOMPAT_CPIO_BIN
check_cmd gzip BPFCOMPAT_GZIP_BIN
if ! find_cmd jailer BPFCOMPAT_FIRECRACKER_JAILER_BIN >/dev/null; then
  echo "warning: jailer not found; production Firecracker deployments should use jailer or equally restrictive process constraints" >&2
fi

if [[ ! -e /dev/kvm ]]; then
  echo "missing /dev/kvm" >&2
  missing=1
elif [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo "/dev/kvm exists but is not readable and writable by this user" >&2
  missing=1
fi

check_file "firecracker kernel image" "${BPFCOMPAT_FIRECRACKER_KERNEL:-}"
check_file "firecracker rootfs" "${BPFCOMPAT_FIRECRACKER_ROOTFS:-}"
check_file "firecracker initrd" "${BPFCOMPAT_FIRECRACKER_INITRD:-}"

if [[ -z "${BPFCOMPAT_FIRECRACKER_KERNEL:-}" ]]; then
  cached_kernel="$(find .bpfcompat/firecracker-assets -maxdepth 1 -type f -name 'vmlinux-*' ! -name '*.gz' ! -name '*.debug' ! -name '*.config' ! -name '*.id' ! -name '*.map' 2>/dev/null | sort -V | tail -n1 || true)"
  if [[ -z "$cached_kernel" ]]; then
    echo "warning: BPFCOMPAT_FIRECRACKER_KERNEL is not set; run make firecracker-kernel-install or set an uncompressed guest kernel image before execution" >&2
  fi
fi

if [[ "$missing" -ne 0 ]]; then
  exit 1
fi

echo "firecracker preflight passed"
