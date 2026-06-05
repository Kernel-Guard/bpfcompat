#!/usr/bin/env bash
set -euo pipefail

arch="$(uname -m)"
case "$arch" in
  aarch64|arm64)
    ;;
  *)
    echo "ARM64 VM proof requires a native ARM64/aarch64 KVM host; current host is ${arch}" >&2
    echo "Use .github/workflows/arm64-build-smoke.yml for compile proof on hosted ARM64, and .github/workflows/multiarch-compatibility.yml on a self-hosted ARM64 KVM runner for VM proof." >&2
    exit 2
    ;;
esac

if [[ ! -e /dev/kvm ]]; then
  echo "missing /dev/kvm" >&2
  exit 1
fi
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo "/dev/kvm exists but is not readable and writable by this user" >&2
  exit 1
fi
if ! command -v qemu-system-aarch64 >/dev/null; then
  echo "missing qemu-system-aarch64" >&2
  exit 1
fi

echo "arm64 KVM preflight passed"
