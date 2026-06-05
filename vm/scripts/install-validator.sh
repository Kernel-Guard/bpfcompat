#!/usr/bin/env bash
set -euo pipefail

rootfs_path="${1:-}"
validator_bin="${2:-validator/c-libbpf/bin/bpfcompat-validator}"

if [[ -z "$rootfs_path" ]]; then
  echo "Usage: $0 <rootfs-path> [validator-bin]" >&2
  exit 1
fi

if [[ ! -f "$validator_bin" ]]; then
  echo "Validator binary not found at $validator_bin" >&2
  exit 1
fi

echo "install-validator.sh is scaffolded only."
echo "Target rootfs: $rootfs_path"
echo "Validator binary: $validator_bin"

