#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RHEL8_SRC="${RHEL8_IMG:-}"
SLES156_SRC="${SLES156_IMG:-}"

if [[ -z "$RHEL8_SRC" && -z "$SLES156_SRC" ]]; then
  cat >&2 <<'USAGE'
[import-required-images] missing required inputs.

Usage:
  make import-required-images \
    SLES156_IMG=/absolute/path/to/sles-15.6-image.qcow2

Optional:
  RHEL8_IMG=/absolute/path/to/rhel-8-image.qcow2
USAGE
  exit 2
fi

require_tool() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "[import-required-images] missing required tool: $name" >&2
    exit 3
  fi
}

require_tool qemu-img
require_tool jq

import_one() {
  local src="$1"
  local dst="$2"
  local label="$3"

  if [[ ! -f "$src" ]]; then
    echo "[import-required-images] source missing for $label: $src" >&2
    exit 4
  fi

  mkdir -p "$(dirname "$dst")"
  local tmp="${dst}.tmp"
  rm -f "$tmp"

  echo "[import-required-images] importing $label"
  qemu-img convert -p -O qcow2 "$src" "$tmp"
  mv -f "$tmp" "$dst"

  local fmt
  fmt="$(qemu-img info --output=json "$dst" | jq -r '.format')"
  if [[ "$fmt" != "qcow2" ]]; then
    echo "[import-required-images] imported image for $label is not qcow2: $fmt" >&2
    exit 5
  fi

  echo "[import-required-images] ready: $dst"
}

if [[ -n "$RHEL8_SRC" ]]; then
  import_one "$RHEL8_SRC" "vm/cache/rhel-8-4.18.qcow2" "rhel-8-4.18"
fi

if [[ -n "$SLES156_SRC" ]]; then
  import_one "$SLES156_SRC" "vm/cache/sles-15.6-6.4.qcow2" "sles-15.6-6.4"
fi

echo "[import-required-images] done"
