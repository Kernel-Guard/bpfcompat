#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MATRIX="${BPFCOMPAT_MATRIX:-matrices/expanded-2026.yaml}"
FAIL_ON_MISSING_REQUIRED="${BPFCOMPAT_FAIL_ON_MISSING_REQUIRED:-0}"

if [[ ! -f "$MATRIX" ]]; then
  echo "[manual-image-check] missing matrix: $MATRIX" >&2
  exit 1
fi

python3 - <<'PY'
import os
import sys
import yaml

matrix_path = os.environ.get("BPFCOMPAT_MATRIX", "matrices/expanded-2026.yaml")
fail_on_missing_required = os.environ.get("BPFCOMPAT_FAIL_ON_MISSING_REQUIRED", "0") == "1"

with open(matrix_path, "r", encoding="utf-8") as f:
    matrix = yaml.safe_load(f) or {}

profiles = matrix.get("profiles") or []
missing_required = []
missing_optional = []
present = 0

print(f"[manual-image-check] matrix={matrix_path}")
print("[manual-image-check] manual-local profiles:")

for entry in profiles:
    pid = str((entry or {}).get("id", "")).strip()
    if not pid:
        continue
    required = bool((entry or {}).get("required", True))
    ppath = os.path.join("vm", "profiles", pid + ".yaml")
    if not os.path.exists(ppath):
        continue
    with open(ppath, "r", encoding="utf-8") as pf:
        pdoc = yaml.safe_load(pf) or {}
    image = pdoc.get("image") or {}
    source_url = str((image.get("source_url") or "")).strip()
    local_path = str((image.get("local_path") or "")).strip()

    if source_url:
        continue

    if local_path and os.path.exists(local_path):
        present += 1
        state = "cached"
    else:
        state = "missing"
        if required:
            missing_required.append((pid, local_path))
        else:
            missing_optional.append((pid, local_path))
    req = "required" if required else "optional"
    print(f"  - {pid} ({req}): {state} ({local_path})")

print()
print(f"[manual-image-check] cached manual-local profiles: {present}")
print(f"[manual-image-check] missing required manual-local profiles: {len(missing_required)}")
print(f"[manual-image-check] missing optional manual-local profiles: {len(missing_optional)}")

if missing_required:
    print("[manual-image-check] required manual-local imports still missing:")
    for pid, local_path in missing_required:
        print(f"  - {pid}: {local_path}")

if fail_on_missing_required and missing_required:
    sys.exit(3)
PY
