#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MATRIX="${BPFCOMPAT_MATRIX:-matrices/expanded-2026.yaml}"
OUT_MATRIX="${BPFCOMPAT_OUT_MATRIX:-matrices/expanded-2026-runnable.yaml}"
INCLUDE_UNSUPPORTED_TRANSPORT="${BPFCOMPAT_INCLUDE_UNSUPPORTED_TRANSPORT:-0}"
INCLUDE_MISSING_MANUAL="${BPFCOMPAT_INCLUDE_MISSING_MANUAL:-0}"
FAIL_ON_REQUIRED_EXCLUDED="${BPFCOMPAT_FAIL_ON_REQUIRED_EXCLUDED:-0}"

if [[ ! -f "$MATRIX" ]]; then
  echo "[matrix-runnable] missing matrix file: $MATRIX" >&2
  exit 1
fi

python3 - <<'PY'
import os
import sys
import yaml

matrix_path = os.environ.get("BPFCOMPAT_MATRIX", "matrices/expanded-2026.yaml")
out_path = os.environ.get("BPFCOMPAT_OUT_MATRIX", "matrices/expanded-2026-runnable.yaml")
include_unsupported = os.environ.get("BPFCOMPAT_INCLUDE_UNSUPPORTED_TRANSPORT", "0") == "1"
include_missing_manual = os.environ.get("BPFCOMPAT_INCLUDE_MISSING_MANUAL", "0") == "1"
fail_on_required_excluded = os.environ.get("BPFCOMPAT_FAIL_ON_REQUIRED_EXCLUDED", "0") == "1"

with open(matrix_path, "r", encoding="utf-8") as f:
    matrix = yaml.safe_load(f) or {}

profiles = matrix.get("profiles") or []
if not profiles:
    print("[matrix-runnable] source matrix has no profiles", file=sys.stderr)
    sys.exit(1)

kept = []
excluded = []
excluded_required = []

for entry in profiles:
    pid = str((entry or {}).get("id", "")).strip()
    if not pid:
        continue
    required = bool((entry or {}).get("required", True))
    ppath = os.path.join("vm", "profiles", pid + ".yaml")
    if not os.path.exists(ppath):
        excluded.append((pid, required, "profile file missing"))
        if required:
            excluded_required.append(pid)
        continue

    with open(ppath, "r", encoding="utf-8") as pf:
        pdoc = yaml.safe_load(pf) or {}

    distro = str((pdoc.get("distro") or "")).strip().lower()
    image = pdoc.get("image") or {}
    local_path = str((image.get("local_path") or "")).strip()
    source_url = str((image.get("source_url") or "")).strip()

    transport_supported = distro not in {"talos", "bottlerocket", "flatcar"} and pid not in {"amazon-linux-2-4.14"}
    manual_missing = (not source_url) and (not local_path or not os.path.exists(local_path))

    if (not transport_supported) and (not include_unsupported):
        reason = "unsupported transport for current SSH executor"
        excluded.append((pid, required, reason))
        if required:
            excluded_required.append(pid)
        continue

    if manual_missing and (not include_missing_manual):
        reason = f"manual-local image missing ({local_path})"
        excluded.append((pid, required, reason))
        if required:
            excluded_required.append(pid)
        continue

    kept.append({"id": pid, "required": required})

if not kept:
    print("[matrix-runnable] no runnable profiles remained after filtering", file=sys.stderr)
    sys.exit(2)

name = str(matrix.get("name") or os.path.basename(matrix_path).replace(".yaml", "")).strip()
if not name:
    name = "matrix"
runnable = {"name": name + "-runnable", "profiles": kept}

os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
with open(out_path, "w", encoding="utf-8") as out:
    yaml.safe_dump(runnable, out, sort_keys=False)

print(f"[matrix-runnable] source={matrix_path}")
print(f"[matrix-runnable] output={out_path}")
print(f"[matrix-runnable] kept={len(kept)} excluded={len(excluded)}")
if excluded:
    print("[matrix-runnable] excluded profiles:")
    for pid, required, reason in excluded:
        req = "required" if required else "optional"
        print(f"  - {pid} ({req}): {reason}")
if excluded_required:
    print("[matrix-runnable] WARNING: required profiles were excluded from runnable matrix:", file=sys.stderr)
    print("[matrix-runnable]   " + ", ".join(excluded_required), file=sys.stderr)
    if fail_on_required_excluded:
        sys.exit(3)
PY
