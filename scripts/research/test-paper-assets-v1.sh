#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 scripts/research/generate-paper-assets-v1.py --out-dir "$tmp/generated"
diff -ru research/paper/generated "$tmp/generated"

python3 - <<'PY'
import json
from pathlib import Path

manifest=json.loads(Path("research/paper/generated/asset-manifest.json").read_text())
assert manifest["schema_version"]=="bpfcompat.research.paper-assets.v1"
assert manifest["claims"]=={
    "pilot_attempts":70,
    "repeat_attempts":21,
    "figures":3,
    "tables":4,
}
assert len(manifest["outputs"])==7
print("[test-paper-assets-v1] manifest assertions PASS")
PY

echo "[test-paper-assets-v1] PASS"
