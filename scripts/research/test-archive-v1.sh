#!/usr/bin/env bash
set -euo pipefail

pilot_zip="${1:?pilot zip required}"
repeat_zip="${2:?repeat zip required}"
materialization_zip="${3:?materialization zip required}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
bundle="$tmp/archive"

python3 scripts/research/archive-v1.py build   --pilot-zip "$pilot_zip"   --repeat-zip "$repeat_zip"   --materialization-zip "$materialization_zip"   --out-dir "$bundle"

python3 scripts/research/archive-v1.py verify   --pilot-zip "$pilot_zip"   --repeat-zip "$repeat_zip"   --materialization-zip "$materialization_zip"   --bundle-dir "$bundle"

cp -a "$bundle" "$tmp/bad-status"
python3 - "$tmp/bad-status/archive-manifest.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text())
row = next(
    item
    for item in doc["payload"]["files"]
    if item["provenance_class"].startswith("third-party")
)
row["redistribution_status"] = "include"
path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PY
if python3 scripts/research/archive-v1.py verify   --pilot-zip "$pilot_zip"   --repeat-zip "$repeat_zip"   --materialization-zip "$materialization_zip"   --bundle-dir "$tmp/bad-status"; then
  echo "expected third-party plain-include mutation to fail" >&2
  exit 1
fi

cp -a "$bundle" "$tmp/bad-excluded"
mkdir -p "$tmp/bad-excluded/payload/materialized/loaders"
unzip -p "$materialization_zip" loaders/ebpf-go-loader   > "$tmp/bad-excluded/payload/materialized/loaders/ebpf-go-loader"
if python3 scripts/research/archive-v1.py verify   --pilot-zip "$pilot_zip"   --repeat-zip "$repeat_zip"   --materialization-zip "$materialization_zip"   --bundle-dir "$tmp/bad-excluded"; then
  echo "expected excluded-loader injection to fail" >&2
  exit 1
fi

echo "[test-archive-v1] PASS"
