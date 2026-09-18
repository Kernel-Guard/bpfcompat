#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/reports" "$tmp/out"

python3 - "$tmp/reports/simple-pass-libbpf.json" <<'PY'
import json, sys
path=sys.argv[1]
profiles=json.load(open("research/corpus/v1/profile-identities.json"))["profiles"]
targets=[]
for p in profiles:
    pid=p["id"]
    targets.append({
        "profile_id": pid,
        "required": False,
        "status": "pass",
        "verdict": "COMPATIBLE",
        "environment": {
            "requested_kernel_family": "test",
            "observed_kernel": "test.0-fixture",
            "kernel_family_match": True,
            "image_source_url": "https://example.invalid/image",
            "image_sha256": "1"*64,
        },
        "profile": {
            "distro": "fixture",
            "version": "1",
            "kernel_family": "test",
            "arch": "x86_64",
        },
        "host": {"kernel": "test.0-fixture", "arch": "x86_64"},
        "notes": [],
    })
doc={
    "schema_version":"v0.1",
    "run":{"id":"fixture","started_at":"2026-09-18T00:00:00Z"},
    "artifact":{
        "sha256":"41647d6d49fc72763fe8e2e7ee0a3b74f92d317de2595d8c95a4ca29b6fd0b0f"
    },
    "validator":{
        "sha256":"4ae1d5b838be07e6e7c304d753389a239c19eb92f6ba3bd77657e5c9583b9d04"
    },
    "targets":targets,
}
json.dump(doc, open(path,"w"))
PY

# Build a temporary one-case plan so the fixture tests normalization mechanics
# without pretending the remaining six study cases ran.
jq '.cases = [.cases[0]] | .expected_profiles = 10'   research/corpus/v1/study-plan.json > "$tmp/plan.json"

python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports"   --study-plan "$tmp/plan.json"   --out-dir "$tmp/out"

jq -e '
  .collection_complete == true and
  .observed_execution_records == 10 and
  .totals.compatible == 10 and
  (.missing_environments | length) == 0 and
  (.environment_drift | length) == 0
' "$tmp/out/collection-summary.json" >/dev/null

test "$(wc -l < "$tmp/out/executions.jsonl")" -eq 10
echo "[test-normalize-study-v1] PASS"
