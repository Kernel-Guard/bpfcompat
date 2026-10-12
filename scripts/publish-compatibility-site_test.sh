#!/usr/bin/env bash
# Regression guard for scripts/publish-compatibility-site.sh.
#
# The public matrix page summarised each report as "Required pass/fail" where
# fail was computed as (required - pass). An infrastructure error (image
# download failed, VM never booted) was therefore shown as a compatibility
# failure. That contradicts the verdict contract: INFRA_ERROR is never a
# statement about the artifact. The page must:
#   1. count required targets as pass / fail / infra separately;
#   2. mark a report whose summary is not complete as incomplete, visibly;
#   3. keep counting a genuine required failure as a failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/publish-compatibility-site.sh"

command -v jq >/dev/null || { echo "SKIP: jq required" >&2; exit 0; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/reports"

# One required target passed, one required target is an infrastructure error,
# one required target genuinely failed. summary.complete is false.
cat >"$work/reports/quirk-library-fixture.json" <<'JSON'
{
  "schema_version": "v0.1",
  "run": {"id": "20261011T000000Z-test"},
  "artifact": {"basename": "fixture.bpf.o", "sha256": "0000"},
  "matrix": {"profiles": ["a", "b", "c"]},
  "summary": {"status": "fail", "verdict": "INFRA_ERROR", "complete": false},
  "targets": [
    {"profile_id": "a", "required": true, "status": "pass", "verdict": "COMPATIBLE"},
    {"profile_id": "b", "required": true, "status": "infra_error", "verdict": "INFRA_ERROR",
     "infra_error": "download image: unexpected HTTP status 502"},
    {"profile_id": "c", "required": true, "status": "fail", "verdict": "INCOMPATIBLE",
     "classification_code": "UNSUPPORTED_MAP_TYPE"}
  ]
}
JSON

out="$work/public"
( cd "$work" && BPFCOMPAT_COMPATIBILITY_VERSION=test-run bash "$SCRIPT" reports "$out" ) >/dev/null

fail=0
ok() { printf 'ok:   %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

md="$out/index.md"
html="$out/index.html"
[[ -f "$md" && -f "$html" ]] || { echo "FAIL: index files not generated" >&2; exit 1; }

# 1. pass / fail / infra are separate columns: 1 pass, 1 fail, 1 infra.
if grep -qE '\| 1 \| 1 \| 1 \|' "$md"; then
  ok "required counts are reported as pass=1 fail=1 infra=1"
else
  bad "required counts do not separate infra from fail"; cat "$md" >&2
fi
if grep -qE '1/2' "$md"; then
  bad "legacy pass/fail cell still counts infra_error as a failure"
else
  ok "infra_error is no longer folded into the failure count"
fi

# 2. incomplete report is visibly flagged.
if grep -qi 'incomplete' "$md" && grep -qi 'incomplete' "$html"; then
  ok "incomplete run is flagged on both index.md and index.html"
else
  bad "incomplete run is not flagged"
fi

# 3. verdict column present in the markdown table header.
if grep -qE '\| Verdict \|' "$md"; then
  ok "summary verdict column is present"
else
  bad "summary verdict column missing"
fi

# 4. summary.complete=false must be honoured even when every REQUIRED target
#    is conclusive (only an optional target is unresolved). jq's `//` treats
#    false as missing, so `(.summary.complete // true)` silently read it as true.
mkdir -p "$work/reports2"
cat >"$work/reports2/quirk-library-optional-gap.json" <<'JSON'
{
  "schema_version": "v0.1",
  "run": {"id": "20261011T000000Z-opt"},
  "artifact": {"basename": "fixture.bpf.o", "sha256": "0000"},
  "summary": {"status": "pass", "verdict": "COMPATIBLE", "complete": false},
  "targets": [
    {"profile_id": "a", "required": true, "status": "pass", "verdict": "COMPATIBLE"},
    {"profile_id": "b", "required": false, "status": "infra_error", "verdict": "INFRA_ERROR"}
  ]
}
JSON
( cd "$work" && BPFCOMPAT_COMPATIBILITY_VERSION=test-run2 bash "$SCRIPT" reports2 "$work/public2" ) >/dev/null
if grep -q '| incomplete |' "$work/public2/index.md"; then
  ok "summary.complete=false is flagged even when only an optional target is unresolved"
else
  bad "summary.complete=false was rendered as complete"; cat "$work/public2/index.md" >&2
fi

if [[ "$fail" -ne 0 ]]; then
  echo "publish-compatibility-site_test: FAILED" >&2
  exit 1
fi
echo "publish-compatibility-site_test: all checks passed"
