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

# 5-8. A required target that passed on a kernel outside the requested family
#      has not established the requested contract. pkg/schema RunVerdict rolls
#      it up as INFRA_ERROR, so the page must count it under Required infra --
#      never as a required pass. Run 38404268435 published "Required pass 8,
#      infra 0" next to an INFRA_ERROR/incomplete summary because
#      oracle-linux-9-uek7-5.15 (requested 5.15) booted 6.12.0 UEK.
mkdir -p "$work/reports3"
cat >"$work/reports3/quirk-library-mismatch.json" <<'JSON'
{
  "schema_version": "v0.1",
  "run": {"id": "20261013T000000Z-mismatch"},
  "artifact": {"basename": "fixture.bpf.o", "sha256": "0000"},
  "summary": {"status": "error", "verdict": "INFRA_ERROR", "complete": false},
  "targets": [
    {"profile_id": "matched", "required": true, "status": "pass", "verdict": "COMPATIBLE",
     "environment": {"requested_kernel_family": "5.14", "observed_kernel": "5.14.0-756.el9.x86_64", "kernel_family_match": true},
     "host": {"kernel": "5.14.0-756.el9.x86_64"}},
    {"profile_id": "uek-trap", "required": true, "status": "pass", "verdict": "COMPATIBLE",
     "environment": {"requested_kernel_family": "5.15", "observed_kernel": "6.12.0-107.59.3.3.el9uek.x86_64", "kernel_family_match": false},
     "host": {"kernel": "6.12.0-107.59.3.3.el9uek.x86_64"}},
    {"profile_id": "real-fail", "required": true, "status": "fail", "verdict": "INCOMPATIBLE",
     "classification_code": "UNSUPPORTED_MAP_TYPE",
     "environment": {"requested_kernel_family": "4.14", "observed_kernel": "5.10.1", "kernel_family_match": false}},
    {"profile_id": "optional-trap", "required": false, "status": "pass", "verdict": "COMPATIBLE",
     "environment": {"requested_kernel_family": "5.4", "observed_kernel": "5.15.0-1", "kernel_family_match": false}}
  ]
}
JSON
( cd "$work" && BPFCOMPAT_COMPATIBILITY_VERSION=test-run3 bash "$SCRIPT" reports3 "$work/public3" ) >/dev/null
md3="$work/public3/index.md"; html3="$work/public3/index.html"
# 5. matched=pass, real-fail=fail, uek-trap=infra; optional-trap not counted.
if grep -qE '\| incomplete \| 1 \| 1 \| 1 \|' "$md3"; then
  ok "a required pass on a mismatched kernel family is counted under Required infra"
else
  bad "a required pass on a mismatched kernel family was not counted as infra"; cat "$md3" >&2
fi
# 6. the INCOMPATIBLE result on a mismatched kernel stays a failure (RunVerdict:
#    a proven incompatibility outranks an infrastructure error).
if grep -qE '\| [0-9]+ \| 0 \| 2 \|' "$md3"; then
  bad "a required INCOMPATIBLE on a mismatched kernel was hidden as infra"
else
  ok "a required INCOMPATIBLE on a mismatched kernel stays a failure"
fi
# 7. the optional target never moves the required counts (5 asserts exactly
#    1/1/1), and 8. the per-target row shows the mismatch instead of a bare pass.
uek_row="$(grep '<code>uek-trap</code>' "$html3" || true)"
if [[ "$uek_row" == *'kernel family mismatch'* && "$uek_row" == *'requested 5.15'* && "$uek_row" != *'class="pass"'* ]]; then
  ok "the per-target row shows the kernel family mismatch, not a plain pass"
else
  bad "the per-target row hides the kernel family mismatch: $uek_row"
fi
# A genuine failure on a mismatched kernel is still a failure: it must keep the
# fail style, not the amber warn style reserved for an unestablished pass.
fail_row="$(grep '<code>real-fail</code>' "$html3" || true)"
if [[ "$fail_row" == *'class="fail">fail on a kernel family mismatch (requested 4.14)<'* ]]; then
  ok "a failure on a mismatched kernel keeps the fail style"
else
  bad "a failure on a mismatched kernel lost its fail style: $fail_row"
fi
matched_row="$(grep '<code>matched</code>' "$html3" || true)"
if [[ "$matched_row" == *'class="pass">pass<'* ]]; then
  ok "a matched target still renders as a plain pass"
else
  bad "a matched target no longer renders as pass: $matched_row"
fi

# 9. A complete, all-pass report whose kernels all match is shown as complete:
#    honest evidence must not be rendered as a failure either.
mkdir -p "$work/reports4"
cat >"$work/reports4/quirk-library-allpass.json" <<'JSON'
{
  "schema_version": "v0.1",
  "run": {"id": "20261013T000000Z-allpass"},
  "artifact": {"basename": "fixture.bpf.o", "sha256": "0000"},
  "summary": {"status": "pass", "verdict": "COMPATIBLE", "complete": true},
  "targets": [
    {"profile_id": "a", "required": true, "status": "pass", "verdict": "COMPATIBLE",
     "environment": {"requested_kernel_family": "6.1", "observed_kernel": "6.1.0-53-cloud-amd64", "kernel_family_match": true}},
    {"profile_id": "b", "required": true, "status": "pass", "verdict": "COMPATIBLE"}
  ]
}
JSON
( cd "$work" && BPFCOMPAT_COMPATIBILITY_VERSION=test-run4 bash "$SCRIPT" reports4 "$work/public4" ) >/dev/null
if grep -qE '\| yes \| 2 \| 0 \| 0 \|' "$work/public4/index.md" && ! grep -qi 'incomplete' "$work/public4/index.md" "$work/public4/index.html"; then
  ok "an all-pass, kernel-matched report renders complete with no incomplete banner"
else
  bad "an all-pass report was rendered as incomplete or miscounted"; cat "$work/public4/index.md" >&2
fi

if [[ "$fail" -ne 0 ]]; then
  echo "publish-compatibility-site_test: FAILED" >&2
  exit 1
fi
echo "publish-compatibility-site_test: all checks passed"
