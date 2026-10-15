#!/usr/bin/env bash
# Regression test for scripts/check-release-gate-reports.sh.
#
# The release VM gate once passed both reports to a single `jq -e`, whose exit
# status reflects only the last output: an invalid positive report followed by
# a valid negative report passed. Every mutation below is applied to ONE report
# while the other stays valid, and must be rejected.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${ROOT_DIR}/scripts/check-release-gate-reports.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

validator="$(printf 'a%.0s' {1..64})"
digest="$(printf 'b%.0s' {1..64})"

report() { # <summary-status> <target-status> <classification-code>
  jq -n \
    --arg summary "$1" \
    --arg status "$2" \
    --arg code "$3" \
    --arg validator "$validator" \
    --arg digest "$digest" '{
      schema_version: "v0.1",
      validator: {basename: "bpfcompat-validator-static-linux-amd64", sha256: $validator},
      summary: {status: $summary},
      targets: [{
        profile_id: "ubuntu-22.04-5.15",
        status: $status,
        notes: ["base image sha256: " + $digest]
      } + (if $code == "" then {} else {classification_code: $code} end)]
    }'
}

report pass pass "" >"$tmp/positive.json"
report fail fail UNKNOWN >"$tmp/negative.json"

failures=0

expect_pass() {
  if ! bash "$script" "$tmp/positive.json" "$tmp/negative.json" "$validator" "$digest" >/dev/null 2>&1; then
    echo "[release-gate-test] rejected valid reports" >&2
    failures=$((failures + 1))
  fi
}

# expect_reject <which> <description> <jq mutation | RAW:content>
expect_reject() {
  local which="$1" description="$2" mutation="$3" pos="$tmp/positive.json" neg="$tmp/negative.json"
  local bad="$tmp/bad.json"
  if [[ "$mutation" == RAW:* ]]; then
    printf '%s' "${mutation#RAW:}" >"$bad"
  else
    jq "$mutation" "$tmp/${which}.json" >"$bad"
  fi
  if [[ "$which" == positive ]]; then pos="$bad"; else neg="$bad"; fi
  if bash "$script" "$pos" "$neg" "$validator" "$digest" >/dev/null 2>&1; then
    echo "[release-gate-test] accepted ${which} report with ${description}" >&2
    failures=$((failures + 1))
  fi
}

expect_pass

for which in positive negative; do
  valid_doc="$(cat "$tmp/${which}.json")"
  expect_reject "$which" "an infra_error target" '.targets[0].status = "infra_error"'
  expect_reject "$which" "a different validator sha256" '.validator.sha256 = ("c" * 64)'
  expect_reject "$which" "no validator identity" 'del(.validator)'
  expect_reject "$which" "no base image digest note" '.targets[0].notes = ["other"]'
  expect_reject "$which" "no notes" 'del(.targets[0].notes)'
  expect_reject "$which" "an empty target list" '.targets = []'
  expect_reject "$which" "no target list" 'del(.targets)'
  expect_reject "$which" "a null document" 'null'
  expect_reject "$which" "a false document" 'false'
  expect_reject "$which" "an empty file" 'RAW:'
  expect_reject "$which" "a null document followed by a valid one" "RAW:null
${valid_doc}"
done
expect_reject positive "a non-pass summary" '.summary.status = "fail"'
expect_reject negative "a non-fail summary" '.summary.status = "pass"'
expect_reject negative "no UNKNOWN classification" 'del(.targets[0].classification_code)'
# A trailing valid document must not launder an invalid first one.
expect_reject negative "an invalid document followed by a valid one" \
  "RAW:$(jq -c '.targets[0].status = "infra_error"' "$tmp/negative.json")
$(cat "$tmp/negative.json")"

expect_usage() { # <description> <args...>
  local description="$1" rc=0
  shift
  bash "$script" "$@" >/dev/null 2>&1 || rc=$?
  if [[ "$rc" -ne 2 ]]; then
    echo "[release-gate-test] ${description}: want exit 2, got ${rc}" >&2
    failures=$((failures + 1))
  fi
}
expect_usage "empty validator sha256" "$tmp/positive.json" "$tmp/negative.json" "" "$digest"
expect_usage "empty image sha256" "$tmp/positive.json" "$tmp/negative.json" "$validator" ""
expect_usage "missing arguments" "$tmp/positive.json" "$tmp/negative.json"

if [[ "$failures" -ne 0 ]]; then
  echo "[release-gate-test] FAIL (${failures})" >&2
  exit 1
fi
echo "[release-gate-test] PASS"
