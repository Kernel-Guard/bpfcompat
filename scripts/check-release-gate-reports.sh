#!/usr/bin/env bash
# Fail-closed assertions over the release VM gate reports.
#
#   check-release-gate-reports.sh <positive.json> <negative.json> \
#       <validator-sha256> <base-image-sha256>
#
# Every assertion runs once per report file. `jq -e` sets its exit status from
# the LAST output only, so passing both reports to one invocation lets a
# failing first report hide behind a passing second one (and even masks a jq
# runtime error on the first file). Each file is also slurped and required to
# be exactly one JSON object, so a multi-document file cannot do the same.
#
# Exit 0: both reports satisfy every assertion. Exit 1: any assertion failed.
# Exit 2: usage error.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 <positive.json> <negative.json> <validator-sha256> <base-image-sha256>" >&2
  exit 2
fi

positive="$1"
negative="$2"
validator_sha256="$3"
image_sha256="$4"

command -v jq >/dev/null || { echo "[release-gate] jq is required" >&2; exit 2; }
[[ "$validator_sha256" =~ ^[0-9a-f]{64}$ ]] ||
  { echo "[release-gate] validator sha256 must be 64 lowercase hex characters" >&2; exit 2; }
[[ "$image_sha256" =~ ^[0-9a-f]{64}$ ]] ||
  { echo "[release-gate] base image sha256 must be 64 lowercase hex characters" >&2; exit 2; }

failures=0

# check <label> <file> <filter>: the filter is applied to the single report
# object and must evaluate to exactly `true`.
check() {
  local label="$1" file="$2" filter="$3"
  if [[ ! -s "$file" ]]; then
    echo "[release-gate] FAIL ${label}: ${file} is missing or empty" >&2
    failures=$((failures + 1))
    return
  fi
  if ! jq -e -s \
    --arg validator "$validator_sha256" \
    --arg digest "$image_sha256" \
    "length == 1 and (.[0] | type == \"object\") and ((.[0] | ${filter}) == true)" \
    "$file" >/dev/null 2>&1; then
    echo "[release-gate] FAIL ${label}: ${file}" >&2
    failures=$((failures + 1))
  fi
}

check "positive summary is pass" "$positive" '.summary.status == "pass"'
check "negative summary is fail" "$negative" '.summary.status == "fail"'

# shellcheck disable=SC2016  # $validator and $digest are jq variables, not shell
for report in "$positive" "$negative"; do
  check "targets are present" "$report" \
    '(.targets | type == "array" and length > 0)'
  check "no infra_error target" "$report" \
    '.targets | all(.status != "infra_error")'
  check "validator sha256 matches the verified candidate" "$report" \
    '.validator.sha256 == $validator'
  check "every target booted the pinned base image" "$report" \
    'all(.targets[]; any(.notes[]?; contains($digest)))'
done

check "negative is classified UNKNOWN" "$negative" \
  '[.. | objects | select(.classification_code? == "UNKNOWN")] | length > 0'

if [[ "$failures" -ne 0 ]]; then
  echo "[release-gate] ${failures} assertion(s) failed" >&2
  exit 1
fi
echo "[release-gate] PASS positive=${positive} negative=${negative}"
