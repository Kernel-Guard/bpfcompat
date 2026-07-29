#!/usr/bin/env bash
set -euo pipefail

profile="${1:-coverage.out}"
minimum="${2:-50.0}"

fail() {
  echo "[coverage] $*" >&2
  exit 2
}

[[ -s "$profile" ]] || fail "coverage profile is missing or empty: ${profile}"
[[ "$minimum" =~ ^[0-9]+([.][0-9]+)?$ ]] ||
  fail "minimum must be a non-negative percentage"

total="$(
  go tool cover -func="$profile" |
    awk '$1 == "total:" {gsub(/%/, "", $3); print $3; exit}'
)"
[[ "$total" =~ ^[0-9]+([.][0-9]+)?$ ]] ||
  fail "could not read total statement coverage"

if ! awk -v total="$total" -v minimum="$minimum" \
  'BEGIN { exit !(total + 0 >= minimum + 0) }'; then
  fail "total statement coverage ${total}% is below required ${minimum}%"
fi

echo "[coverage] PASS total=${total}% minimum=${minimum}%"
