#!/usr/bin/env bash
set -euo pipefail

LEFT="${1:-dist/research-corpus-v1-a}"
RIGHT="${2:-dist/research-corpus-v1-b}"

fail() {
  echo "[compare-research-materializations] $*" >&2
  exit 1
}

for bundle in "$LEFT" "$RIGHT"; do
  [[ -s "$bundle/materialization.json" ]] ||
    fail "missing materialization.json in $bundle"
done

left_projection="$(mktemp)"
right_projection="$(mktemp)"
trap 'rm -f "$left_projection" "$right_projection"' EXIT

jq -S '{
  schema_version,
  corpus_version,
  source_revisions,
  artifacts,
  validation_contracts
}' "$LEFT/materialization.json" > "$left_projection"

jq -S '{
  schema_version,
  corpus_version,
  source_revisions,
  artifacts,
  validation_contracts
}' "$RIGHT/materialization.json" > "$right_projection"

if ! diff -u "$left_projection" "$right_projection"; then
  fail "materialized artifact or validation-contract identities are not reproducible"
fi

echo "[compare-research-materializations] PASS"
