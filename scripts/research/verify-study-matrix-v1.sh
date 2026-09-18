#!/usr/bin/env bash
set -euo pipefail

MATRIX="${1:-research/corpus/v1/execution-matrix.yaml}"
LOCK="${2:-research/corpus/v1/profile-identities.json}"
PLAN="${3:-research/corpus/v1/study-plan.json}"

fail() {
  echo "[verify-research-matrix-v1] $*" >&2
  exit 1
}

for f in "$MATRIX" "$LOCK" "$PLAN"; do
  [[ -s "$f" ]] || fail "missing required input: $f"
done

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
matrix_ids="$tmp_dir/matrix.txt"
lock_ids="$tmp_dir/lock.txt"

if ! go run ./cmd/bpfcompat profile list --matrix "$MATRIX" |
  sed '/^[[:space:]]*$/d' | LC_ALL=C sort > "$matrix_ids"; then
  fail "failed to enumerate matrix profiles"
fi
[[ -s "$matrix_ids" ]] || fail "matrix contains no profiles"

if ! jq -er '
  .profiles
  | if type == "array" and length > 0
    then .[] | .id
    else error("profiles must be a non-empty array")
    end
' "$LOCK" | LC_ALL=C sort > "$lock_ids"; then
  fail "failed to enumerate locked profiles"
fi
[[ -s "$lock_ids" ]] || fail "profile lock contains no profiles"

if [[ "$(uniq -d "$matrix_ids" | wc -l)" -ne 0 ]]; then
  fail "matrix contains duplicate profile ids"
fi
if [[ "$(uniq -d "$lock_ids" | wc -l)" -ne 0 ]]; then
  fail "profile lock contains duplicate profile ids"
fi

if ! diff -u "$lock_ids" "$matrix_ids"; then
  fail "matrix and profile lock select different profile sets"
fi

expected="$(jq -er '.expected_profiles | select(type == "number" and . > 0)' "$PLAN")" ||
  fail "study plan has invalid expected_profiles"
actual="$(wc -l < "$lock_ids" | tr -d '[:space:]')"
[[ "$actual" == "$expected" ]] ||
  fail "study plan expects $expected profiles but lock contains $actual"

echo "[verify-research-matrix-v1] PASS"
