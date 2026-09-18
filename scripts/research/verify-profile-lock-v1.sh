#!/usr/bin/env bash
set -euo pipefail

LOCK="${1:-research/corpus/v1/profile-identities.json}"

fail() {
  echo "[verify-research-profile-lock] $*" >&2
  exit 1
}

[[ -s "$LOCK" ]] || fail "missing profile identity lock: $LOCK"

while IFS=$'\t' read -r id path expected; do
  [[ -s "$path" ]] || fail "missing profile $id at $path"
  actual="$(git hash-object "$path")"
  [[ "$actual" == "$expected" ]] ||
    fail "profile drift for $id: expected git blob $expected got $actual"
done < <(jq -r '.profiles[] | [.id, .path, .git_blob] | @tsv' "$LOCK")

PLAN="research/corpus/v1/study-plan.json"
[[ -s "$PLAN" ]] || fail "missing study plan: $PLAN"

while IFS=$'\t' read -r case_id path expected; do
  [[ -s "$path" ]] || fail "missing study manifest for $case_id at $path"
  actual="$(git hash-object "$path")"
  [[ "$actual" == "$expected" ]] ||
    fail "manifest drift for $case_id: expected git blob $expected got $actual"
done < <(
  jq -r '.cases[] | select(.manifest != null) | [.id, .manifest, .manifest_git_blob] | @tsv' "$PLAN"
)

echo "[verify-research-profile-lock] PASS"
