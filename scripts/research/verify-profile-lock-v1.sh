#!/usr/bin/env bash
set -euo pipefail

LOCK="${1:-research/corpus/v1/profile-identities.json}"
PLAN="${2:-research/corpus/v1/study-plan.json}"

fail() {
  echo "[verify-research-profile-lock] $*" >&2
  exit 1
}

[[ -s "$LOCK" ]] || fail "missing profile identity lock: $LOCK"
[[ -s "$PLAN" ]] || fail "missing study plan: $PLAN"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
profile_rows="$tmp_dir/profiles.tsv"
manifest_rows="$tmp_dir/manifests.tsv"

if ! jq -er '
  (.profiles | type == "array" and length > 0) as $ok
  | if $ok then .profiles[] | [.id, .path, .git_blob] | @tsv
    else error("profiles must be a non-empty array")
    end
' "$LOCK" > "$profile_rows"; then
  fail "invalid or empty profile lock"
fi
[[ -s "$profile_rows" ]] || fail "profile lock query produced no rows"

while IFS=$'\t' read -r id path expected; do
  [[ -n "$id" && -n "$path" && -n "$expected" ]] ||
    fail "profile lock row contains an empty field"
  [[ -s "$path" ]] || fail "missing profile $id at $path"
  actual="$(git hash-object "$path")"
  [[ "$actual" == "$expected" ]] ||
    fail "profile drift for $id: expected git blob $expected got $actual"
done < "$profile_rows"

if ! jq -er '
  (.cases | type == "array" and length > 0) as $ok
  | if $ok then
      .cases[]
      | select(.manifest != null)
      | [.id, .manifest, .manifest_git_blob]
      | @tsv
    else error("cases must be a non-empty array")
    end
' "$PLAN" > "$manifest_rows"; then
  fail "invalid study plan"
fi
[[ -s "$manifest_rows" ]] || fail "study plan contains no locked manifests"

while IFS=$'\t' read -r case_id path expected; do
  [[ -n "$case_id" && -n "$path" && -n "$expected" ]] ||
    fail "manifest lock row contains an empty field"
  [[ -s "$path" ]] || fail "missing study manifest for $case_id at $path"
  actual="$(git hash-object "$path")"
  [[ "$actual" == "$expected" ]] ||
    fail "manifest drift for $case_id: expected git blob $expected got $actual"
done < "$manifest_rows"

echo "[verify-research-profile-lock] PASS"
