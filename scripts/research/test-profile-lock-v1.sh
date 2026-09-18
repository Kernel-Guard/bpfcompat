#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

expect_fail() {
  local label="$1"
  shift
  if "$@" >"$tmp/$label.stdout" 2>"$tmp/$label.stderr"; then
    echo "expected failure: $label" >&2
    exit 1
  fi
}

profile="$tmp/profile.yaml"
manifest="$tmp/manifest.yaml"
lock="$tmp/lock.json"
plan="$tmp/plan.json"

printf 'id: fixture\n' > "$profile"
printf 'name: fixture\n' > "$manifest"
profile_blob="$(git hash-object "$profile")"
manifest_blob="$(git hash-object "$manifest")"

jq -n   --arg path "$profile"   --arg blob "$profile_blob"   '{profiles:[{id:"fixture",path:$path,git_blob:$blob}]}' > "$lock"

jq -n   --arg path "$manifest"   --arg blob "$manifest_blob"   '{cases:[{id:"fixture-case",manifest:$path,manifest_git_blob:$blob}]}' > "$plan"

bash scripts/research/verify-profile-lock-v1.sh "$lock" "$plan" >/dev/null

printf 'drift: true\n' >> "$profile"
expect_fail profile-drift bash scripts/research/verify-profile-lock-v1.sh "$lock" "$plan"
grep -q "profile drift" "$tmp/profile-drift.stderr"
printf 'id: fixture\n' > "$profile"

printf 'drift: true\n' >> "$manifest"
expect_fail manifest-drift bash scripts/research/verify-profile-lock-v1.sh "$lock" "$plan"
grep -q "manifest drift" "$tmp/manifest-drift.stderr"
printf 'name: fixture\n' > "$manifest"

rm "$profile"
expect_fail missing-profile bash scripts/research/verify-profile-lock-v1.sh "$lock" "$plan"
grep -q "missing profile" "$tmp/missing-profile.stderr"
printf 'id: fixture\n' > "$profile"

printf '{not-json\n' > "$tmp/malformed.json"
expect_fail malformed-lock bash scripts/research/verify-profile-lock-v1.sh "$tmp/malformed.json" "$plan"
grep -q "invalid or empty profile lock" "$tmp/malformed-lock.stderr"

printf '{"profiles":[]}\n' > "$tmp/empty.json"
expect_fail empty-lock bash scripts/research/verify-profile-lock-v1.sh "$tmp/empty.json" "$plan"
grep -q "invalid or empty profile lock" "$tmp/empty-lock.stderr"

printf '{"cases":"wrong-shape"}\n' > "$tmp/bad-plan.json"
expect_fail malformed-plan bash scripts/research/verify-profile-lock-v1.sh "$lock" "$tmp/bad-plan.json"
grep -q "invalid study plan" "$tmp/malformed-plan.stderr"

echo "[test-profile-lock-v1] PASS"
