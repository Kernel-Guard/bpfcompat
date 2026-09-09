#!/usr/bin/env bash
# Regression cover for scripts/check-canary-pins.sh.
#
# Every fixture resolves tags from this repository's own git objects
# (v0.3.6, v0.3.7, v0.4.0-rc.2, v0.4.0-rc.3), so the suite is deterministic
# and needs no GitHub API access. It seeds the failures that would actually
# happen -- a release bumped without repinning the canary, a pin whose
# `# vX.Y.Z` comment lies about which release it is, a canary that lost its
# stable job -- and asserts the guard goes red for each.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

script="scripts/check-canary-pins.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

STABLE_TAG=v0.3.7
STABLE_SHA="$(git rev-parse -q --verify "refs/tags/${STABLE_TAG}^{commit}")"
PREV_TAG=v0.3.6
PREV_SHA="$(git rev-parse -q --verify "refs/tags/${PREV_TAG}^{commit}")"
CAND_TAG=v0.4.0-rc.3
CAND_SHA="$(git rev-parse -q --verify "refs/tags/${CAND_TAG}^{commit}")"
PREV_CAND_TAG=v0.4.0-rc.2
PREV_CAND_SHA="$(git rev-parse -q --verify "refs/tags/${PREV_CAND_TAG}^{commit}")"

[[ -n "$STABLE_SHA" && -n "$PREV_SHA" && -n "$CAND_SHA" && -n "$PREV_CAND_SHA" ]] ||
  { echo "[canary-pins-test] fixture tags missing from this clone" >&2; exit 1; }

metadata() { # $1=stable $2=release $3=channel
  cat >"$tmp/release.yaml" <<EOF
stable_version: $1
release_version: $2
release_channel: $3
release_operator: ErenAri
approval_mode: solo-maintainer
minimum_go: 1.25.14
report_schema: v0.1
EOF
}

pin() { # $1=channel $2=sha $3=version-comment
  printf '      - name: %s job\n        # bpfcompat-pin: %s\n        uses: Kernel-Guard/bpfcompat@%s # %s\n' \
    "$1" "$1" "$2" "$3"
}

workflow() { # stdin = job bodies
  {
    printf 'name: consumer-canary\non:\n  workflow_dispatch:\njobs:\n'
    cat
  } >"$tmp/canary.yml"
}

run_guard() {
  # Every fixture tag above resolves from local git objects, so point the
  # remote fallback at a name that does not exist: a fixture must never make
  # this suite depend on reaching github.com.
  BPFCOMPAT_RELEASE_METADATA="$tmp/release.yaml" \
    BPFCOMPAT_CANARY_WORKFLOW="$tmp/canary.yml" \
    BPFCOMPAT_TAG_REMOTE=bpfcompat-test-no-such-remote \
    bash "$script" >"$tmp/out.log" 2>&1
}

expect_pass() {
  if ! run_guard; then
    echo "[canary-pins-test] expected PASS but guard failed: $1" >&2
    cat "$tmp/out.log" >&2
    exit 1
  fi
}

expect_fail() {
  if run_guard; then
    echo "[canary-pins-test] expected FAIL but guard passed: $1" >&2
    cat "$tmp/out.log" >&2
    exit 1
  fi
}

# 0. The repository as it actually stands must pass, against the real
#    workflow and the real release.yaml. A guard that only ever sees fixtures
#    proves nothing about the lane it is supposed to protect.
BPFCOMPAT_RELEASE_METADATA=release.yaml bash "$script" >"$tmp/real.log"
grep -Fq "PASS stable=v" "$tmp/real.log"

# 1. Both pins current, prerelease channel: the happy path.
metadata 0.3.7 0.4.0-rc.3 prerelease
{ pin stable "$STABLE_SHA" "$STABLE_TAG"; pin candidate "$CAND_SHA" "$CAND_TAG"; } | workflow
expect_pass "current stable and candidate pins"

# 2. stable_version bumped, canary left on the previous release. This is the
#    drift the guard exists for: the pin still resolves to a real release,
#    just not the documented one.
metadata 0.3.7 0.4.0-rc.3 prerelease
{ pin stable "$PREV_SHA" "$STABLE_TAG"; pin candidate "$CAND_SHA" "$CAND_TAG"; } | workflow
expect_fail "stale stable pin SHA"
grep -Fq "is exercising a stale release" "$tmp/out.log"

# 3. Correct SHA, lying comment. The `# vX.Y.Z` comment is the only thing a
#    reviewer reads; it is part of the contract, not decoration.
metadata 0.3.7 0.4.0-rc.3 prerelease
{ pin stable "$STABLE_SHA" "$PREV_TAG"; pin candidate "$CAND_SHA" "$CAND_TAG"; } | workflow
expect_fail "stable pin comment names the wrong release"
grep -Fq "but release.yaml says ${STABLE_TAG}" "$tmp/out.log"

# 4. A new candidate cut, canary left on the previous rc, channel still
#    prerelease.
metadata 0.3.7 0.4.0-rc.3 prerelease
{ pin stable "$STABLE_SHA" "$STABLE_TAG"; pin candidate "$PREV_CAND_SHA" "$PREV_CAND_TAG"; } | workflow
expect_fail "stale candidate pin during prerelease"

# 4b. Same, but only the SHA is stale and the comment was updated.
metadata 0.3.7 0.4.0-rc.3 prerelease
{ pin stable "$STABLE_SHA" "$STABLE_TAG"; pin candidate "$PREV_CAND_SHA" "$CAND_TAG"; } | workflow
expect_fail "candidate pin SHA is the previous rc"

# 5. Stable job deleted. Must not read as "nothing to check".
metadata 0.3.7 0.4.0-rc.3 prerelease
pin candidate "$CAND_SHA" "$CAND_TAG" | workflow
expect_fail "missing stable pin"
grep -Fq "has no canary" "$tmp/out.log"

# 6. No pins at all. The zero-match case must fail, never pass silently.
metadata 0.3.7 0.4.0-rc.3 prerelease
printf '      - name: nothing\n        run: true\n' | workflow
expect_fail "workflow declares no pins"

# 7. Stable channel with no active prerelease: the candidate lane still points
#    at last cycle's rc, which is fine, but stable is still enforced.
metadata 0.3.7 0.3.7 stable
{ pin stable "$STABLE_SHA" "$STABLE_TAG"; pin candidate "$PREV_CAND_SHA" "$PREV_CAND_TAG"; } | workflow
expect_pass "stable channel does not enforce the candidate pin"
grep -Fq "candidate pin not enforced" "$tmp/out.log"

# 8. ... and stable channel with no candidate job at all.
metadata 0.3.7 0.3.7 stable
pin stable "$STABLE_SHA" "$STABLE_TAG" | workflow
expect_pass "stable channel with no candidate pin"

# 9. Stable channel still fails on a stale stable pin.
metadata 0.3.7 0.3.7 stable
pin stable "$PREV_SHA" "$STABLE_TAG" | workflow
expect_fail "stale stable pin in stable channel"

# 10. A mutable ref is not a pin, even when it names the right release.
metadata 0.3.7 0.4.0-rc.3 prerelease
{ pin stable "$STABLE_TAG" "$STABLE_TAG"; pin candidate "$CAND_SHA" "$CAND_TAG"; } | workflow
expect_fail "stable pinned to a tag instead of a commit SHA"
grep -Fq "not a full 40-character commit SHA" "$tmp/out.log"

# 11. Two stable pins: which one is authoritative is undefined, so refuse.
metadata 0.3.7 0.4.0-rc.3 prerelease
{
  pin stable "$STABLE_SHA" "$STABLE_TAG"
  pin stable "$STABLE_SHA" "$STABLE_TAG"
  pin candidate "$CAND_SHA" "$CAND_TAG"
} | workflow
expect_fail "duplicate stable pin"
grep -Fq "second 'stable' pin" "$tmp/out.log"

# 12. A marker with no `uses:` after it is a pin that silently checks nothing.
metadata 0.3.7 0.4.0-rc.3 prerelease
{
  printf '      - name: stable job\n        # bpfcompat-pin: stable\n        run: true\n'
  pin candidate "$CAND_SHA" "$CAND_TAG"
} | workflow
expect_fail "stable marker with no action pin under it"

# 13. A typo'd channel name must not quietly satisfy anything.
metadata 0.3.7 0.4.0-rc.3 prerelease
{ pin stabel "$STABLE_SHA" "$STABLE_TAG"; pin candidate "$CAND_SHA" "$CAND_TAG"; } | workflow
expect_fail "misspelled pin channel"
grep -Fq "unknown pin channel" "$tmp/out.log"

# 14. A pin naming a tag that does not exist must fail, not be skipped.
metadata 9.9.9 0.4.0-rc.3 prerelease
{ pin stable "$STABLE_SHA" v9.9.9; pin candidate "$CAND_SHA" "$CAND_TAG"; } | workflow
expect_fail "stable pin names a tag that does not exist"

echo "[canary-pins-test] PASS"
