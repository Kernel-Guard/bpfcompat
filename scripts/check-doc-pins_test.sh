#!/usr/bin/env bash
# Regression cover for scripts/check-doc-pins.sh. Each case builds a throwaway
# repository whose `origin` is a local bare repository holding the tags, with
# a release.yaml and a README that pins the action.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
failures=0
fail() { echo "[doc-pins-test] FAIL: $*" >&2; failures=$((failures + 1)); }
ok() { echo "[doc-pins-test] ok: $*"; }
gitq() { git -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c tag.gpgsign=false "$@" >/dev/null 2>&1; }

# fixture <name> <channel> <stable_version> <readme-pin-line> [tags...]
fixture() {
  local d="$tmp/$1" channel="$2" stable="$3" pin="$4"; shift 4
  mkdir -p "$d/origin.git" "$d/work/scripts"
  gitq -C "$d/origin.git" init --bare
  gitq -C "$d/work" init -b main
  cp "$ROOT_DIR/scripts/check-doc-pins.sh" "$d/work/scripts/"
  printf 'stable_version: %s\nrelease_version: %s\nrelease_channel: %s\n' "$stable" "$stable" "$channel" >"$d/work/release.yaml"
  printf '# x\n```yaml\n      - %s\n```\n' "$pin" >"$d/work/README.md"
  # The consumer canary's stable pin names the release the stable window keeps
  # (CANARY, default v0.3.7); NO_CANARY leaves the file out.
  if [[ -z "${NO_CANARY:-}" ]]; then
    mkdir -p "$d/work/.github/workflows"
    printf 'jobs:\n  s:\n    steps:\n      # bpfcompat-pin: stable\n      - uses: Kernel-Guard/bpfcompat@%s # %s\n' \
      "$(printf 'a%.0s' {1..40})" "${CANARY:-v0.3.7}" >"$d/work/.github/workflows/consumer-canary.yml"
  fi
  gitq -C "$d/work" add -A
  gitq -C "$d/work" commit -m base
  for t in "$@"; do gitq -C "$d/work" tag -a "$t" -m "$t"; done
  gitq -C "$d/work" remote add origin "$d/origin.git"
  gitq -C "$d/work" push origin main --tags
  # The CI checkout carries no tags locally; the check must ask the remote.
  for t in "$@"; do gitq -C "$d/work" tag -d "$t"; done
  W="$d/work"
}
# template <version> [file]: an integration template SHA-pinned to <version>,
# committed on top of the fixture (the version's tag is on the base commit).
template() {
  mkdir -p "$W/docs/integrations"
  printf 'jobs:\n  t:\n    steps:\n      - uses: Kernel-Guard/bpfcompat@%s # %s\n' \
    "$(git -C "$W" rev-list --max-parents=0 HEAD)" "$1" >"$W/docs/integrations/${2:-t}.yml"
  gitq -C "$W" add -A
  gitq -C "$W" commit -m "template $1"
}
# tag_head <tag>: tag the current HEAD on the remote (the tag build of it).
tag_head() {
  gitq -C "$W" tag -a "$1" -m "$1"
  gitq -C "$W" push origin "$1"
  gitq -C "$W" tag -d "$1"
}
expect() { # <pass|fail> <description> [stderr-substring]
  local want="$1" desc="$2" needle="${3:-}" rc=0
  bash "$W/scripts/check-doc-pins.sh" >"$tmp/out" 2>&1 || rc=$?
  if [[ "$want" == pass && $rc -eq 0 ]] || [[ "$want" == fail && $rc -ne 0 && ( -z "$needle" || $(grep -cF -- "$needle" "$tmp/out") -gt 0 ) ]]; then
    ok "$desc"
  else
    fail "$desc (rc=$rc)"; sed 's/^/    | /' "$tmp/out" >&2
  fi
}

fixture released prerelease 0.3.7 'uses: Kernel-Guard/bpfcompat@v0.3.7' v0.3.7
expect pass "prerelease channel: pin on an existing release tag"

fixture stablepr stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.7
expect pass "stable PR: docs name v0.4.0 while its tag positively does not exist yet"

fixture stabletagged stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.7 v0.4.0
expect pass "stable channel after the tag: the pin resolves normally"

fixture otherversion stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.1' v0.3.7
expect fail "stable PR: a pin on another missing version still fails" "pins v0.4.1, which is not a released tag"

fixture rcchannel prerelease 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.7
expect fail "prerelease channel: a missing tag is never accepted" "pins v0.4.0, which is not a released tag"

fixture shapin stable 0.4.0 "uses: Kernel-Guard/bpfcompat@$(printf 'a%.0s' {1..40}) # v0.4.0" v0.3.7
expect fail "stable PR: a SHA pin claiming the unreleased version fails" "claims v0.4.0, but that tag does not exist"

fixture offline stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.7
git -C "$W" remote set-url origin "$tmp/offline/does-not-exist.git"
expect fail "stable PR: an unreachable remote fails closed" "pins v0.4.0, which is not a released tag"

# The integration templates are SHA-pinned (docs/integrations/README.md), so
# they cannot name vX.Y.Z before its tag exists: during the stable release
# window they stay on the most recent earlier stable release.
fixture tplpr stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.6 v0.3.7
template v0.3.7
expect pass "stable PR: templates keep their SHA pin on the newest earlier stable"

fixture tplold stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.6 v0.3.7
template v0.3.6
expect fail "stable PR: a template on an older stable than the newest fails" "docs pin more than one bpfcompat version"

fixture tplthree stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.6 v0.3.7
template v0.3.7 a
template v0.3.6 b
expect fail "stable PR: three documented versions fail" "docs pin more than one bpfcompat version"

fixture tplbuild stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.7
template v0.3.7
tag_head v0.4.0
expect pass "tag build: the new tag is HEAD, templates still on the previous stable"

fixture tplafter stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.7 v0.4.0
template v0.3.7
expect fail "after the tag: templates must be repinned to the new release" "docs pin more than one bpfcompat version"

fixture tplform stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.7
mkdir -p "$W/docs"; printf 'jobs:\n  t:\n    steps:\n      - uses: "Kernel-Guard/bpfcompat@v0.3.7"\n' >"$W/docs/stale.yml"
expect fail "stable PR: a tag-form pin on the previous stable is not a SHA-pinned template" "docs pin more than one bpfcompat version"

CANARY=v0.3.6 fixture tplcanary stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.6 v0.3.7
template v0.3.7
expect fail "stable PR: templates must stay on the release the canary pins" "docs pin more than one bpfcompat version"

fixture tplbuildwrong stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.6 v0.3.7
template v0.3.6
tag_head v0.4.0
expect fail "tag build: templates on another release than the canary's fail" "docs pin more than one bpfcompat version"

CANARY='v0.3.7 # v0.3.6' fixture tpltwocomments stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.6 v0.3.7
template v0.3.6
expect fail "stable PR: the canary's first version comment counts, as in check-canary-pins" "docs pin more than one bpfcompat version"

NO_CANARY=1 fixture tplnocanary stable 0.4.0 'uses: Kernel-Guard/bpfcompat@v0.4.0' v0.3.7
template v0.3.7
expect fail "stable PR: without a canary stable pin there is no window" "docs pin more than one bpfcompat version"

fixture tplrc prerelease 0.3.7 'uses: Kernel-Guard/bpfcompat@v0.3.7' v0.3.6 v0.3.7
template v0.3.6
expect fail "prerelease channel: two documented versions fail as before" "docs pin more than one bpfcompat version"

if [[ $failures -ne 0 ]]; then echo "[doc-pins-test] $failures failure(s)" >&2; exit 1; fi
echo "[doc-pins-test] PASS"
