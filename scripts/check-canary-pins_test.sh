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

# 15. The remote fallback that shallow-checkout lanes depend on must resolve a
#     lightweight tag as well as an annotated one. Only annotated tags
#     advertise a peeled `^{}` ref, so asking for that ref alone reports a
#     lightweight tag as nonexistent and fails the release gate for a tag that
#     exists. Extract tag_commit() from the shipped script -- no second copy to
#     drift -- and point it at a local fixture remote, so this stays offline.
fixture="$tmp/fixture"
mkdir -p "$fixture/upstream"
(
  cd "$fixture/upstream"
  git init -q -b main .
  git -c user.email=t@e -c user.name=t commit -q --allow-empty -m fixture
  git tag lightweight-1.0.0
  git -c user.email=t@e -c user.name=t tag -a annotated-1.0.0 -m annotated
)
git clone -q --depth 1 "file://$fixture/upstream" "$fixture/clone"
(
  cd "$fixture/clone"
  # Drop the local tags so only the remote fallback can answer, exactly as on a
  # shallow CI checkout.
  for t in $(git tag); do git tag -d "$t" >/dev/null; done

  fn="$(awk '/^tag_lookup\(\) \{/ {f=1} f {print} f && /^\}/ {exit}' "$ROOT_DIR/$script")"
  [[ -n "$fn" ]] || { echo "[canary-pins-test] could not extract tag_lookup() from $script" >&2; exit 1; }
  # tag_lookup() reads $tag_remote from its enclosing scope in the real script.
  # shellcheck disable=SC2034  # used by the eval'd function below
  tag_remote=origin
  # shellcheck disable=SC2086
  eval "$fn"

  expected="$(git -C "$fixture/upstream" rev-parse HEAD)"
  for t in lightweight-1.0.0 annotated-1.0.0; do
    tag_lookup "$t"
    if [[ "$LOOKUP_STATE" != found || "$LOOKUP_SHA" != "$expected" ]]; then
      echo "[canary-pins-test] remote fallback resolved $t to ${LOOKUP_STATE}/${LOOKUP_SHA:-<empty>}, want found/$expected" >&2
      exit 1
    fi
  done
  # A tag the reachable remote does not have is positively absent.
  tag_lookup no-such-tag
  [[ "$LOOKUP_STATE" == absent ]] || { echo "[canary-pins-test] missing tag reported as ${LOOKUP_STATE}, want absent" >&2; exit 1; }
  # An unreachable remote is an error, never "absent".
  tag_remote="file://$fixture/does-not-exist"
  tag_lookup no-such-tag
  [[ "$LOOKUP_STATE" == error ]] || { echo "[canary-pins-test] unreachable remote reported as ${LOOKUP_STATE}, want error" >&2; exit 1; }
)

# 16-27. The new-RC bootstrap, exercised end to end in fixture repositories:
#        real git, real annotated tags, a reachable or unreachable "origin";
#        only `gh` (the published-release query) and, for one case,
#        `git ls-remote` are stubbed on PATH. The script under test is the
#        shipped one, copied verbatim; nothing in it is overridden.
fx="$tmp/bootstrap"
mkdir -p "$fx/bin"
cat >"$fx/bin/gh" <<'STUB'
#!/usr/bin/env bash
# gh api repos/Kernel-Guard/bpfcompat/releases/tags/<tag> --jq ...
[[ "$1" == api && "$2" == repos/Kernel-Guard/bpfcompat/releases/tags/* ]] || exit 99
tag="${2##*/}"
line="$(grep -m1 "^${tag} " "$GH_RELEASES" 2>/dev/null)" || exit 1
echo "${line#* }"
STUB
chmod +x "$fx/bin/gh"

gitq() { git -c user.email=t@e -c user.name=t "$@" >/dev/null 2>&1; }
new_fixture() { # fresh work repo + bare origin; tags v0.3.7, rc.2, rc.3, rc.7, v0.5.0-rc.1
  rm -rf "$fx/work" "$fx/origin.git"
  git init -q --bare "$fx/origin.git"
  git init -q -b main "$fx/work"
  mkdir -p "$fx/work/scripts" "$fx/work/.github/workflows"
  cp "$ROOT_DIR/$script" "$fx/work/scripts/check-canary-pins.sh"
  (
    cd "$fx/work"
    gitq remote add origin "$fx/origin.git"
    for t in v0.3.7 v0.4.0-rc.2 v0.4.0-rc.3 v0.4.0-rc.7 v0.5.0-rc.1; do
      gitq commit --allow-empty -m "$t"
      gitq tag -a "$t" -m "$t"
    done
    gitq commit --allow-empty -m "main after rc.3"
    gitq push -q origin main --tags
  )
  printf 'v0.4.0-rc.2 false true\nv0.4.0-rc.3 false true\nv0.4.0-rc.7 false true\nv0.5.0-rc.1 false true\n' >"$fx/releases"
}
fsha() { git -C "$fx/work" rev-parse "refs/tags/$1^{commit}"; }
fmeta() { # $1=stable $2=release $3=channel
  printf 'stable_version: %s\nrelease_version: %s\nrelease_channel: %s\nrelease_operator: ErenAri\napproval_mode: solo-maintainer\n' \
    "$1" "$2" "$3" >"$fx/work/release.yaml"
}
fcanary() { # stdin = job bodies
  { printf 'name: consumer-canary\non:\n  workflow_dispatch:\njobs:\n'; cat; } >"$fx/work/.github/workflows/consumer-canary.yml"
}
frun() { # [extra PATH dir]
  ( cd "$fx/work" && PATH="${1:+$1:}$fx/bin:$PATH" GH_RELEASES="$fx/releases" \
      bash scripts/check-canary-pins.sh >"$fx/out.log" 2>&1 )
}
fpass() { if ! frun "${2:-}"; then echo "[canary-pins-test] expected PASS: $1" >&2; cat "$fx/out.log" >&2; exit 1; fi; echo "[canary-pins-test] pass: $1"; }
ffail() { # $1=label $2=expected message fragment [$3=extra PATH dir]
  if frun "${3:-}"; then echo "[canary-pins-test] expected FAIL: $1" >&2; cat "$fx/out.log" >&2; exit 1; fi
  grep -Fq -- "$2" "$fx/out.log" || { echo "[canary-pins-test] $1 failed for the wrong reason:" >&2; cat "$fx/out.log" >&2; exit 1; }
  echo "[canary-pins-test] refused: $1"
}

new_fixture
S="$(fsha v0.3.7)"; R2="$(fsha v0.4.0-rc.2)"; R3="$(fsha v0.4.0-rc.3)"; R7="$(fsha v0.4.0-rc.7)"; F1="$(fsha v0.5.0-rc.1)"

# 16. Genuine new-RC preparation: v0.4.0-rc.4 positively absent on origin.
fmeta 0.3.7 0.4.0-rc.4 prerelease
{ pin stable "$S" v0.3.7; pin candidate "$R3" v0.4.0-rc.3; } | fcanary
fpass "new RC being prepared: earlier published rc of the same release accepted"
grep -q "candidate bootstrap" "$fx/out.log" || { echo "[canary-pins-test] bootstrap must be announced" >&2; exit 1; }

# 17. Wrong release family.
{ pin stable "$S" v0.3.7; pin candidate "$F1" v0.5.0-rc.1; } | fcanary
ffail "bootstrap pin from another release family" "must be an earlier rc of 0.4.0"
# 18. Higher RC number.
{ pin stable "$S" v0.3.7; pin candidate "$R7" v0.4.0-rc.7; } | fcanary
ffail "bootstrap pin with a higher rc number" "is not earlier than v0.4.0-rc.4"
# 19. Same RC number.
{ pin stable "$S" v0.3.7; pin candidate "$R3" v0.4.0-rc.4; } | fcanary
ffail "bootstrap pin with the same rc number" "is not earlier than v0.4.0-rc.4"
# 20. Tag exists but the pin is another commit.
{ pin stable "$S" v0.3.7; pin candidate "$R2" v0.4.0-rc.3; } | fcanary
ffail "bootstrap pin whose tag resolves elsewhere" "candidate pin is ${R2} but v0.4.0-rc.3 is ${R3}"
# 21. Unpublished (draft) previous RC, and an unanswerable API.
{ pin stable "$S" v0.3.7; pin candidate "$R3" v0.4.0-rc.3; } | fcanary
sed -i 's/^v0.4.0-rc.3 false true$/v0.4.0-rc.3 true true/' "$fx/releases"
ffail "previous rc is only a draft release" "is not a verified published prerelease"
sed -i '/^v0.4.0-rc.3 /d' "$fx/releases"
ffail "previous rc has no release (or the API failed)" "is not a verified published prerelease"
printf 'v0.4.0-rc.3 false true\n' >>"$fx/releases"
# 22. Missing candidate pin.
pin stable "$S" v0.3.7 | fcanary
ffail "bootstrap without a candidate pin" "declares no '# bpfcompat-pin: candidate' pin"
# 23. Missing / unreachable remote: absence cannot be established.
{ pin stable "$S" v0.3.7; pin candidate "$R3" v0.4.0-rc.3; } | fcanary
git -C "$fx/work" remote set-url origin "$fx/no-such-origin.git"
ffail "unreachable remote" "cannot determine whether v0.4.0-rc.4 exists"
git -C "$fx/work" remote remove origin
ffail "no remote configured" "cannot determine whether v0.4.0-rc.4 exists"
git -C "$fx/work" remote add origin "$fx/origin.git"
# 24. A malformed tag response from the remote.
mkdir -p "$fx/badgit"
real_git="$(command -v git)"
cat >"$fx/badgit/git" <<STUB
#!/usr/bin/env bash
if [[ "\$1" == ls-remote ]]; then printf 'not-a-sha\trefs/tags/v0.4.0-rc.4\n'; exit 0; fi
exec "$real_git" "\$@"
STUB
chmod +x "$fx/badgit/git"
ffail "malformed ls-remote answer" "cannot determine whether v0.4.0-rc.4 exists" "$fx/badgit"
# 24b. "No such ref" (exit 2) must come with an empty listing to count as absent.
cat >"$fx/badgit/git" <<STUB
#!/usr/bin/env bash
if [[ "\$1" == ls-remote ]]; then printf 'unexpected output\n'; exit 2; fi
exec "$real_git" "\$@"
STUB
chmod +x "$fx/badgit/git"
ffail "ls-remote exit 2 with output" "cannot determine whether v0.4.0-rc.4 exists" "$fx/badgit"
# 25. Genuine tag build: v0.4.0-rc.4 exists and IS the commit under check.
( cd "$fx/work" && gitq commit --allow-empty -m "release: target v0.4.0-rc.4" && gitq tag -a v0.4.0-rc.4 -m rc4 && gitq push -q origin main --tags )
printf 'v0.4.0-rc.4 false true\n' >>"$fx/releases"
fpass "tag build of the new rc itself: previous published rc accepted"
# 26. A subsequent main commit with the stale pin: strict again.
( cd "$fx/work" && gitq commit --allow-empty -m "next change on main" )
ffail "commit after the rc tag with a stale candidate pin" "candidate pin is commented 'v0.4.0-rc.3' but release.yaml says v0.4.0-rc.4"
# ...and repinned to the new RC it passes strictly.
{ pin stable "$S" v0.3.7; pin candidate "$(fsha v0.4.0-rc.4)" v0.4.0-rc.4; } | fcanary
fpass "repinned to the new rc after the tag"
# 27. Stable channel is unchanged: wrong stable pin fails, correct passes,
#     and no bootstrap applies to the stable pin.
fmeta 0.3.7 0.3.7 stable
{ pin stable "$R3" v0.3.7; } | fcanary
ffail "stable channel: stale stable pin" "stable pin is ${R3} but v0.3.7 is ${S}"
{ pin stable "$S" v0.3.7; } | fcanary
fpass "stable channel: correct stable pin"
fmeta 0.3.8 0.3.8 stable
{ pin stable "$S" v0.3.7; } | fcanary
ffail "stable channel: stable pin never bootstraps to an older release" "stable pin is commented 'v0.3.7' but release.yaml says v0.3.8"

# 28. Every workflow step that reaches the canary-pin check -- directly or via
#     `make production-tech-check` -- must provide GH_TOKEN, or the RC
#     bootstrap's published-prerelease query fails closed and the new RC can
#     never be built (the tag build's quality-gate step was missed once).
missing="$(python3 - "$ROOT_DIR/.github/workflows" <<'PY'
import glob, os, re, sys, yaml
# Real invocations only; the *_test.sh suites use fixtures and stubs.
trigger = re.compile(r"make (check-release-consistency|production-tech-check)\b|scripts/(check-canary-pins|check-release-consistency|production-tech-check)\.sh")
bad = []
for path in sorted(glob.glob(os.path.join(sys.argv[1], "*.yml"))):
    wf = yaml.safe_load(open(path)) or {}
    for jname, job in (wf.get("jobs") or {}).items():
        jenv = job.get("env") or {}
        for i, step in enumerate(job.get("steps") or []):
            run = step.get("run") or ""
            if trigger.search(run):
                env = {**(wf.get("env") or {}), **jenv, **(step.get("env") or {})}
                if "GH_TOKEN" not in env:
                    bad.append(f"{os.path.basename(path)}:{jname}:{step.get('name', i)}")
print("\n".join(bad))
PY
)"
if [[ -n "$missing" ]]; then
  echo "[canary-pins-test] workflow steps that reach the canary-pin check without GH_TOKEN:" >&2
  echo "$missing" >&2
  exit 1
fi
echo "[canary-pins-test] every workflow path into the canary-pin check provides GH_TOKEN"

echo "[canary-pins-test] PASS"
