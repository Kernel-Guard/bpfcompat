#!/usr/bin/env bash
# Regression suite for scripts/research-v1-release-state.sh.
#
# Real git (a local remote with a real annotated research-v1 tag); `gh` is a
# stub serving a fixture release and logging attestation calls. Each case
# changes one fact. A case that must fail must fail for its stated reason and
# must print no publish= decision.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/research-v1-release-state.sh"
command -v jq >/dev/null || { echo "FAIL: jq required" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git_q() { git -c user.name=t -c user.email=t@example.invalid -c init.defaultBranch=main "$@" >/dev/null; }

# Remote: the pinned commit carries annotated research-v1; a later commit is main.
git_q init -q "$work/origin"
echo one >"$work/origin/f"; git_q -C "$work/origin" add f; git_q -C "$work/origin" commit -q -m one
pinned="$(git -C "$work/origin" rev-parse HEAD)"
git_q -C "$work/origin" tag -a research-v1 -m "research v1"
echo two >"$work/origin/f"; git_q -C "$work/origin" commit -q -am two
later="$(git -C "$work/origin" rev-parse HEAD)"
# A remote without the tag.
git_q clone -q --no-tags "$work/origin" "$work/notag"
git_q -C "$work/notag" tag -d research-v1 2>/dev/null || true

# Fixture release: four assets and a matching lock.
good="$work/release.good"; mkdir -p "$good"
printf '{"files": 668}\n' >"$good/archive-manifest.json"
printf 'PK-payload-bytes' >"$good/bpfcompat-research-v1-payload.zip"
sha() { sha256sum -- "$1" | awk '{print $1}'; }
write_lock() { # <dir> -> lock in <dir>/archive-lock.json, checksums file
  local d="$1"
  jq -n --arg m "sha256:$(sha "$d/archive-manifest.json")" \
    --arg p "sha256:$(sha "$d/bpfcompat-research-v1-payload.zip")" \
    --argjson s "$(stat -c %s -- "$d/bpfcompat-research-v1-payload.zip")" \
    '{schema_version: "bpfcompat.research.archive-lock.v1",
      manifest: {sha256: $m}, payload_zip: {sha256: $p, size_bytes: $s}}' >"$d/archive-lock.json"
  (cd "$d" && sha256sum archive-manifest.json archive-lock.json bpfcompat-research-v1-payload.zip >RELEASE-CHECKSUMS.txt)
}
write_lock "$good"
cp "$good/archive-lock.json" "$work/repo-lock.json"

# gh stub.
#   STUB_RELEASE_DIR    assets served by `release view` (names) and `release download`
#   STUB_VIEW           ok | notfound | error
#   STUB_DRAFT / STUB_PRE   release flags (default false)
#   STUB_DOWNLOAD_EXTRA     extra file dropped into the download dir
#   STUB_ATTEST_FAIL        asset basename whose attestation fails
mkdir -p "$work/bin"
cat >"$work/bin/gh" <<'STUB'
#!/usr/bin/env bash
case "$1 $2" in
  "release view")
    case "${STUB_VIEW:-ok}" in
      notfound) echo "release not found" >&2; exit 1 ;;
      error) echo "HTTP 502: Bad Gateway" >&2; exit 1 ;;
    esac
    names="$(cd "$STUB_RELEASE_DIR" && find . -maxdepth 1 -type f -printf '%f\n' | jq -Rsc 'split("\n") | map(select(length>0)) | map({name: .})')"
    jq -n --argjson a "$names" --argjson d "${STUB_DRAFT:-false}" --argjson p "${STUB_PRE:-false}" \
      '{tagName: "research-v1", isDraft: $d, isPrerelease: $p, assets: $a}' ;;
  "release download")
    dir=""
    while [[ $# -gt 0 ]]; do [[ "$1" == --dir ]] && dir="$2"; shift; done
    cp "$STUB_RELEASE_DIR"/* "$dir/"
    [[ -z "${STUB_DOWNLOAD_EXTRA:-}" ]] || printf x >"$dir/$STUB_DOWNLOAD_EXTRA" ;;
  "attestation verify")
    printf '%s\n' "$*" >>"$STUB_ATTEST_LOG"
    [[ -n "${STUB_ATTEST_FAIL:-}" && "$(basename "$3")" == "$STUB_ATTEST_FAIL" ]] && exit 1
    exit 0 ;;
  *) echo "unexpected gh call: $*" >&2; exit 99 ;;
esac
STUB
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH" STUB_ATTEST_LOG="$work/attest.log"

rel="$work/release"
reset_release() { rm -rf "$rel"; cp -a "$good" "$rel"; }

fail=0
# run <expect: false|true|fail> <description> <reason> [env assignments...]
run() {
  local expect="$1" desc="$2" reason="$3"; shift 3
  : >"$STUB_ATTEST_LOG"
  set +e
  env STUB_RELEASE_DIR="$rel" BPFCOMPAT_RESEARCH_REMOTE="$work/origin" GITHUB_SHA="$later" "$@" \
    bash "$SCRIPT" Kernel-Guard/bpfcompat research-v1 "$pinned" "$work/repo-lock.json" "$work/state" \
    >"$work/out" 2>"$work/err"
  local rc=$?
  set -e
  local ok=1
  if [[ "$expect" == fail ]]; then
    [[ "$rc" -ne 0 ]] || ok=0
    grep -q 'publish=' "$work/out" && ok=0
    grep -Fq -- "$reason" "$work/err" || ok=0
  else
    [[ "$rc" -eq 0 && "$(cat "$work/out")" == "publish=$expect" ]] || ok=0
    [[ -z "$reason" ]] || grep -Fq -- "$reason" "$work/err" || ok=0
  fi
  if (( ok )); then
    printf 'ok:   %s\n' "$desc"
  else
    printf 'FAIL: %s (rc=%s, expected %s / %s)\n' "$desc" "$rc" "$expect" "$reason" >&2
    sed 's/^/      out: /' "$work/out" >&2; sed 's/^/      err: /' "$work/err" >&2
    fail=1
  fi
}

reset_release
run false "intact release, later commit: verified, not re-published" "verified intact"
[[ "$(wc -l <"$STUB_ATTEST_LOG")" -eq 4 ]] && grep -c -- "--source-digest $pinned --source-ref refs/heads/main" "$STUB_ATTEST_LOG" | grep -qx 4 &&
  grep -c -- "--signer-workflow Kernel-Guard/bpfcompat/.github/workflows/scholarly-release-v1.yml" "$STUB_ATTEST_LOG" | grep -qx 4 &&
  echo "ok:   all four assets attestation-verified against the pinned commit" ||
  { echo "FAIL: attestation calls not bound to the pinned commit" >&2; cat "$STUB_ATTEST_LOG" >&2; fail=1; }

run true "nothing published, running from the pinned commit: first publication" "first publication" \
  BPFCOMPAT_RESEARCH_REMOTE="$work/notag" STUB_VIEW=notfound GITHUB_SHA="$pinned"
run fail "nothing published, running from a later commit: never re-created" "would create a different research-v1" \
  BPFCOMPAT_RESEARCH_REMOTE="$work/notag" STUB_VIEW=notfound
run fail "tag without release" "tag exists without its release" STUB_VIEW=notfound
run fail "release without tag" "release exists without its tag" BPFCOMPAT_RESEARCH_REMOTE="$work/notag"
run fail "release lookup error is not 'absent'" "could not query release" STUB_VIEW=error
run fail "unreachable tag remote" "could not query tag" BPFCOMPAT_RESEARCH_REMOTE="$work/does-not-exist"
run fail "malformed GITHUB_SHA" "GITHUB_SHA is not a full SHA" GITHUB_SHA=main
run fail "draft release" "is not the published four-asset research release" STUB_DRAFT=true
run fail "prerelease" "is not the published four-asset research release" STUB_PRE=true

# Tag moved / recreated elsewhere.
git_q clone -q "$work/origin" "$work/moved"
git_q -C "$work/moved" tag -d research-v1
git_q -C "$work/moved" tag -a research-v1 -m moved "$later"
run fail "tag peels to a different commit" "peels to $later" BPFCOMPAT_RESEARCH_REMOTE="$work/moved"
git_q clone -q "$work/origin" "$work/light"
git_q -C "$work/light" tag -d research-v1
git_q -C "$work/light" tag research-v1 "$pinned"
run fail "lightweight tag" "is not an annotated tag" BPFCOMPAT_RESEARCH_REMOTE="$work/light"

reset_release; printf x >"$rel/extra.txt"
run fail "extra release asset" "is not the published four-asset research release"
reset_release; rm "$rel/archive-manifest.json"
run fail "missing release asset" "is not the published four-asset research release"
reset_release
run fail "download returns an unlisted file" "do not match the expected four files" STUB_DOWNLOAD_EXTRA=injected.sh

reset_release; printf ' ' >>"$rel/archive-lock.json"
(cd "$rel" && sha256sum archive-manifest.json archive-lock.json bpfcompat-research-v1-payload.zip >RELEASE-CHECKSUMS.txt)
run fail "published lock differs from the reviewed lock" "differs from the reviewed"

# Payload swapped and every self-consistent file regenerated: only the
# reviewed lock in the repository can catch it.
reset_release; printf 'PK-evil' >"$rel/bpfcompat-research-v1-payload.zip"; write_lock "$rel"
run fail "payload swapped with a regenerated lock" "differs from the reviewed"
# Payload swapped while the lock is kept: lock binding catches it.
reset_release; printf 'PK-evil' >"$rel/bpfcompat-research-v1-payload.zip"
(cd "$rel" && sha256sum archive-manifest.json archive-lock.json bpfcompat-research-v1-payload.zip >RELEASE-CHECKSUMS.txt)
run fail "payload swapped, lock kept" "does not match the archive lock"
# Same-size swap: only the payload digest binding can catch it.
reset_release; printf 'PK-payload-BYTES' >"$rel/bpfcompat-research-v1-payload.zip"
(cd "$rel" && sha256sum archive-manifest.json archive-lock.json bpfcompat-research-v1-payload.zip >RELEASE-CHECKSUMS.txt)
run fail "same-size payload swapped, lock kept" "does not match the archive lock"
reset_release; printf '{"files": 669}\n' >"$rel/archive-manifest.json"
(cd "$rel" && sha256sum archive-manifest.json archive-lock.json bpfcompat-research-v1-payload.zip >RELEASE-CHECKSUMS.txt)
run fail "manifest swapped, lock kept" "does not match the archive lock"

reset_release; sed -i '/payload.zip/d' "$rel/RELEASE-CHECKSUMS.txt"
run fail "checksums file omits an asset" "does not list exactly the three archive files"
reset_release; printf '%064d  archive-lock.json\n' 0 >>"$rel/RELEASE-CHECKSUMS.txt"
run fail "checksums file lists an asset twice" "does not list exactly the three archive files"
reset_release; sed -i '1s/  archive-manifest.json$/ *archive-manifest.json/' "$rel/RELEASE-CHECKSUMS.txt"
run fail "checksums file uses a binary-mode marker" "does not list exactly the three archive files"
reset_release; sed -i '1s/  archive-manifest.json$/  .\/archive-manifest.json/' "$rel/RELEASE-CHECKSUMS.txt"
run fail "checksums file uses a relative path" "does not list exactly the three archive files"
reset_release; sed -i "1s/^[0-9a-f]\{8\}/00000000/" "$rel/RELEASE-CHECKSUMS.txt"
run fail "checksums file entry does not verify" "does not verify"

reset_release
for asset in archive-lock.json archive-manifest.json bpfcompat-research-v1-payload.zip RELEASE-CHECKSUMS.txt; do
  run fail "missing attestation: $asset" "$asset has no scholarly-release-v1.yml attestation" STUB_ATTEST_FAIL="$asset"
done

if (( fail )); then
  echo "research-v1-release-state_test: FAILED" >&2
  exit 1
fi
echo "research-v1-release-state_test: all checks passed"
