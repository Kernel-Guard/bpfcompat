#!/usr/bin/env bash
# Negative-mutation tests for scripts/campaign-candidate-bind.sh.
#
# Real git (a local remote with a real annotated tag and a real candidate
# checkout); `gh` is a stub that serves a fixture release and records every
# attestation call, so each mutation changes exactly one fact.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/campaign-candidate-bind.sh"
command -v jq >/dev/null || { echo "SKIP: jq required" >&2; exit 0; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git_q() { git -c user.name=t -c user.email=t@example.invalid -c init.defaultBranch=main "$@" >/dev/null; }

# A remote with the candidate commit, a later commit, and an annotated RC tag.
git_q init -q "$work/origin"
echo one >"$work/origin/f"; git_q -C "$work/origin" add f; git_q -C "$work/origin" commit -q -m one
commit="$(git -C "$work/origin" rev-parse HEAD)"
git_q -C "$work/origin" tag -a v0.4.0-rc.4 -m rc4
echo two >"$work/origin/f"; git_q -C "$work/origin" commit -q -am two
other="$(git -C "$work/origin" rev-parse HEAD)"
git_q clone -q "$work/origin" "$work/src"
git_q -C "$work/src" checkout -q "$commit"

# Fixture release assets.
rel="$work/release"; mkdir -p "$rel"
make_cli() { # <tag> <commit>
  printf '#!/bin/sh\n[ "$1" = version ] && printf %s\\n %s\n' "'" \
    "$(jq -nc --arg v "$1" --arg c "$2" '{name: "bpfcompat", version: $v, commit: $c}')'" >"$rel/bpfcompat-linux-amd64"
  chmod +x "$rel/bpfcompat-linux-amd64"
}
make_cli v0.4.0-rc.4 "$commit"
printf 'validator-bytes' >"$rel/bpfcompat-validator-static-linux-amd64"
(cd "$rel" && sha256sum bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 >SHA256SUMS)
write_evidence() { # <commit>
  jq -n --arg c "$1" --arg s "$(sha256sum "$rel/SHA256SUMS" | awk '{print $1}')" '{
    schema_version: "v0.1", repository: "Kernel-Guard/bpfcompat", channel: "prerelease",
    tag: "v0.4.0-rc.4", commit_sha: $c, checksums_sha256: $s}' >"$rel/release-candidate-evidence.json"
}
write_evidence "$commit"
snapshot="$work/release.good"; cp -a "$rel" "$snapshot"

# gh stub: release view/download from $rel; attestation verify logged and
# failing for any basename listed in $STUB_ATTEST_FAIL.
mkdir -p "$work/bin"
cat >"$work/bin/gh" <<'STUB'
#!/usr/bin/env bash
case "$1 $2" in
  "release view") printf '%s\n' "${STUB_RELEASE_STATE:-false true}" ;;
  "release download")
    dir=""; pattern=""
    while [[ $# -gt 0 ]]; do
      case "$1" in --dir) dir="$2"; shift ;; --pattern) pattern="$2"; shift ;; esac
      shift
    done
    [[ -f "$STUB_RELEASE/$pattern" ]] || exit 1
    cp "$STUB_RELEASE/$pattern" "$dir/" ;;
  "attestation verify")
    printf '%s\n' "$*" >>"$STUB_ATTEST_LOG"
    for f in ${STUB_ATTEST_FAIL:-}; do [[ "$(basename "$3")" == "$f" ]] && exit 1; done
    exit 0 ;;
  *) echo "unexpected gh call: $*" >&2; exit 99 ;;
esac
STUB
chmod +x "$work/bin/gh"

write_pin() {
  jq -n --arg c "${1:-$commit}" --arg s "$(sha256sum "$rel/SHA256SUMS" | awk '{print $1}')" \
    --arg e "$(sha256sum "$rel/release-candidate-evidence.json" | awk '{print $1}')" \
    '{schema_version: "v0.1", tag: "v0.4.0-rc.4", commit_sha: $c, checksums_sha256: $s, candidate_evidence_sha256: $e}' \
    >"$work/pin.json"
}

fail=0
ok() { printf 'ok:   %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

run() { # <name> [VAR=value ...]
  local name="$1"; shift
  out="$work/out-$name"; : >"$work/attest-$name.log"
  set +e
  env PATH="$work/bin:$PATH" STUB_RELEASE="$rel" STUB_ATTEST_LOG="$work/attest-$name.log" \
    BPFCOMPAT_CAMPAIGN_REMOTE="$work/origin" "$@" \
    bash "$SCRIPT" "$work/pin.json" "$work/src" "$out" >"$work/$name.log" 2>&1
  rc=$?
  set -e
}
reset() { rm -rf "$rel"; cp -a "$snapshot" "$rel"; write_pin; git_q -C "$work/src" checkout -q -f "$commit"; }
refuse() { # <name> <expected-message-fragment>
  if [[ "$rc" -ne 0 ]] && grep -q -- "$2" "$work/$1.log" && [[ ! -e "$out/candidate-binding.json" ]]; then
    ok "$1: refused ($2)"
  else
    bad "$1: rc=$rc, want refusal containing '$2'"; sed 's/^/    /' "$work/$1.log" >&2
  fi
}

# Happy path.
reset; run good
if [[ "$rc" -eq 0 ]] && jq -e --arg c "$commit" '.bound and .commit_sha == $c and .tag == "v0.4.0-rc.4"' "$out/candidate-binding.json" >/dev/null; then
  ok "good: bound to the pinned tag and commit"
else
  bad "good: rc=$rc"; sed 's/^/    /' "$work/good.log" >&2
fi
want_sha="$(sha256sum "$rel/bpfcompat-validator-static-linux-amd64" | awk '{print $1}')"
grep -qx "BPFCOMPAT_VALIDATOR_SHA256=$want_sha" "$out/candidate.env" && ok "good: validator pinned by digest for the runner" || bad "good: candidate.env lacks the validator digest"
if [[ "$(grep -c -- "--source-digest $commit --source-ref refs/tags/v0.4.0-rc.4" "$work/attest-good.log")" -eq 3 ]] \
   && [[ "$(grep -c -- '--signer-workflow Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml' "$work/attest-good.log")" -eq 3 ]]; then
  ok "good: evidence, CLI and validator attestations are bound to the tag, commit and release workflow"
else
  bad "good: attestation calls not bound as required"; cat "$work/attest-good.log" >&2
fi

# No pin: explicitly unbound, never an error and never bound.
reset; rm -f "$work/pin.json"; run nopin
jq -e '.bound == false' "$work/out-nopin/candidate-binding.json" >/dev/null 2>&1 && [[ "$rc" -eq 0 ]] \
  && ok "nopin: campaign is explicitly unbound" || bad "nopin: rc=$rc"

reset; write_pin "$other"; run wrong-commit
refuse wrong-commit "not the pinned"

reset; run draft STUB_RELEASE_STATE="true true"
refuse draft "not a published prerelease"
reset; run stable-release STUB_RELEASE_STATE="false false"
refuse stable-release "not a published prerelease"

reset; echo "0000000000000000000000000000000000000000000000000000000000000000  extra" >>"$rel/SHA256SUMS"; run sums-substituted
refuse sums-substituted "SHA256SUMS of v0.4.0-rc.4 does not match"

reset; jq '.positive_report_sha256 = "x"' "$rel/release-candidate-evidence.json" >"$work/e" && mv "$work/e" "$rel/release-candidate-evidence.json"; run evidence-substituted
refuse evidence-substituted "release-candidate-evidence.json of v0.4.0-rc.4 does not match"

# Evidence for another commit, with a pin that matches its bytes: the content
# check still refuses it.
reset; write_evidence "$other"; write_pin; run evidence-other-commit
refuse evidence-other-commit "does not describe"

reset; printf 'swapped' >"$rel/bpfcompat-validator-static-linux-amd64"; run validator-swapped
refuse validator-swapped "bpfcompat-validator-static-linux-amd64 does not match SHA256SUMS"

reset; rm "$rel/bpfcompat-validator-static-linux-amd64"; run validator-missing
refuse validator-missing "cannot download bpfcompat-validator-static-linux-amd64"

reset; run attest-fails STUB_ATTEST_FAIL=bpfcompat-linux-amd64
refuse attest-fails "has no release-artifacts.yml attestation"

# A CLI whose bytes are listed in SHA256SUMS but that reports another build.
reset; make_cli v0.4.0-rc.4 "$other"
(cd "$rel" && sha256sum bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 >SHA256SUMS); write_evidence "$commit"; write_pin
run cli-other-build
refuse cli-other-build "not v0.4.0-rc.4 at"

# Release builds embed `git rev-parse --short=12` (Makefile, release-artifacts.yml).
# A 12-character prefix of the pinned commit is accepted; a short prefix of
# another commit, or one too short to be meaningful, is not.
reset; make_cli v0.4.0-rc.4 "${commit:0:12}"
(cd "$rel" && sha256sum bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 >SHA256SUMS); write_evidence "$commit"; write_pin
run cli-short-commit
[[ "$rc" -eq 0 ]] && ok "cli-short-commit: a 12-character prefix of the pinned commit is accepted" || { bad "cli-short-commit: rc=$rc"; sed 's/^/    /' "$work/cli-short-commit.log" >&2; }
reset; make_cli v0.4.0-rc.4 "${other:0:12}"
(cd "$rel" && sha256sum bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 >SHA256SUMS); write_evidence "$commit"; write_pin
run cli-short-other
refuse cli-short-other "not v0.4.0-rc.4 at"
reset; make_cli v0.4.0-rc.4 "${commit:0:7}"
(cd "$rel" && sha256sum bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 >SHA256SUMS); write_evidence "$commit"; write_pin
run cli-too-short
refuse cli-too-short "not v0.4.0-rc.4 at"
reset; make_cli v0.4.0-rc.3 "$commit"
(cd "$rel" && sha256sum bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 >SHA256SUMS); write_evidence "$commit"; write_pin
run cli-other-version
refuse cli-other-version "not v0.4.0-rc.4 at"

reset; git_q -C "$work/src" checkout -q "$other"; run source-wrong-commit
refuse source-wrong-commit "candidate source is at"

reset; echo dirty >"$work/src/f"; run source-modified
refuse source-modified "local modifications"

reset; jq '.extra = 1' "$work/pin.json" >"$work/p" && mv "$work/p" "$work/pin.json"; run pin-malformed
refuse pin-malformed "is malformed"

if [[ "$fail" -ne 0 ]]; then echo "campaign-candidate-bind_test: FAILED" >&2; exit 1; fi
echo "campaign-candidate-bind_test: all checks passed"
