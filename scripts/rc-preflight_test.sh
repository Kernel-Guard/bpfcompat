#!/usr/bin/env bash
# Regression cover for scripts/rc-preflight.sh, the read-only RC inventory.
#
# A fake `gh` answers `gh api <path>` from a route table (glob -> HTTP status ->
# fixture file) and `gh release download` from a fixture SHA256SUMS, and logs
# every call so the test can prove nothing but reads happened. "Now" is fixed
# with BPFCOMPAT_PREFLIGHT_NOW. The checkout's own release.yaml, CHANGELOG,
# lock and distribution policy are read as they are.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRE="$ROOT_DIR/scripts/rc-preflight.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
failures=0
fail() { echo "[rc-preflight-test] FAIL: $*" >&2; failures=$((failures + 1)); }
ok() { echo "[rc-preflight-test] ok: $*"; }

version="$(awk -F': ' '$1 == "release_version" { print $2 }' "$ROOT_DIR/release.yaml")"
TAG="v${version}"
[[ "$TAG" =~ -rc\.[0-9]+$ ]] || { echo "[rc-preflight-test] skip: release.yaml is not a prerelease ($version)"; exit 0; }
VSHA="$(awk -F= '$1 == "reproduces" { split($2, a, " "); print a[2] }' "$ROOT_DIR/validator/build-inputs.lock")"
C1="$(printf 'a%.0s' {1..40})" C2="$(printf 'b%.0s' {1..40})" TAGOBJ="$(printf 'c%.0s' {1..40})"
PUB="2026-11-02T10:00:00Z"
PUB_EPOCH="$(date -u -d "$PUB" +%s)"
at() { date -u -d "@$((PUB_EPOCH + $1 * 3600 + 600))" +%Y-%m-%dT%H:%M:%SZ; } # <hours> -> ISO, 10 min past the hour

mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_LOG"
if [[ "$1" == api ]]; then
  while IFS=$'\t' read -r glob status file; do
    [[ -z "$glob" || "$glob" == \#* ]] && continue
    # shellcheck disable=SC2053
    if [[ "$2" == $glob ]]; then
      case "$status" in
        200) cat "$FIX/$file"; exit 0 ;;
        *) echo "gh: HTTP $status (https://api.github.com/$2)" >&2; exit 1 ;;
      esac
    fi
  done <"$FIX/routes"
  echo "gh: HTTP 404 (unrouted $2)" >&2; exit 1
fi
if [[ "$1 $2" == "release download" ]]; then
  dir=""; while [[ $# -gt 0 ]]; do [[ "$1" == --dir ]] && dir="$2"; shift; done
  mkdir -p "$dir"; cp "$FIX/SHA256SUMS" "$dir/SHA256SUMS"; exit 0
fi
echo "gh shim: refusing non-read command: $*" >&2; exit 9
EOF
chmod +x "$tmp/bin/gh"

b64() { base64 -w0 "$1"; }
contents() { jq -n --arg c "$(b64 "$1")" '{content: $c}'; }

# scenario <name>: a fixture dir with a published release by default.
scenario() {
  F="$tmp/$1"; mkdir -p "$F"
  jq -n --arg s "$TAGOBJ" '{object: {type: "tag", sha: $s}}' >"$F/ref.json"
  jq -n --arg s "$C1" '{object: {type: "commit", sha: $s}}' >"$F/tagobj.json"
  jq -n --arg t "$TAG" '{workflow_runs: [{id: 900, run_attempt: 1, head_branch: $t, status: "completed", conclusion: "success"}]}' >"$F/runs.json"
  names=(bpfcompat-linux-amd64 bpfcompat-linux-arm64 bpfcompat-validator-static-linux-amd64 bpfcompat-third-party-licenses.tar.gz
    bpfcompat-validator-relink-kit-linux-amd64.tar.gz validator-build-inputs.json SHA256SUMS SHA256SUMS.sig SHA256SUMS.crt
    bpfcompat.sbom.cdx.json bpfcompat.sbom.cdx.sig bpfcompat.sbom.cdx.crt release-candidate-evidence.json)
  printf '%s\n' "${names[@]}" | jq -R '{name: .}' | jq -s --arg t "$TAG" --arg p "$PUB" \
    '[{tag_name: $t, draft: false, prerelease: true, published_at: $p, assets: .}]' >"$F/releases.json"
  { for n in bpfcompat-linux-amd64 bpfcompat-linux-arm64 bpfcompat-third-party-licenses.tar.gz bpfcompat-validator-relink-kit-linux-amd64.tar.gz validator-build-inputs.json; do
      printf '%064d  %s\n' 1 "$n"; done
    printf '%s  bpfcompat-validator-static-linux-amd64\n' "$VSHA"; } >"$F/SHA256SUMS"
  contents "$ROOT_DIR/distribution/policy.json" >"$F/policy.json"
  jq -n --arg t "$TAG" --arg c "$C1" '{tag: $t, commit_sha: $c}' >"$F/cc-raw.json"; contents "$F/cc-raw.json" >"$F/cc.json"
  printf '      - name: x\n        # bpfcompat-pin: candidate\n        uses: Kernel-Guard/bpfcompat@%s # %s\n' "$C1" "$TAG" >"$F/consumer-raw.yml"; contents "$F/consumer-raw.yml" >"$F/consumer.json"
  printf 'env:\n  CANDIDATE_TAG: %s\n  CANDIDATE_PUBLISHED_AT: "%s"\n' "$TAG" "$PUB" >"$F/rcc-raw.yml"; contents "$F/rcc-raw.yml" >"$F/rcc.json"
  jq -n --arg m "$(at 0)" --arg a "$(at 25)" --arg b "$(at 70)" '{workflow_runs: [
    {id: 1, run_attempt: 1, event: "workflow_dispatch", status: "completed", conclusion: "success", run_started_at: $m},
    {id: 2, run_attempt: 1, event: "schedule", status: "completed", conclusion: "success", run_started_at: $a},
    {id: 3, run_attempt: 1, event: "schedule", status: "completed", conclusion: "success", run_started_at: $b}]}' >"$F/cruns.json"
  jq -n '{workflow_runs: [range(4) | {status: "completed", conclusion: "success"}]}' >"$F/camp.json"
  jq -n '{workflow_runs: [{id: 77, status: "completed", conclusion: "success"}]}' >"$F/drill.json"
  cat >"$F/routes" <<EOF
repos/*/git/ref/tags/*	200	ref.json
repos/*/git/tags/*	200	tagobj.json
repos/*/actions/workflows/release-artifacts.yml/runs*	200	runs.json
repos/*/releases?per_page=100	200	releases.json
repos/*/contents/distribution/policy.json?ref=*	200	policy.json
repos/*/contents/.github/campaign-candidate.json?ref=main	200	cc.json
repos/*/contents/.github/workflows/consumer-canary.yml?ref=main	200	consumer.json
repos/*/contents/.github/workflows/release-candidate-canary.yml?ref=main	200	rcc.json
repos/*/actions/workflows/release-candidate-canary.yml/runs*	200	cruns.json
repos/*/actions/workflows/latest-kernel-compatibility.yml/runs*	200	camp.json
repos/*/actions/workflows/rollback-drill.yml/runs*	200	drill.json
EOF
}
route() { sed -i "1i $2" "$tmp/$1/routes"; } # prepend an overriding route
run() { # <scenario> <now-hours-after-publication> [args...]
  local s="$1" h="$2"; shift 2
  : >"$tmp/gh.log"
  set +e
  PATH="$tmp/bin:$PATH" FIX="$tmp/$s" GH_LOG="$tmp/gh.log" BPFCOMPAT_PREFLIGHT_NOW=$((PUB_EPOCH + h * 3600)) \
    bash "$PRE" --tag "$TAG" "$@" >"$tmp/out" 2>&1
  rc=$?
  set -e
}
line() { grep -E "^$1 +$2 " "$tmp/out" >/dev/null; }
show() { sed 's/^/    | /' "$tmp/out" >&2; }

# 1. Before the tag: everything after it is PENDING, nothing is MISSING.
scenario pretag; route pretag $'repos/*/git/ref/tags/*\t404\tnone'
run pretag 0
if [[ $rc -eq 0 ]] && line PENDING "tag exists" && line PENDING "validator identity" && line PENDING "canary t-plus-72h" &&
  ! grep -q '^MISSING' "$tmp/out" && ! grep -q '^VERIFIED  tag' "$tmp/out"; then ok "no tag: later items PENDING, exit 0"
else fail "no tag (rc=$rc)"; show; fi

# 2. A lookup failure is not "not found": the report aborts (exit 3).
scenario apierr; route apierr $'repos/*/git/ref/tags/*\t502\tnone'
run apierr 0
if [[ $rc -eq 3 ]] && ! grep -q 'tag exists' "$tmp/out" && grep -q 'lookup failed' "$tmp/out"; then ok "API failure aborts instead of reporting PENDING"
else fail "API failure (rc=$rc)"; show; fi
scenario apierr2; route apierr2 $'repos/*/releases?per_page=100\t500\tnone'
run apierr2 0
if [[ $rc -eq 3 ]] && ! grep -q 'release staged' "$tmp/out"; then ok "a later lookup failure aborts too"
else fail "later API failure (rc=$rc)"; show; fi

# 3. Published release, all evidence observable, inside every window.
scenario full
run full 200 --commit "$C1"
if [[ $rc -eq 0 ]] && line VERIFIED "tag exists" && grep -q "as approved" "$tmp/out" && line VERIFIED "tag build" &&
  line VERIFIED "release staged" && line VERIFIED "SHA256SUMS lists required assets" && line VERIFIED "validator identity" &&
  line VERIFIED "optional assets match tagged policy" && line VERIFIED "RC published as prerelease" &&
  line VERIFIED "designated: campaign-candidate.json" && line VERIFIED "designated: consumer-canary candidate pin" &&
  line VERIFIED "designated: release-candidate-canary" && line VERIFIED "canary manual" && line VERIFIED "canary t-plus-24h" &&
  line VERIFIED "canary t-plus-72h" && line VERIFIED "scheduled campaigns" && line VERIFIED "rollback drill run" &&
  line PENDING "operator promotion confirmation"; then ok "annotated tag dereferenced; every observable item VERIFIED"
else fail "full scenario (rc=$rc)"; show; fi
if awk '!/^api / && !/^release download .*--pattern SHA256SUMS/' "$tmp/gh.log" | grep -q .; then fail "non-read gh call: $(cat "$tmp/gh.log")"
elif grep -qE -- '(-X|--method)' "$tmp/gh.log"; then fail "gh api called with a method"
else ok "only GET api calls and the SHA256SUMS download were made"; fi

# 4. Wrong identities are MISSING.
run full 200 --commit "$C2"
if [[ $rc -eq 1 ]] && line MISSING "tag exists"; then ok "tag on another commit than approved: MISSING"; else fail "commit mismatch (rc=$rc)"; show; fi
scenario badval; sed -i "s/^$VSHA /$(printf '%064d' 7) /" "$tmp/badval/SHA256SUMS"
run badval 200
if [[ $rc -eq 1 ]] && line MISSING "validator identity"; then ok "different validator digest: MISSING"; else fail "validator mismatch (rc=$rc)"; show; fi
scenario noasset; jq '.[0].assets |= map(select(.name != "bpfcompat-third-party-licenses.tar.gz"))' "$tmp/noasset/releases.json" >"$tmp/x" && mv "$tmp/x" "$tmp/noasset/releases.json"
run noasset 200
if [[ $rc -eq 1 ]] && line MISSING "release staged" && grep -q 'absent: bpfcompat-third-party-licenses.tar.gz' "$tmp/out"; then ok "missing release asset: MISSING"
else fail "missing asset (rc=$rc)"; show; fi
scenario optional; printf '%064d  bpfcompat-validator-native-sources.tar\n' 5 >>"$tmp/optional/SHA256SUMS"
run optional 200
if [[ $rc -eq 1 ]] && line MISSING "optional assets match tagged policy"; then ok "optional asset shipped against the tagged (undecided) policy: MISSING"
else fail "optional asset (rc=$rc)"; show; fi

# 5. Time: windows open are PENDING, closed and empty are MISSING; elapsed time never VERIFIES.
scenario early; jq '.workflow_runs = [.workflow_runs[0]]' "$tmp/early/cruns.json" >"$tmp/x" && mv "$tmp/x" "$tmp/early/cruns.json"
jq '.workflow_runs = []' "$tmp/early/camp.json" >"$tmp/x" && mv "$tmp/x" "$tmp/early/camp.json"
jq '.workflow_runs = []' "$tmp/early/drill.json" >"$tmp/x" && mv "$tmp/x" "$tmp/early/drill.json"
run early 50
if line PENDING "canary t-plus-72h" && line MISSING "canary t-plus-24h" && line PENDING "scheduled campaigns" &&
  grep -q '0 of 4' "$tmp/out" && line PENDING "rollback drill run"; then ok "50h: T+24h window closed empty is MISSING, T+72h still PENDING"
else fail "time windows at 50h (rc=$rc)"; show; fi
run early 400
if line MISSING "canary t-plus-72h" && line PENDING "scheduled campaigns" && ! line VERIFIED "scheduled campaigns"; then
  ok "400h with no runs: T+72h MISSING, campaigns still PENDING (never VERIFIED by time)"
else fail "time windows at 400h (rc=$rc)"; show; fi
scenario late; jq --arg l "$(at 35)" '.workflow_runs[1].run_started_at = $l' "$tmp/late/cruns.json" >"$tmp/x" && mv "$tmp/x" "$tmp/late/cruns.json"
run late 200
if line MISSING "canary t-plus-24h"; then ok "a schedule run outside 20-30h does not count as T+24h"; else fail "out-of-window run counted (rc=$rc)"; show; fi
scenario failedrun; jq '.workflow_runs[2].conclusion = "failure"' "$tmp/failedrun/cruns.json" >"$tmp/x" && mv "$tmp/x" "$tmp/failedrun/cruns.json"
run failedrun 200
if line MISSING "canary t-plus-72h"; then ok "a failed in-window run does not count"; else fail "failed run counted (rc=$rc)"; show; fi

# 6. Draft release: published-only items wait.
scenario draft; jq '.[0].draft = true | .[0].published_at = null' "$tmp/draft/releases.json" >"$tmp/x" && mv "$tmp/x" "$tmp/draft/releases.json"
run draft 200
if [[ $rc -eq 0 ]] && line PENDING "RC published as prerelease" && line PENDING "canary manual" && line VERIFIED "validator identity"; then
  ok "draft: verified assets, publication-dependent items PENDING"
else fail "draft (rc=$rc)"; show; fi

# 7. Usage.
if bash "$PRE" --tag v0.4.0 >/dev/null 2>&1; then fail "stable tag accepted"; else ok "non-RC tag refused"; fi

if [[ $failures -ne 0 ]]; then echo "[rc-preflight-test] $failures failure(s)" >&2; exit 1; fi
echo "rc-preflight_test: all checks passed"
