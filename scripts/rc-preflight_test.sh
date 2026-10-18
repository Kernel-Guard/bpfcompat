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
DIG="sha256:$(printf 'd%.0s' {1..64})"
RCN="${TAG##*-rc.}"
PUB="2026-11-02T10:00:00Z"
PUB_EPOCH="$(date -u -d "$PUB" +%s)"
at() { date -u -d "@$((PUB_EPOCH + $1 * 3600 + 600))" +%Y-%m-%dT%H:%M:%SZ; } # <hours> -> ISO, 10 min past the hour
DESIGNATED="$(date -u -d "@$((PUB_EPOCH + 300))" +%Y-%m-%dT%H:%M:%SZ)"            # designation merged 5 min after T0

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
  dir="" pat=""
  while [[ $# -gt 0 ]]; do case "$1" in --dir) dir="$2";; --pattern) pat="$2";; esac; shift; done
  if [[ -f "$FIX/download-fail" ]]; then echo "gh: HTTP 403" >&2; exit 1; fi
  mkdir -p "$dir"; cp "$FIX/$pat" "$dir/$pat"; exit 0
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
  printf 'jobs:\n  test:\n    steps:\n      - name: x\n        # bpfcompat-pin: candidate\n        uses: Kernel-Guard/bpfcompat@%s # %s\n' "$C1" "$TAG" >"$F/consumer-raw.yml"; contents "$F/consumer-raw.yml" >"$F/consumer.json"
  printf 'env:\n  CANDIDATE_TAG: %s\n  CANDIDATE_COMMIT: %s\n  CANDIDATE_DIGEST: %s\n  CANDIDATE_PUBLISHED_AT: "%s"\njobs:\n  x:\n    name: rc%s-canary-component-clean-install-1\n    uses: Kernel-Guard/bpfcompat@%s # %s\n    out: reports/rc%s-action.json\n' \
    "$TAG" "$C1" "$DIG" "$PUB" "$RCN" "$C1" "$TAG" "$RCN" >"$F/rcc-raw.yml"; contents "$F/rcc-raw.yml" >"$F/rcc.json"
  jq -n --arg i "ghcr.io/kernel-guard/bpfcompat@$DIG" '{image: $i}' >"$F/release-candidate-evidence.json"
  jq -n '[{sha: "e000000000000000000000000000000000000000", commit: {committer: {date: "2020-01-01T00:00:00Z"}}}]' >"$F/commits.json"
  jq -n --arg m "$DESIGNATED" '[{merged_at: $m, base: {ref: "main"}}]' >"$F/pulls.json"
  jq -n '{jobs: [{name: "Select RC observation window", conclusion: "success"}, {name: "Clean install", conclusion: "success"}]}' >"$F/jobs.json"
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
repos/*/commits?sha=main&path=*	200	commits.json
repos/*/commits/*/pulls	200	pulls.json
repos/*/actions/runs/*/jobs*	200	jobs.json
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
  line VERIFIED "canary t-plus-72h" && line VERIFIED "scheduled campaigns" && line PENDING "rollback drill run" &&
  grep -q 'which candidate it drilled' "$tmp/out" &&
  line PENDING "operator promotion confirmation"; then ok "annotated tag dereferenced; every observable item VERIFIED"
else fail "full scenario (rc=$rc)"; show; fi
if awk '!/^api / && !/^release download .*--pattern (SHA256SUMS|release-candidate-evidence\.json) /' "$tmp/gh.log" | grep -q .; then fail "non-read gh call: $(cat "$tmp/gh.log")"
elif grep -qE -- '(-X|--method|-f |-F |--field|--input)' "$tmp/gh.log"; then fail "gh api called with a method or body"
else ok "only GET api calls and the two text downloads were made"; fi

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

# 7. Designation must cover every candidate-bound value; runs before it do not count.
scenario stale; sed -i "s/rc${RCN}-canary-component-clean-install-1/rc4-canary-component-clean-install-1/" "$tmp/stale/rcc-raw.yml"
contents "$tmp/stale/rcc-raw.yml" >"$tmp/stale/rcc.json"
run stale 200
if line PENDING "designated: release-candidate-canary" && grep -q "artifact/report names" "$tmp/out" && line PENDING "canary manual" &&
  grep -q 'requires main to be designated' "$tmp/out"; then ok "leftover previous-candidate artifact names: not designated, canaries not counted"
else fail "stale designation (rc=$rc)"; show; fi
scenario olddigest; sed -i "s/CANDIDATE_DIGEST: .*/CANDIDATE_DIGEST: sha256:$(printf 'e%.0s' {1..64})/" "$tmp/olddigest/rcc-raw.yml"
contents "$tmp/olddigest/rcc-raw.yml" >"$tmp/olddigest/rcc.json"
run olddigest 200
if line PENDING "designated: release-candidate-canary" && grep -q "CANDIDATE_DIGEST=(\"sha256:$(printf 'e%.0s' {1..64})\" in the workflow env)" "$tmp/out"; then
  ok "previous candidate digest left in the canary: not designated, and the stale value is shown"
else fail "stale digest (rc=$rc)"; show; fi
scenario runtext
{ printf 'jobs:\n  notes:\n    steps:\n      - run: |\n          CANDIDATE_TAG: %s\n          CANDIDATE_COMMIT: %s\n          CANDIDATE_DIGEST: %s\n          CANDIDATE_PUBLISHED_AT: "%s"\n' "$TAG" "$C1" "$DIG" "$PUB"
  printf '  x:\n    name: rc%s-canary-component-clean-install-1\n    uses: Kernel-Guard/bpfcompat@%s # %s\n    out: reports/rc%s-action.json\n' "$RCN" "$C1" "$TAG" "$RCN"
  printf 'env:\n  CANDIDATE_TAG: v0.0.0-rc.1\n  CANDIDATE_COMMIT: %s\n  CANDIDATE_DIGEST: %s\n  CANDIDATE_PUBLISHED_AT: "%s"\n' "$C1" "$DIG" "$PUB"; } >"$tmp/runtext/rcc-raw.yml"
contents "$tmp/runtext/rcc-raw.yml" >"$tmp/runtext/rcc.json"
run runtext 200
if line PENDING "designated: release-candidate-canary" && grep -q 'CANDIDATE_TAG=' "$tmp/out"; then ok "current values in run text do not hide a stale workflow env"
else fail "run-text env (rc=$rc)"; show; fi
scenario prerun; LATE_DES="$(date -u -d "@$((PUB_EPOCH + 3 * 3600))" +%Y-%m-%dT%H:%M:%SZ)"
jq --arg d "$LATE_DES" '.[0].merged_at = $d' "$tmp/prerun/pulls.json" >"$tmp/x" && mv "$tmp/x" "$tmp/prerun/pulls.json"
# The API filter is what excludes earlier runs: serve only what created>=designation would return.
jq '.workflow_runs |= map(select(.event == "schedule"))' "$tmp/prerun/cruns.json" >"$tmp/prerun/cruns-filtered.json"
route prerun $'repos/*/actions/workflows/release-candidate-canary.yml/runs*\t200\tcruns-filtered.json'
run prerun 200
if grep -qF "created=%3E%3D${LATE_DES}" "$tmp/gh.log" && line PENDING "canary manual" && line VERIFIED "canary t-plus-24h"; then
  ok "runs are listed from the designation merge time, not from publication"
else fail "pre-designation run (rc=$rc)"; show; fi
scenario planonly; jq '.jobs = [.jobs[0], {name: "Clean install", conclusion: "skipped"}]' "$tmp/planonly/jobs.json" >"$tmp/x" && mv "$tmp/x" "$tmp/planonly/jobs.json"
run planonly 200
if line MISSING "canary t-plus-24h" && line MISSING "canary t-plus-72h"; then ok "a run whose later jobs the plan job skipped does not count"
else fail "plan-only run counted (rc=$rc)"; show; fi

scenario oldaction; printf '    uses: Kernel-Guard/bpfcompat@%s # v0.4.0-rc.4\n' "$C2" >>"$tmp/oldaction/rcc-raw.yml"
contents "$tmp/oldaction/rcc-raw.yml" >"$tmp/oldaction/rcc.json"
run oldaction 200
if line PENDING "designated: release-candidate-canary" && grep -q 'published-action pin' "$tmp/out"; then ok "canary Action pin left on another commit: not designated"
else fail "stale action pin (rc=$rc)"; show; fi
scenario nomarker; printf 'jobs: {}\n' >"$tmp/nomarker/consumer-raw.yml"; contents "$tmp/nomarker/consumer-raw.yml" >"$tmp/nomarker/consumer.json"
run nomarker 200
if line PENDING "designated: consumer-canary candidate pin" && grep -q "requires one '# bpfcompat-pin: candidate' marker" "$tmp/out"; then ok "missing pin marker is reported, not a silent exit"
else fail "missing pin marker (rc=$rc)"; show; fi

# An actual stale action cannot be hidden by a correct commented line or an
# alternative YAML scalar spelling. Keep these end-to-end with the fake API.
for variant in commented commentonly quoted lowercase tabbed ref subpath wrongtag; do
  scenario "pin-$variant"
  file="$F/rcc-raw.yml"
  case "$variant" in
    commented)
      sed -i "s/uses: Kernel-Guard\/bpfcompat@$C1/# uses: Kernel-Guard\/bpfcompat@$C1/" "$file"
      printf '    uses: Kernel-Guard/bpfcompat@v0.4.0-rc.4\n' >>"$file" ;;
    commentonly) sed -i "s/uses: Kernel-Guard/# uses: Kernel-Guard/" "$file" ;;
    quoted) printf '    uses: "Kernel-Guard/bpfcompat@%s" # %s\n' "$C2" "$TAG" >>"$file" ;;
    lowercase) printf '    uses: kernel-guard/bpfcompat@%s # %s\n' "$C2" "$TAG" >>"$file" ;;
    tabbed) printf '    uses:\tKernel-Guard/bpfcompat@%s # %s\n' "$C2" "$TAG" >>"$file" ;;
    ref) printf '    uses: Kernel-Guard/bpfcompat@main\n' >>"$file" ;;
    subpath) printf '    uses: Kernel-Guard/bpfcompat/sub@%s # %s\n' "$C1" "$TAG" >>"$file" ;;
    wrongtag) sed -i "s/# $TAG/# v9.9.9-rc.1/" "$file" ;;
  esac
  contents "$file" >"$F/rcc.json"
  run "pin-$variant" 200
  if line PENDING "designated: release-candidate-canary" && line PENDING "canary manual"; then
    ok "Action $variant cannot establish candidate designation"
  else fail "Action $variant falsely designated (rc=$rc)"; show; fi
done
for variant in commented duplicate stale-after-comment; do
  scenario "consumer-$variant"
  file="$F/consumer-raw.yml"
  case "$variant" in
    commented) sed -i 's/        uses:/        # uses:/' "$file" ;;
    duplicate) cat "$file" >>"$F/second"; cat "$F/second" >>"$file" ;;
    stale-after-comment)
      sed -i 's/        uses:/        # uses:/' "$file"
      printf '        uses: Kernel-Guard/bpfcompat@%s # %s\n' "$C2" "$TAG" >>"$file" ;;
  esac
  contents "$file" >"$F/consumer.json"
  run "consumer-$variant" 200
  if line PENDING "designated: consumer-canary candidate pin" && line PENDING "canary manual"; then
    ok "consumer $variant cannot establish candidate designation"
  else fail "consumer $variant falsely designated (rc=$rc)"; show; fi
done
scenario quotedgood
sed -i "s|uses: Kernel-Guard/bpfcompat@$C1|uses: 'kernel-guard/bpfcompat@$C1'|" "$F/rcc-raw.yml"
sed -i "s|uses: Kernel-Guard/bpfcompat@$C1|uses: \"Kernel-Guard/bpfcompat@$C1\"|" "$F/consumer-raw.yml"
contents "$F/rcc-raw.yml" >"$F/rcc.json"; contents "$F/consumer-raw.yml" >"$F/consumer.json"
run quotedgood 200
if line VERIFIED "designated: release-candidate-canary" && line VERIFIED "designated: consumer-canary candidate pin"; then
  ok "correct quoted pins and case-insensitive repository names are accepted"
else fail "valid quoted pins refused (rc=$rc)"; show; fi

# The workflow's plan job can start after the run crosses its hour boundary.
scenario hour19
jq --arg t "$(at 19)" '.workflow_runs[1].run_started_at = $t' "$F/cruns.json" >"$tmp/x" && mv "$tmp/x" "$F/cruns.json"
run hour19 200
if line VERIFIED "canary t-plus-24h"; then ok "hour-19 run with successful executed jobs remains observable"
else fail "hour-19 executed run refused (rc=$rc)"; show; fi
jq '.jobs = [.jobs[0], {name: "Clean install", conclusion: "skipped"}]' "$F/jobs.json" >"$tmp/x" && mv "$tmp/x" "$F/jobs.json"
run hour19 200
if line MISSING "canary t-plus-24h"; then ok "hour-19 plan-only run never becomes VERIFIED"
else fail "hour-19 plan-only run counted (rc=$rc)"; show; fi

# 8. Malformed answers abort; nothing is inferred from them.
scenario badjson; printf 'not json' >"$tmp/badjson/releases.json"
run badjson 200
if [[ $rc -eq 3 ]] && grep -q 'not JSON' "$tmp/out" && ! grep -q 'release staged' "$tmp/out"; then ok "non-JSON API body aborts"; else fail "non-JSON body (rc=$rc)"; show; fi
scenario badb64; printf '{"content": "%%%%not-base64%%%%"}' >"$tmp/badb64/policy.json"
run badb64 200
if [[ $rc -eq 3 ]] && grep -q 'cannot decode' "$tmp/out"; then ok "undecodable file contents abort"; else fail "bad base64 (rc=$rc)"; show; fi
scenario dlfail; touch "$tmp/dlfail/download-fail"
run dlfail 200
if [[ $rc -eq 3 ]] && grep -q 'cannot download SHA256SUMS' "$tmp/out" && ! grep -q '^MISSING   validator identity' "$tmp/out"; then
  ok "a failed asset download aborts instead of reporting MISSING"
else fail "download failure (rc=$rc)"; show; fi

scenario badev; printf 'garbage' >"$tmp/badev/release-candidate-evidence.json"
run badev 200
if [[ $rc -eq 3 ]] && grep -q 'release-candidate-evidence.json of .* is not JSON' "$tmp/out"; then ok "unparsable candidate evidence aborts"
else fail "bad evidence (rc=$rc)"; show; fi

# 9. Building the pin parser: no module or toolchain download, and the caller's
#    toolchain choice is kept (an older Go on PATH may switch to a cached
#    go.mod toolchain). A caller GOPRIVATE would otherwise let Go fetch a
#    toolchain directly despite GOPROXY=off.
REAL_GO="$(command -v go)"
mkdir -p "$tmp/goshim" "$tmp/gofail"
cat >"$tmp/goshim/go" <<SHIM
#!/usr/bin/env bash
printf 'GOTOOLCHAIN=%s GOPROXY=%s GONOPROXY=%s GONOSUMDB=%s GOWORK=%s ARGS=%s\n' "\${GOTOOLCHAIN-<unset>}" "\${GOPROXY-<unset>}" "\${GONOPROXY-<unset>}" "\${GONOSUMDB-<unset>}" "\${GOWORK-<unset>}" "\$*" >>"$tmp/go.log"
exec "$REAL_GO" "\$@"
SHIM
printf '#!/usr/bin/env bash\necho "go: go.mod requires go >= 9.9 (running go 1.0)" >&2\nexit 1\n' >"$tmp/gofail/go"
chmod +x "$tmp/goshim/go" "$tmp/gofail/go"
scenario gobuild; : >"$tmp/go.log"
set +e
PATH="$tmp/bin:$tmp/goshim:$PATH" FIX="$tmp/gobuild" GH_LOG="$tmp/gh.log" GOTOOLCHAIN="${GOTOOLCHAIN:-auto}" GOPRIVATE=golang.org GONOPROXY=golang.org/toolchain \
  BPFCOMPAT_PREFLIGHT_NOW=$((PUB_EPOCH + 200 * 3600)) bash "$PRE" --tag "$TAG" >"$tmp/out" 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]] && grep -q "^GOTOOLCHAIN=${GOTOOLCHAIN:-auto} GOPROXY=off GONOPROXY=none.invalid GONOSUMDB=none.invalid GOWORK=off ARGS=build -mod=vendor " "$tmp/go.log"; then
  ok "parser build keeps the caller's GOTOOLCHAIN and overrides GOPRIVATE/GONOPROXY, with GOPROXY=off, GOWORK=off and -mod=vendor"
else fail "parser build environment (rc=$rc): $(cat "$tmp/go.log")"; show; fi
scenario gofails
set +e
PATH="$tmp/bin:$tmp/gofail:$PATH" FIX="$tmp/gofails" GH_LOG="$tmp/gh.log" \
  BPFCOMPAT_PREFLIGHT_NOW=$((PUB_EPOCH + 200 * 3600)) bash "$PRE" --tag "$TAG" >"$tmp/out" 2>&1
rc=$?
set -e
if [[ $rc -eq 3 ]] && grep -q 'cannot build the vendored workflow-pin parser' "$tmp/out" && ! grep -q 'designated: consumer-canary' "$tmp/out"; then
  ok "an unusable Go aborts the report instead of reporting a pin status"
else fail "unusable Go (rc=$rc)"; show; fi

# 10. Usage.

if bash "$PRE" --tag v0.4.0 >/dev/null 2>&1; then fail "stable tag accepted"; else ok "non-RC tag refused"; fi

if [[ $failures -ne 0 ]]; then echo "[rc-preflight-test] $failures failure(s)" >&2; exit 1; fi
echo "rc-preflight_test: all checks passed"
