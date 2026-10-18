#!/usr/bin/env bash
# Read-only inventory of a release candidate's prerequisites and evidence.
#
#   rc-preflight.sh --tag vX.Y.Z-rc.N [--commit <40-hex>] [--repo owner/repo]
#
# Prints one line per item: VERIFIED, MISSING or PENDING, the item, and the
# evidence behind the status. It only reads: GitHub REST GETs through `gh api`,
# `gh release download` of two text files (SHA256SUMS and
# release-candidate-evidence.json), and files in this checkout. It never dispatches or reruns a workflow, never writes to GitHub,
# never executes a downloaded file and never writes operator evidence.
#
# Status meanings:
#   VERIFIED  observed directly (a ref, a run, a file, a hash) and as required.
#   MISSING   observed and wrong, or its window has closed without it.
#   PENDING   not observable yet (no tag, no run, operator-held evidence, an
#             open decision). Elapsed time alone never makes an item VERIFIED.
# Canary and campaign runs count only when they started after publication and
# after main was designated to this candidate; a canary run counts only if a
# job after its planning job succeeded. A rollback drill run stays PENDING:
# which candidate it drilled is not visible here. Run-level items say only
# that a run of the right kind exists; binding its evidence to the candidate is the job of
# scripts/production-readiness-report.sh, which this does not replace. Canary
# windows (20-30h, 68-78h after publication) are judged from each run's start
# time as a proxy for its plan job, which enforces the exact window itself.
#
# Exit: 0 no MISSING, 1 at least one MISSING, 2 usage, 3 a lookup, download,
# parse or decode failed (the report is then incomplete and nothing is inferred
# from the failure).
# Test hook: BPFCOMPAT_PREFLIGHT_NOW=<epoch> fixes "now".
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo="Kernel-Guard/bpfcompat" tag="" want_commit=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag="${2:-}"; shift 2 ;;
    --commit) want_commit="${2:-}"; shift 2 ;;
    --repo) repo="${2:-}"; shift 2 ;;
    *) echo "usage: $0 --tag vX.Y.Z-rc.N [--commit <sha>] [--repo owner/repo]" >&2; exit 2 ;;
  esac
done
[[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)-rc\.[1-9][0-9]*$ ]] || { echo "rc-preflight: --tag must be vX.Y.Z-rc.N" >&2; exit 2; }
[[ -z "$want_commit" || "$want_commit" =~ ^[0-9a-f]{40}$ ]] || { echo "rc-preflight: --commit must be a full SHA" >&2; exit 2; }
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "rc-preflight: invalid --repo" >&2; exit 2; }
for t in gh jq git; do command -v "$t" >/dev/null || { echo "rc-preflight: $t is required" >&2; exit 2; }; done
version="${tag#v}"
now="${BPFCOMPAT_PREFLIGHT_NOW:-$(date -u +%s)}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
missing=0
say() { # <status> <item> <detail>
  printf '%-8s  %-44s  %s\n' "$1" "$2" "$3"
  [[ "$1" != MISSING ]] || missing=1
}
# fetch <path> <file>: GET JSON into <file>. Returns 0, or 4 for HTTP 404; any
# other failure, or a body that is not JSON, aborts the whole report (exit 3).
# Runs in the main shell, never in $(...), so the abort cannot be mistaken for
# "not found".
abort() { echo "rc-preflight: $*; report incomplete" >&2; exit 3; }
fetch() {
  if gh api "$1" >"$2" 2>"$tmp/err"; then
    jq -e . "$2" >/dev/null 2>&1 || abort "GET $1 returned a body that is not JSON"
    return 0
  fi
  if grep -q 'HTTP 404' "$tmp/err"; then return 4; fi
  abort "lookup failed: GET $1: $(head -1 "$tmp/err")"
}
# need <path> <file>: like fetch, but a 404 is a lookup failure too.
need() { fetch "$1" "$2" || abort "lookup failed: GET $1: not found"; }
# decode <contents.json> <out>: base64 file contents from the contents API.
decode() { jq -r .content "$1" | base64 -d >"$2" 2>/dev/null && [[ -s "$2" ]] || abort "cannot decode file contents ($1)"; }
# asset <name> <dir>: download one release asset (text only, never executed).
asset() { gh release download "$tag" --repo "$repo" --pattern "$1" --dir "$2" >/dev/null 2>"$tmp/err" || abort "cannot download $1 from the $tag release: $(head -1 "$tmp/err")"; }
epoch() { date -u -d "$1" +%s; }

echo "rc-preflight: ${repo} ${tag} at $(date -u -d "@$now" +%Y-%m-%dT%H:%M:%SZ) (read-only)"

# ------------------------------------------------------------ source metadata
rv="$(awk -F': ' '$1 == "release_version" { print $2 }' "$ROOT/release.yaml")"
rc="$(awk -F': ' '$1 == "release_channel" { print $2 }' "$ROOT/release.yaml")"
if [[ "$rv" == "$version" && "$rc" == prerelease ]]; then say VERIFIED "release.yaml names the candidate" "release_version=$rv release_channel=$rc"
else say MISSING "release.yaml names the candidate" "release_version=$rv release_channel=$rc (checkout $(git -C "$ROOT" rev-parse --short HEAD))"; fi
if grep -Fq "## [${version}]" "$ROOT/CHANGELOG.md"; then say VERIFIED "CHANGELOG has the candidate heading" "## [${version}]"
else say MISSING "CHANGELOG has the candidate heading" "no '## [${version}]' heading"; fi
expected_validator="$(awk -F= '$1 == "reproduces" { split($2, a, " "); print a[2] }' "$ROOT/validator/build-inputs.lock")"

policy="$ROOT/distribution/policy.json"
if ! bash "$ROOT/scripts/check-distribution-policy.sh" "$policy" >/dev/null 2>&1; then
  say MISSING "distribution policy is well-formed" "scripts/check-distribution-policy.sh refused $policy"
else
  open="$(jq -r '[.blocks_stable[] as $k | select(.decisions[$k].status != "decided") | $k] | join(",")' "$policy")"
  pre="$(jq -r '.decisions.prerelease_with_open_decisions | "\(.status) \(.value)"' "$policy")"
  case "$pre" in
    "decided true") say VERIFIED "recorded: prerelease with open decisions" "operator recorded true (a policy value, not a legal finding)" ;;
    "decided false")
      if [[ -n "$open" ]]; then say MISSING "recorded: prerelease with open decisions" "recorded false while open: $open"
      else say VERIFIED "recorded: prerelease with open decisions" "recorded false; no stable-blocking decision is open"; fi ;;
    *) say PENDING "recorded: prerelease with open decisions" "undecided (Q17); open stable-blocking decisions: ${open:-none}" ;;
  esac
  if [[ -z "$open" ]]; then say VERIFIED "recorded: stable-blocking decisions" "all recorded in distribution/policy.json"
  else say PENDING "recorded: stable-blocking decisions" "undecided: $open (needed before a stable tag, not before this RC)"; fi
fi

# ------------------------------------------------------------ tag
if ! fetch "repos/${repo}/git/ref/tags/${tag}" "$tmp/ref.json"; then
  say PENDING "tag exists" "$tag not created"
  for item in "tag build (release-artifacts)" "release staged with required assets" "SHA256SUMS lists required assets" \
              "validator identity" "optional assets match tagged policy" "RC published as prerelease"; do
    say PENDING "$item" "requires $tag"
  done
  for item in "designated: campaign-candidate.json" "designated: consumer-canary candidate pin" "designated: release-candidate-canary" \
              "canary manual" "canary t-plus-24h" "canary t-plus-72h" "scheduled campaigns (4)" "rollback drill run"; do
    say PENDING "$item" "requires a published $tag"
  done
  say PENDING "Falco expanded entry" "operator-held; bound by production-readiness-report.sh"
  say PENDING "fail-closed promotion incident note" "operator-held; bound by production-readiness-report.sh"
  say PENDING "operator promotion confirmation" "operator-held; never written by tooling"
  exit "$missing"
fi
obj_type="$(jq -r .object.type "$tmp/ref.json")" obj_sha="$(jq -r .object.sha "$tmp/ref.json")"
commit="$obj_sha"
if [[ "$obj_type" == tag ]]; then need "repos/${repo}/git/tags/${obj_sha}" "$tmp/tagobj.json"; commit="$(jq -r .object.sha "$tmp/tagobj.json")"; fi
if [[ -z "$want_commit" ]]; then say VERIFIED "tag exists" "$tag -> $commit (no --commit to compare)"
elif [[ "$commit" == "$want_commit" ]]; then say VERIFIED "tag exists" "$tag -> $commit (as approved)"
else say MISSING "tag exists" "$tag -> $commit, approved commit is $want_commit"; fi

# ------------------------------------------------------------ tag build
need "repos/${repo}/actions/workflows/release-artifacts.yml/runs?event=push&head_sha=${commit}&per_page=50" "$tmp/runs.json"
run="$(jq -c --arg t "$tag" '[.workflow_runs[] | select(.head_branch == $t)] | sort_by(.run_attempt) | last // empty' "$tmp/runs.json")"
if [[ -z "$run" ]]; then say PENDING "tag build (release-artifacts)" "no push run for $tag at $commit yet"
else
  rid="$(jq -r .id <<<"$run")" ra="$(jq -r .run_attempt <<<"$run")" st="$(jq -r .status <<<"$run")" co="$(jq -r .conclusion <<<"$run")"
  if [[ "$st" != completed ]]; then say PENDING "tag build (release-artifacts)" "run $rid attempt $ra is $st"
  elif [[ "$co" == success ]]; then say VERIFIED "tag build (release-artifacts)" "run $rid attempt $ra success"
  else say MISSING "tag build (release-artifacts)" "run $rid attempt $ra concluded $co"; fi
fi

# ------------------------------------------------------------ release
need "repos/${repo}/releases?per_page=100" "$tmp/releases.json"
rel="$(jq -c --arg t "$tag" '[.[] | select(.tag_name == $t)] | first // empty' "$tmp/releases.json")"
required=(bpfcompat-linux-amd64 bpfcompat-linux-arm64 bpfcompat-validator-static-linux-amd64
  bpfcompat-third-party-licenses.tar.gz bpfcompat-validator-relink-kit-linux-amd64.tar.gz validator-build-inputs.json)
signed=(SHA256SUMS SHA256SUMS.sig SHA256SUMS.crt bpfcompat.sbom.cdx.json bpfcompat.sbom.cdx.sig bpfcompat.sbom.cdx.crt release-candidate-evidence.json)
published_at="" digest=""
if [[ -z "$rel" ]]; then
  for item in "release staged with required assets" "SHA256SUMS lists required assets" "validator identity" \
              "optional assets match tagged policy" "RC published as prerelease"; do say PENDING "$item" "no release for $tag yet"; done
else
  names="$(jq -r '.assets[].name' <<<"$rel")"
  absent=()
  for a in "${required[@]}" "${signed[@]}"; do grep -qxF "$a" <<<"$names" || absent+=("$a"); done
  if [[ ${#absent[@]} -eq 0 ]]; then say VERIFIED "release staged with required assets" "$(jq '.assets | length' <<<"$rel") assets"
  else say MISSING "release staged with required assets" "absent: ${absent[*]}"; fi
  if grep -qxF SHA256SUMS <<<"$names"; then
    asset SHA256SUMS "$tmp/sums"
    sums="$tmp/sums/SHA256SUMS"
    unlisted=()
    for a in "${required[@]}"; do awk -v f="$a" '$2 == f && $1 ~ /^[0-9a-f]{64}$/ { n++ } END { exit n != 1 }' "$sums" || unlisted+=("$a"); done
    if [[ ${#unlisted[@]} -eq 0 ]]; then say VERIFIED "SHA256SUMS lists required assets" "${#required[@]} required entries, $(grep -c . "$sums") lines"
    else say MISSING "SHA256SUMS lists required assets" "missing or duplicated: ${unlisted[*]}"; fi
    vs="$(awk '$2 == "bpfcompat-validator-static-linux-amd64" { print $1 }' "$sums")"
    if [[ -n "$vs" && "$vs" == "$expected_validator" ]]; then say VERIFIED "validator identity" "$vs (validator/build-inputs.lock reproduces=)"
    else say MISSING "validator identity" "SHA256SUMS ${vs:-none}, lock expects $expected_validator"; fi
    if fetch "repos/${repo}/contents/distribution/policy.json?ref=${tag}" "$tmp/policy-contents.json"; then
      decode "$tmp/policy-contents.json" "$tmp/policy.json"
      bad=""
      for pair in "ship_link_inputs_asset:bpfcompat-validator-link-inputs-linux-amd64.tar.gz" "ship_native_sources_asset:bpfcompat-validator-native-sources.tar"; do
        d="${pair%%:*}" f="${pair#*:}"
        ship="$(bash "$ROOT/scripts/check-distribution-policy.sh" --ship "$d" "$tmp/policy.json" 2>/dev/null || echo error)"
        listed=false; awk -v f="$f" '$2 == f { n++ } END { exit !n }' "$sums" && listed=true
        [[ "$ship" == "$listed" ]] || bad+="$d=$ship but $f listed=$listed; "
      done
      if [[ -z "$bad" ]]; then say VERIFIED "optional assets match tagged policy" "policy at $tag agrees with SHA256SUMS"
      else say MISSING "optional assets match tagged policy" "$bad"; fi
    else
      say MISSING "optional assets match tagged policy" "distribution/policy.json absent at $tag"
    fi
  else
    for item in "SHA256SUMS lists required assets" "validator identity" "optional assets match tagged policy"; do
      say MISSING "$item" "the $tag release has no SHA256SUMS asset"
    done
  fi
  draft="$(jq -r .draft <<<"$rel")" prerel="$(jq -r .prerelease <<<"$rel")"
  if [[ "$draft" == true ]]; then say PENDING "RC published as prerelease" "draft (promotion pending)"
  elif [[ "$prerel" == true ]]; then
    published_at="$(jq -r .published_at <<<"$rel")"
    say VERIFIED "RC published as prerelease" "published $published_at"
    digest=""
    if grep -qxF release-candidate-evidence.json <<<"$names"; then
      asset release-candidate-evidence.json "$tmp/ev"
      digest="$(jq -r '.image // empty' "$tmp/ev/release-candidate-evidence.json" 2>/dev/null | sed -n 's/.*@\(sha256:[0-9a-f]\{64\}\)$/\1/p')"
    fi
  else say MISSING "RC published as prerelease" "published but not marked prerelease"; fi
fi

# ------------------------------------------------------------ designation and qualification
# Runs only count when they started after publication AND after main was
# designated to this candidate; before that, the workflows still named the
# previous candidate.
rcnum="${tag##*-rc.}"
if [[ -z "$published_at" ]]; then
  for item in "designated: campaign-candidate.json" "designated: consumer-canary candidate pin" "designated: release-candidate-canary" \
              "canary manual" "canary t-plus-24h" "canary t-plus-72h" "scheduled campaigns (4)" "rollback drill run"; do
    say PENDING "$item" "requires a published $tag"
  done
else
  main_file() { need "repos/${repo}/contents/$1?ref=main" "$tmp/contents.json"; decode "$tmp/contents.json" "$2"; }
  # last_change <path>: epoch at which the newest change to <path> landed on
  # main: the merge time of the pull request that brought that commit in, or
  # the commit's own date when it was pushed directly.
  last_change() {
    need "repos/${repo}/commits?sha=main&path=$1&per_page=1" "$tmp/commits.json"
    local sha d
    sha="$(jq -r '.[0].sha // empty' "$tmp/commits.json")"
    [[ -n "$sha" ]] || abort "no main commit touches $1"
    need "repos/${repo}/commits/${sha}/pulls" "$tmp/pulls.json"
    d="$(jq -r '[.[] | select(.merged_at != null and .base.ref == "main") | .merged_at] | max // empty' "$tmp/pulls.json")"
    [[ -n "$d" ]] || d="$(jq -r '.[0].commit.committer.date' "$tmp/commits.json")"
    epoch "$d"
  }
  ok_designations=0
  main_file .github/campaign-candidate.json "$tmp/cc.json"
  jq -e . "$tmp/cc.json" >/dev/null 2>&1 || abort "campaign-candidate.json on main is not JSON"
  if [[ "$(jq -r .tag "$tmp/cc.json")" == "$tag" && "$(jq -r .commit_sha "$tmp/cc.json")" == "$commit" ]]; then
    say VERIFIED "designated: campaign-candidate.json" "main binds $tag $commit"; ok_designations=$((ok_designations + 1))
  else say PENDING "designated: campaign-candidate.json" "main binds $(jq -r .tag "$tmp/cc.json") (retarget after verification)"; fi
  main_file .github/workflows/consumer-canary.yml "$tmp/consumer.yml"
  pin="$(grep -A1 'bpfcompat-pin: candidate' "$tmp/consumer.yml" | tail -1)"
  if [[ "$pin" == *"@${commit} # ${tag}"* ]]; then say VERIFIED "designated: consumer-canary candidate pin" "pinned to $commit"; ok_designations=$((ok_designations + 1))
  else say PENDING "designated: consumer-canary candidate pin" "main pins:${pin##*@}"; fi
  main_file .github/workflows/release-candidate-canary.yml "$tmp/rcc.yml"
  envv() { sed -nE "s/^ *$1: *\"?([^\"]*)\"?\$/\\1/p" "$tmp/rcc.yml" | head -1; }
  problems=""
  [[ "$(envv CANDIDATE_TAG)" == "$tag" ]] || problems+="CANDIDATE_TAG=$(envv CANDIDATE_TAG) "
  [[ "$(envv CANDIDATE_COMMIT)" == "$commit" ]] || problems+="CANDIDATE_COMMIT=$(envv CANDIDATE_COMMIT) "
  [[ "$(envv CANDIDATE_PUBLISHED_AT)" == "$published_at" ]] || problems+="CANDIDATE_PUBLISHED_AT=$(envv CANDIDATE_PUBLISHED_AT) "
  if [[ -z "$digest" ]]; then problems+="(release-candidate-evidence.json names no image digest) "
  elif [[ "$(envv CANDIDATE_DIGEST)" != "$digest" ]]; then problems+="CANDIDATE_DIGEST=$(envv CANDIDATE_DIGEST) "; fi
  grep -q "rc${rcnum}-canary-component-" "$tmp/rcc.yml" || problems+="no rc${rcnum}-canary-component names "
  if grep -Eo 'rc[0-9]+-canary-component-|reports/rc[0-9]+-action' "$tmp/rcc.yml" | grep -vqE "^(rc${rcnum}-|reports/rc${rcnum}-)"; then
    problems+="other candidates' artifact/report names remain "
  fi
  if [[ -z "$problems" ]]; then say VERIFIED "designated: release-candidate-canary" "tag, commit, digest $digest, published $published_at, rc${rcnum} names"; ok_designations=$((ok_designations + 1))
  else say PENDING "designated: release-candidate-canary" "main still differs: $problems"; fi

  pub="$(epoch "$published_at")"
  if [[ "$ok_designations" -ne 3 ]]; then
    for item in "canary manual" "canary t-plus-24h" "canary t-plus-72h" "scheduled campaigns (4)"; do
      say PENDING "$item" "requires main to be designated to $tag"
    done
  else
    since="$pub"
    for f in .github/campaign-candidate.json .github/workflows/consumer-canary.yml .github/workflows/release-candidate-canary.yml; do
      c="$(last_change "$f")"; (( c > since )) && since="$c"
    done
    since_iso="$(date -u -d "@$since" +%Y-%m-%dT%H:%M:%SZ)"
    need "repos/${repo}/actions/workflows/release-candidate-canary.yml/runs?created=%3E%3D${since_iso}&per_page=100" "$tmp/cruns.json"
    # A canary run counts only if a job after the planning job succeeded:
    # that proves the plan job accepted its window (out-of-window runs skip
    # every later job and still conclude "success").
    executed() {
      need "repos/${repo}/actions/runs/$1/jobs?per_page=100" "$tmp/jobs-$1.json"
      jq -e '[.jobs[] | select(.name != "Select RC observation window" and .conclusion == "success")] | length > 0' "$tmp/jobs-$1.json" >/dev/null
    }
    canary() { # <milestone> <event> <min-h> <max-h>
      local id st h hit=""
      while IFS=$'\t' read -r id st; do
        [[ -n "$id" ]] || continue
        h=$(( ($(epoch "$st") - pub) / 3600 ))
        (( h >= $3 && h <= $4 + 1 )) || continue
        if executed "$id"; then hit="$id started $st"; break; fi
      done < <(jq -r --arg e "$2" '.workflow_runs[] | select(.event == $e and .status == "completed" and .conclusion == "success") | "\(.id)\t\(.run_started_at)"' "$tmp/cruns.json")
      if [[ -n "$hit" ]]; then say VERIFIED "canary $1" "$2 run $hit, past its plan job (candidate binding: readiness report)"
      elif (( now < pub + ($4 + 2) * 3600 )); then say PENDING "canary $1" "window ${3}-${4}h after publication open or not reached"
      else say MISSING "canary $1" "no executed $2 run ${3}-${4}h after publication"; fi
    }
    canary manual workflow_dispatch 0 100000
    canary t-plus-24h schedule 20 30
    canary t-plus-72h schedule 68 78
    need "repos/${repo}/actions/workflows/latest-kernel-compatibility.yml/runs?event=schedule&created=%3E%3D${since_iso}&per_page=100" "$tmp/camp.json"
    n="$(jq '[.workflow_runs[] | select(.status == "completed" and .conclusion == "success")] | length' "$tmp/camp.json")"
    if [[ "$n" -ge 4 ]]; then say VERIFIED "scheduled campaigns (4)" "$n successful scheduled runs since designation (spacing and binding: readiness report)"
    else say PENDING "scheduled campaigns (4)" "$n of 4 successful scheduled runs since designation ($since_iso)"; fi
  fi
  need "repos/${repo}/actions/workflows/rollback-drill.yml/runs?created=%3E%3D${published_at}&per_page=50" "$tmp/drill.json"
  drill="$(jq -r '[.workflow_runs[] | select(.status == "completed" and .conclusion == "success") | .id] | first // empty' "$tmp/drill.json")"
  if [[ -n "$drill" ]]; then say PENDING "rollback drill run" "run $drill succeeded since publication; which candidate it drilled is checked only by the readiness report"
  else say PENDING "rollback drill run" "no successful run since publication"; fi
fi
say PENDING "Falco expanded entry" "operator-held; bound by production-readiness-report.sh"
say PENDING "fail-closed promotion incident note" "operator-held; bound by production-readiness-report.sh"
say PENDING "operator promotion confirmation" "operator-held; never written by tooling"
exit "$missing"
