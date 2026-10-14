#!/usr/bin/env bash
# Re-check the candidate VM gate reports of a release-artifacts run, one report
# at a time, before a tag is promoted.
#
# release-artifacts.yml checks its infra_error, validator-sha256 and base-image
# conditions with a single `jq -e FILTER release-positive.json
# release-negative.json`. `jq -e` takes its exit status from the LAST output
# only, so each of those conditions is decided by the negative report alone and
# a failing positive report is masked. This script evaluates every condition
# against each report separately. Run it on the release-gate-evidence-<run_id>
# artifact of the tag build that is about to be promoted.
#
# usage: check-release-gate-reports.sh <release-positive.json>
#          <release-negative.json> <validator-sha256> <base-image-sha256>
#          [<release-candidate-evidence.json> <expected-tag> <expected-commit>]
#
# <validator-sha256> is the bpfcompat-validator-static-linux-amd64 entry of the
# build's SHA256SUMS. With the optional evidence file the two reports must also
# be the exact bytes the attested release-candidate evidence names, and the
# evidence must name <expected-tag> and <expected-commit> (the release being
# promoted), so another release's evidence cannot stand in for it. The tag and
# commit are mandatory whenever evidence is given.
#
# Exit status: 0 every condition holds, 1 a condition failed (all failures are
# listed), 2 usage error.
# shellcheck disable=SC2016 # jq programs read $vars bound by --arg, not by the shell
set -euo pipefail

usage() {
  echo "usage: $0 <release-positive.json> <release-negative.json> <validator-sha256> <base-image-sha256> [<release-candidate-evidence.json> <expected-tag> <expected-commit>]" >&2
  exit 2
}

[[ "$#" -eq 4 || "$#" -eq 7 ]] || usage
positive="$1"
negative="$2"
validator_sha="$3"
image_sha="$4"
evidence="${5:-}"
expected_tag="${6:-}"
expected_commit="${7:-}"

die() {
  echo "[release-gate] FAIL: $*" >&2
  exit 1
}

[[ "$validator_sha" =~ ^[0-9a-f]{64}$ ]] || die "validator sha256 must be 64 lowercase hex characters"
[[ "$image_sha" =~ ^[0-9a-f]{64}$ ]] || die "base image sha256 must be 64 lowercase hex characters"
if [[ "$#" -eq 7 ]]; then
  [[ -n "$evidence" ]] || die "evidence file path must not be empty"
  [[ "$expected_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || die "expected tag must look like vX.Y.Z or vX.Y.Z-rc.N"
  [[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || die "expected commit must be a full 40-character lowercase commit sha"
fi
for report in "$positive" "$negative"; do
  [[ -f "$report" && ! -L "$report" && -s "$report" ]] || die "missing, empty or symlinked report: ${report}"
  jq -e 'type == "object"' "$report" >/dev/null 2>&1 || die "not a JSON object: ${report}"
done

failures=0
# check <label> <report> <jq filter> [jq args...]: exactly ONE report per jq
# call, so no condition can be decided by a different file.
check() {
  local label="$1" report="$2" filter="$3"
  shift 3
  if jq -e "$@" "$filter" "$report" >/dev/null 2>&1; then
    echo "[release-gate] ok   ${label}: ${report}"
  else
    echo "[release-gate] FAIL ${label}: ${report}" >&2
    failures=$((failures + 1))
  fi
}

for report in "$positive" "$negative"; do
  check "has at least one target" "$report" \
    '(.targets | type == "array") and (.targets | length > 0)'
  check "no infra_error target" "$report" \
    '(.targets | type == "array") and (.targets | all(.status != "infra_error"))'
  check "validator sha256 is the candidate's" "$report" \
    '.validator.sha256 == $v' --arg v "$validator_sha"
  check "every target notes the pinned base image digest" "$report" \
    '(.targets | type == "array") and all(.targets[]; any(.notes[]?; type == "string" and contains($d)))' \
    --arg d "$image_sha"
done
check "positive summary is pass" "$positive" '.summary.status == "pass"'
check "every positive target passed" "$positive" \
  '(.targets | type == "array") and (.targets | all(.status == "pass"))'
check "negative summary is fail" "$negative" '.summary.status == "fail"'
check "every negative target failed with a classification code" "$negative" \
  '(.targets | type == "array") and all(.targets[]; .status == "fail" and ((.classification_code // "") | type == "string" and length > 0))'
check "negative is classified UNKNOWN" "$negative" \
  'any(.. | objects; .classification_code? == "UNKNOWN")'

if [[ -n "$evidence" ]]; then
  if [[ -f "$evidence" && ! -L "$evidence" && -s "$evidence" ]]; then
    pos_sha="$(sha256sum "$positive" | awk '{print $1}')"
    neg_sha="$(sha256sum "$negative" | awk '{print $1}')"
    check "reports are the bytes the candidate evidence names" "$evidence" \
      '.positive_report_sha256 == $p and .negative_report_sha256 == $n' \
      --arg p "$pos_sha" --arg n "$neg_sha"
    check "candidate evidence is for tag ${expected_tag}" "$evidence" \
      '.tag == $t' --arg t "$expected_tag"
    check "candidate evidence is for commit ${expected_commit}" "$evidence" \
      '.commit_sha == $c' --arg c "$expected_commit"
  else
    echo "[release-gate] FAIL missing, empty or symlinked evidence file: ${evidence}" >&2
    failures=$((failures + 1))
  fi
fi

if ((failures > 0)); then
  die "${failures} gate condition(s) failed; do not promote this build"
fi
echo "[release-gate] PASS: positive and negative reports each satisfy every gate condition"
