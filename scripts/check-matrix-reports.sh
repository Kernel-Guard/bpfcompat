#!/usr/bin/env bash
# Decide whether this run's compatibility reports may be published.
#
#   check-matrix-reports.sh <reports-dir> <matrix.yaml> <not-before-epoch> \
#       <report.json>=<artifact-path> [<report.json>=<artifact-path> ...]
#
# compatibility-matrix-publish deploys the public page even when a validation
# step failed, so an honest incomplete report (INFRA_ERROR cells, "incomplete"
# banner) replaces a stale green page. That only stays honest if what is
# published is provably THIS run's evidence. Every expected report must:
#   1. exist and parse as JSON;
#   2. declare schema_version "v0.1";
#   3. have run.started_at at or after <not-before-epoch> (the job start), so a
#      leftover file can never be republished as current;
#   4. cover exactly the profile ids the matrix requests (no more, no fewer),
#      each with the matrix's `required` flag (omitted means required);
#   5. name, in artifact.sha256, the bytes of <artifact-path> built in this run;
#   6. carry a boolean summary.complete that is false whenever any target
#      produced no answer (INFRA_ERROR, UNSUPPORTED, kernel-family mismatch),
#      because the page's "incomplete" banner is driven by it.
#
# Exit 0: all expected reports pass -> publish. Exit 1: any check failed ->
# do not publish (the previous page stays, and the workflow says why).
# Exit 2: usage error. Target verdicts are NOT judged here: an INFRA_ERROR or
# INCOMPATIBLE target is exactly what an honest page must show.
set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "Usage: $0 <reports-dir> <matrix.yaml> <not-before-epoch> <report.json>=<artifact-path>..." >&2
  exit 2
fi

reports_dir="$1"
matrix="$2"
not_before="$3"
shift 3

command -v jq >/dev/null || { echo "check-matrix-reports: jq is required" >&2; exit 2; }
[[ "$not_before" =~ ^[0-9]+$ ]] || { echo "check-matrix-reports: not-before must be a Unix epoch" >&2; exit 2; }
[[ -f "$matrix" ]] || { echo "check-matrix-reports: matrix not found: $matrix" >&2; exit 2; }

# Matrix profile ids, sorted, one per line. Plain awk over the documented
# matrix layout (`  - id: <profile>`), so no YAML library is needed.
expected_profiles="$(awk '$1 == "-" && $2 == "id:" {print $3}' "$matrix" | tr -d '"'"'" | sort)"
# (profile id, required) pairs, sorted. `required` defaults to true, exactly
# as internal/matrix RequiredBool does.
expected_required="$(awk '
  $1 == "-" && $2 == "id:" { if (id != "") print id "\t" req; id = $3; req = "true"; next }
  $1 == "required:" && id != "" { req = $2 }
  END { if (id != "") print id "\t" req }
' "$matrix" | tr -d '"'"'" | sort)"
if [[ -z "$expected_profiles" ]]; then
  echo "check-matrix-reports: no profiles found in $matrix" >&2
  exit 2
fi

fail=0
refuse() {
  echo "::error::refusing to publish: $*"
  fail=1
}

for pair in "$@"; do
  report_name="${pair%%=*}"
  artifact_path="${pair#*=}"
  if [[ -z "$report_name" || -z "$artifact_path" || "$report_name" == "$pair" ]]; then
    echo "check-matrix-reports: expected <report.json>=<artifact-path>, got '$pair'" >&2
    exit 2
  fi
  report="$reports_dir/$report_name"

  if [[ ! -f "$report" ]]; then
    refuse "$report_name was not produced by this run"
    continue
  fi
  if ! jq -e . "$report" >/dev/null 2>&1; then
    refuse "$report_name is not valid JSON"
    continue
  fi

  schema="$(jq -r '.schema_version // ""' "$report")"
  if [[ "$schema" != "v0.1" ]]; then
    refuse "$report_name has schema_version '$schema' (want v0.1)"
  fi

  started="$(jq -r '.run.started_at // ""' "$report")"
  started_epoch="$(date -u -d "$started" +%s 2>/dev/null || echo "")"
  if [[ -z "$started_epoch" ]]; then
    refuse "$report_name has no parseable run.started_at ('$started')"
  elif (( started_epoch < not_before )); then
    refuse "$report_name started at $started, before this job began; it is not this run's evidence"
  fi

  # Real v0.1 results, not just the right ids: a summary verdict, and for
  # every target a boolean `required`, a non-empty `status`, and a verdict
  # from the contract (docs/compatibility-contract.md). A report without
  # results must never become a published page.
  if ! jq -e '
      def known: . == "COMPATIBLE" or . == "INCOMPATIBLE" or . == "INFRA_ERROR" or . == "UNSUPPORTED";
      (.summary | type) == "object"
      and ((.summary.status // "") | type == "string" and length > 0)
      and ((.summary.verdict // "") | known)
      and ((.targets | type) == "array")
      and (.targets | length > 0)
      and all(.targets[];
            (.required | type) == "boolean"
            and ((.status // "") | type == "string" and length > 0)
            and ((.verdict // "") | known))
    ' "$report" >/dev/null 2>&1; then
    refuse "$report_name lacks v0.1 results (summary status/verdict, or per-target required/status/known verdict)"
  fi

  got_profiles="$(jq -r '(.targets // [])[].profile_id' "$report" | sort)"
  if [[ "$got_profiles" != "$expected_profiles" ]]; then
    refuse "$report_name covers profiles [$(echo "$got_profiles" | paste -sd, -)] but the matrix requests [$(echo "$expected_profiles" | paste -sd, -)]"
  else
    got_required="$(jq -r '(.targets // [])[] | "\(.profile_id)\t\(.required)"' "$report" | sort)"
    if [[ "$got_required" != "$expected_required" ]]; then
      refuse "$report_name marks required/optional profiles differently from the matrix; required targets are counted separately on the page"
    fi
  fi

  # Coverage: complete must be stated, and cannot claim true over a target
  # that produced no answer (docs/compatibility-contract.md, run-level roll-up).
  if ! jq -e '
      (.summary.complete | type) == "boolean"
      and (if any((.targets // [])[];
                  .verdict == "INFRA_ERROR" or .verdict == "UNSUPPORTED"
                  or (.environment.kernel_family_match? == false))
           then .summary.complete == false else true end)
    ' "$report" >/dev/null 2>&1; then
    refuse "$report_name summary.complete is missing, not boolean, or true although a target produced no answer"
  fi

  if [[ ! -f "$artifact_path" ]]; then
    refuse "artifact $artifact_path for $report_name is missing; cannot bind the report to its bytes"
  else
    want_sha="$(sha256sum "$artifact_path" | awk '{print $1}')"
    got_sha="$(jq -r '.artifact.sha256 // ""' "$report")"
    if [[ "$got_sha" != "$want_sha" ]]; then
      refuse "$report_name is about artifact sha256 $got_sha, not the $artifact_path built in this run ($want_sha)"
    fi
  fi
done

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
echo "check-matrix-reports: $# report(s) are this run's evidence for $matrix; publishable"
