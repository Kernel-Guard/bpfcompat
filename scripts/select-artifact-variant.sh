#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <report.json> <report.json> [more...]" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

best_report=""
best_artifact=""
best_required_fail=999999
best_required_pass=-1
best_total_fail=999999

for report in "$@"; do
  if [[ ! -f "$report" ]]; then
    echo "missing report: $report" >&2
    exit 1
  fi

  artifact_path="$(jq -r '.artifact.path // ""' "$report")"
  if [[ -z "$artifact_path" ]]; then
    artifact_path="<unknown>"
  fi

  required_fail="$(jq '[.targets[] | select((.required == true) and (.status != "pass"))] | length' "$report")"
  required_pass="$(jq '[.targets[] | select((.required == true) and (.status == "pass"))] | length' "$report")"
  total_fail="$(jq '[.targets[] | select(.status != "pass")] | length' "$report")"
  summary_status="$(jq -r '.summary.status // "unknown"' "$report")"

  echo "[selector] candidate report=${report} status=${summary_status} required_pass=${required_pass} required_fail=${required_fail} total_fail=${total_fail} artifact=${artifact_path}"

  better=0
  if (( required_fail < best_required_fail )); then
    better=1
  elif (( required_fail == best_required_fail )) && (( required_pass > best_required_pass )); then
    better=1
  elif (( required_fail == best_required_fail )) && (( required_pass == best_required_pass )) && (( total_fail < best_total_fail )); then
    better=1
  fi

  if (( better == 1 )); then
    best_report="$report"
    best_artifact="$artifact_path"
    best_required_fail="$required_fail"
    best_required_pass="$required_pass"
    best_total_fail="$total_fail"
  fi
done

if [[ -z "$best_report" ]]; then
  echo "no candidate selected" >&2
  exit 1
fi

echo "[selector] selected report=${best_report} artifact=${best_artifact} required_pass=${best_required_pass} required_fail=${best_required_fail} total_fail=${best_total_fail}"
