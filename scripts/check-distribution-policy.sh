#!/usr/bin/env bash
# Validate distribution/policy.json, the recorded distribution decisions.
#
#   check-distribution-policy.sh [<policy>]                    shape check
#   check-distribution-policy.sh --require-decided [<policy>]  also refuse any
#       decision listed in blocks_stable that is still undecided (stable builds)
#   check-distribution-policy.sh --ship <decision> [<policy>]  print "true" or
#       "false": whether an optional asset is shipped. Undecided prints false;
#       an undecided decision never selects an answer, it only withholds the
#       optional asset.
#
# Every decision has status "undecided" with value null, or status "decided"
# with a value from its allowed list. Exit 0 ok, 1 refused, 2 usage/shape.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="check"
decision=""
case "${1:-}" in
  --require-decided) mode="require"; shift ;;
  --ship) mode="ship"; decision="${2:-}"; shift 2 || { echo "usage: $0 --ship <decision> [<policy>]" >&2; exit 2; } ;;
  -*) echo "usage: $0 [--require-decided | --ship <decision>] [<policy>]" >&2; exit 2 ;;
esac
policy="${1:-$ROOT/distribution/policy.json}"
[[ -f "$policy" ]] || { echo "distribution-policy: $policy not found" >&2; exit 2; }
command -v jq >/dev/null || { echo "distribution-policy: jq is required" >&2; exit 2; }

problems="$(jq -r '
  if .schema_version != "v1" then "schema_version must be v1"
  elif (.decisions | type) != "object" or (.decisions | length) == 0 then "decisions must be a non-empty object"
  else
    (.decisions | to_entries[] |
      .key as $k | .value as $d |
      if ($d.allowed | type) != "array" or ($d.allowed | length) < 2 then "\($k): allowed needs at least two values"
      elif ($d.questions | type) != "array" or ($d.questions | length) == 0 then "\($k): questions must name at least one question"
      elif $d.status == "undecided" then (if $d.value != null then "\($k): undecided must have value null" else empty end)
      elif $d.status == "decided" then (if ([$d.allowed[] | select(. == $d.value)] | length) != 1 then "\($k): decided value is not in allowed" else empty end)
      else "\($k): status must be undecided or decided" end),
    (.blocks_stable // [] | .[] | select(type != "string") | "blocks_stable entries must be strings"),
    ((.blocks_stable // []) - (.decisions | keys) | .[] | "blocks_stable names unknown decision \(.)")
  end' "$policy")" || { echo "distribution-policy: $policy is not valid JSON" >&2; exit 2; }
if [[ -n "$problems" ]]; then
  printf 'distribution-policy: %s\n' "$problems" >&2
  exit 2
fi

case "$mode" in
  check)
    echo "distribution-policy: $policy is well-formed ($(jq '[.decisions[] | select(.status == "undecided")] | length' "$policy") undecided)"
    ;;
  require)
    open="$(jq -r '.blocks_stable[] as $k | select(.decisions[$k].status != "decided") | $k' "$policy")"
    if [[ -n "$open" ]]; then
      while IFS= read -r k; do
        echo "::error::distribution decision '$k' is undecided ($(jq -r --arg k "$k" '.decisions[$k].questions | join(", ")' "$policy")); a stable release needs it recorded in distribution/policy.json" >&2
      done <<<"$open"
      exit 1
    fi
    echo "distribution-policy: every stable-blocking decision is recorded"
    ;;
  ship)
    jq -e --arg k "$decision" '.decisions | has($k)' "$policy" >/dev/null ||
      { echo "distribution-policy: unknown decision '$decision'" >&2; exit 2; }
    jq -e --arg k "$decision" '.decisions[$k].allowed == [true, false]' "$policy" >/dev/null ||
      { echo "distribution-policy: '$decision' is not a ship/omit decision" >&2; exit 2; }
    jq -r --arg k "$decision" 'if .decisions[$k].status == "decided" and .decisions[$k].value == true then "true" else "false" end' "$policy"
    ;;
esac
