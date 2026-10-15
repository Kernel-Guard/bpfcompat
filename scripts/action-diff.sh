#!/usr/bin/env bash
# GitHub Action diff mode: compare a baseline and a candidate bpfcompat report
# with `bpfcompat diff` and apply the caller's CI policy (issue #141).
#
# The comparison itself is entirely `bpfcompat diff`; this script only
#   - resolves and checks the two report paths (and optional pinned SHA-256s),
#   - runs the diff into fresh output files (a stale diff is never reused),
#   - checks that what came back is a real diff consistent with the exit code,
#   - applies the policy to the diff's own summary counts, and
#   - writes the step summary and step outputs.
#
# Policy is applied to the summary counts rather than to the exit code: the
# CLI exits 2 when a required regression and an inconclusive cell coexist, and
# `fail-on-regression: false` must not thereby waive `fail-on-incomplete`.
#
# Inputs (environment): INPUT_BASELINE_REPORT, INPUT_CANDIDATE_REPORT,
# INPUT_BASELINE_REPORT_SHA256, INPUT_CANDIDATE_REPORT_SHA256,
# INPUT_FAIL_ON_REGRESSION, INPUT_FAIL_ON_INCOMPLETE, INPUT_DIFF_OUT,
# INPUT_DIFF_MARKDOWN, INPUT_REQUIRE_GATE, INPUT_ARTIFACT, INPUT_COMMAND, INPUT_SUITE,
# BPFCOMPAT_BIN, GITHUB_WORKSPACE, RUNNER_TEMP, GITHUB_OUTPUT,
# GITHUB_STEP_SUMMARY.
#
# Exit status: 0 when the policy passed, 1 when it failed or the comparison
# could not be performed. Step output `result` is NO_NEW_REGRESSIONS,
# NEW_REGRESSIONS, INCONCLUSIVE, or INVALID_INPUT.
set -euo pipefail

readonly DIFF_SCHEMA="bpfcompat.regression-diff.v0.1"

set_output() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
  fi
}

summary() {
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    cat >>"$GITHUB_STEP_SUMMARY"
  else
    cat >/dev/null
  fi
}

# invalid <message>: the comparison could not be performed. This is never a
# statement about the candidate, and no policy setting turns it into a pass.
invalid() {
  local msg="$1"
  # stderr: invalid is often reached inside $(...), which captures stdout.
  echo "::error title=bpfcompat diff::$msg" >&2
  set_output result INVALID_INPUT
  summary <<EOF

## bpfcompat regression diff

**Result: \`INVALID_INPUT\`** — the comparison could not be performed, so nothing is claimed about the candidate.

$msg
EOF
  exit 1
}

bool_input() { # <name> <value> <default>
  local v="${2:-$3}"
  case "$v" in
    true | false) printf '%s' "$v" ;;
    # The value is not echoed: it is caller-controlled, and a newline in it
    # could start a second workflow command.
    *) invalid "input $1 must be true or false" ;;
  esac
}

workspace="${GITHUB_WORKSPACE:-$PWD}"
workspace_real="$(realpath -e -- "$workspace")" || invalid "workspace not found: $workspace"
roots=("$workspace_real")
if [[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]]; then
  roots+=("$(realpath -e -- "$RUNNER_TEMP")")
fi

under_root() { # <real path>
  local p="$1" r
  for r in "${roots[@]}"; do
    [[ "$p" == "$r" || "$p" == "$r"/* ]] && return 0
  done
  return 1
}

absolute() { # <input>
  if [[ "$1" = /* ]]; then printf '%s' "$1"; else printf '%s/%s' "$workspace" "$1"; fi
}

# A report must be an existing regular file whose real location (symlinks
# followed) is inside the workspace or the runner temp directory.
resolve_report() { # <input name> <value>
  local name="$1" value="$2" real
  [[ -n "$value" ]] || invalid "$name is required in diff mode (set both baseline-report and candidate-report)"
  real="$(realpath -e -- "$(absolute "$value")" 2>/dev/null)" || invalid "$name not found: $value"
  under_root "$real" || invalid "$name resolves outside the workspace and runner temp directory: $value"
  [[ -f "$real" ]] || invalid "$name is not a regular file: $value"
  printf '%s' "$real"
}

# An output path must stay inside the workspace or runner temp directory.
resolve_output() { # <input name> <value>
  local name="$1" value="$2" real
  # GITHUB_OUTPUT is line-based: a newline in a path would add lines to it.
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || invalid "$name must not contain a newline"
  real="$(realpath -m -- "$(absolute "$value")")"
  under_root "$real" || invalid "$name resolves outside the workspace and runner temp directory: $value"
  [[ ! -d "$real" ]] || invalid "$name is a directory: $value"
  printf '%s' "$real"
}

check_sha256() { # <input name> <file> <expected>
  local name="$1" file="$2" want="$3" got
  [[ -n "$want" ]] || return 0
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || invalid "$name must be 64 lowercase hex characters"
  got="$(sha256sum -- "$file" | awk '{print $1}')"
  [[ "$got" == "$want" ]] || invalid "$name mismatch for $file: expected $want, got $got"
}

if [[ -n "${INPUT_ARTIFACT:-}${INPUT_COMMAND:-}${INPUT_SUITE:-}" ]]; then
  invalid "baseline-report/candidate-report select diff mode and cannot be combined with artifact, command, or suite; compare reports in a separate step"
fi

fail_on_regression="$(bool_input fail-on-regression "${INPUT_FAIL_ON_REGRESSION:-}" true)"
fail_on_incomplete="$(bool_input fail-on-incomplete "${INPUT_FAIL_ON_INCOMPLETE:-}" true)"
require_gate="$(bool_input require-gate "${INPUT_REQUIRE_GATE:-}" false)"

baseline="$(resolve_report baseline-report "${INPUT_BASELINE_REPORT:-}")"
candidate="$(resolve_report candidate-report "${INPUT_CANDIDATE_REPORT:-}")"
check_sha256 baseline-report-sha256 "$baseline" "${INPUT_BASELINE_REPORT_SHA256:-}"
check_sha256 candidate-report-sha256 "$candidate" "${INPUT_CANDIDATE_REPORT_SHA256:-}"

diff_json="$(resolve_output diff-out "${INPUT_DIFF_OUT:-reports/bpfcompat-diff.json}")"
diff_md="$(resolve_output diff-markdown "${INPUT_DIFF_MARKDOWN:-reports/bpfcompat-diff.md}")"
[[ "$diff_json" != "$diff_md" ]] || invalid "diff-out and diff-markdown must be different files"
# Before anything is removed: an output that is one of the inputs (directly
# or through a link) would destroy it, and the baseline is often the only copy.
for o in "$diff_json" "$diff_md"; do
  for i in "$baseline" "$candidate"; do
    if [[ "$o" == "$i" || "$o" -ef "$i" ]]; then
      invalid "output $o is the same file as input $i; it would be destroyed"
    fi
  done
done

bin="${BPFCOMPAT_BIN:-}"
[[ -n "$bin" && -x "$bin" ]] || invalid "bpfcompat binary not found or not executable: ${bin:-<unset>}"

# Never let a diff left by an earlier step stand in for this comparison.
rm -f -- "$diff_json" "$diff_md"
mkdir -p -- "$(dirname -- "$diff_json")" "$(dirname -- "$diff_md")"

echo "Running: $bin diff --baseline $baseline --candidate $candidate --out $diff_json --markdown $diff_md"
set +e
"$bin" diff --baseline "$baseline" --candidate "$candidate" --out "$diff_json" --markdown "$diff_md"
status=$?
set -e

case "$status" in
  0) want_result=NO_NEW_REGRESSIONS ;;
  1) want_result=INCONCLUSIVE ;;
  2) want_result=NEW_REGRESSIONS ;;
  *) invalid "bpfcompat diff exited $status, outside its documented 0/1/2 contract" ;;
esac
if [[ ! -s "$diff_json" ]]; then
  invalid "bpfcompat diff could not compare the reports (exit $status, no diff written); see the step log for the reason"
fi
if ! jq -e --arg s "$DIFF_SCHEMA" --arg r "$want_result" '
    .schema_version == $s and .summary.result == $r
    and (.summary.new_required_regressions | type) == "number"
    and (.summary.inconclusive_required | type) == "number"
    and (.summary.coverage_removed_required | type) == "number"' "$diff_json" >/dev/null 2>&1; then
  invalid "bpfcompat diff output is not a $DIFF_SCHEMA document consistent with its exit code $status"
fi

result="$(jq -r .summary.result "$diff_json")"
regressions="$(jq -r .summary.new_required_regressions "$diff_json")"
inconclusive="$(jq -r .summary.inconclusive_required "$diff_json")"
coverage_removed="$(jq -r .summary.coverage_removed_required "$diff_json")"
incomplete=$((inconclusive + coverage_removed))
# summary.gate is "enforced" only when at least one profile is required in
# both reports; baseline_gate/candidate_gate are each report's own gate. An
# absent field (an older binary) is no gate evidence, never a gate.
gate="$(jq -r '.summary.gate // ""' "$diff_json")"
baseline_gate="$(jq -r '.summary.baseline_gate // ""' "$diff_json")"
candidate_gate="$(jq -r '.summary.candidate_gate // ""' "$diff_json")"

policy_failed=false
reasons=()
if [[ "$fail_on_regression" == true && "$regressions" -gt 0 ]]; then
  policy_failed=true
  reasons+=("$regressions new required regression(s) and fail-on-regression is true")
fi
if [[ "$fail_on_incomplete" == true && "$incomplete" -gt 0 ]]; then
  policy_failed=true
  reasons+=("$incomplete required comparison(s) could not be established and fail-on-incomplete is true")
fi
if [[ "$require_gate" == true ]] && [[ "$gate" != enforced || "$baseline_gate" != enforced || "$candidate_gate" != enforced ]]; then
  policy_failed=true
  reasons+=("no gated comparison (gate '${gate:-absent}', baseline '${baseline_gate:-absent}', candidate '${candidate_gate:-absent}'): diagnostic diff, not a gate, and require-gate is true")
fi

set_output result "$result"
set_output new-required-regressions "$regressions"
set_output inconclusive-required "$inconclusive"
set_output coverage-removed-required "$coverage_removed"
set_output diff-json "$diff_json"
set_output diff-markdown "$diff_md"
set_output gate "$gate"
set_output baseline-gate "$baseline_gate"
set_output candidate-gate "$candidate_gate"

{
  echo
  echo "## bpfcompat regression diff"
  echo
  echo "| Result | New required regressions | Required inconclusive | Required coverage removed | fail-on-regression | fail-on-incomplete | Policy |"
  echo "|---|---|---|---|---|---|---|"
  printf '| `%s` | %s | %s | %s | %s | %s | %s |\n' "$result" "$regressions" "$inconclusive" "$coverage_removed" \
    "$fail_on_regression" "$fail_on_incomplete" "$([[ "$policy_failed" == true ]] && echo '**failed**' || echo passed)"
  echo
  echo '`NEW_REGRESSIONS` means a required kernel the baseline supported is broken in the candidate.'
  echo '`INCONCLUSIVE` means a required comparison could not be established (infrastructure error, missing result, or a different kernel); it is not a claim about the candidate.'
  echo
  if [[ "$require_gate" == true ]]; then
    echo "require-gate: \`true\` — gate \`${gate:-absent}\`, baseline \`${baseline_gate:-absent}\`, candidate \`${candidate_gate:-absent}\` (unless a profile is required in both reports, the diff is diagnostic, not a gate, and fails this policy)."
    echo
  fi
  if [[ -f "$diff_md" ]]; then
    cat -- "$diff_md"
  else
    echo "_bpfcompat diff wrote no Markdown; see the diff JSON._"
  fi
} | summary

if [[ "$policy_failed" == true ]]; then
  for r in "${reasons[@]}"; do
    echo "::error title=bpfcompat diff::$r"
  done
  exit 1
fi
echo "bpfcompat diff: $result; policy passed"
