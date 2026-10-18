#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

input="${1:-}"
output="${2:-}"
if [[ "$output" == *.md ]]; then
  output_json="${3:-${output%.md}.json}"
else
  output_json="${3:-${output}.json}"
fi

fail() {
  echo "[production-readiness] $*" >&2
  exit 2
}

[[ -n "$input" && -n "$output" ]] ||
  fail "usage: production-readiness-report.sh INPUT.json OUTPUT.md"
command -v jq >/dev/null || fail "jq is required"
command -v sha256sum >/dev/null || fail "sha256sum is required"
[[ -s "$input" ]] || fail "input manifest is missing or empty: $input"

manifest_dir="$(cd "$(dirname "$input")" && pwd)"
input="$(realpath "$input")"

evidence_path() {
  local relative="$1"
  local resolved
  [[ -n "$relative" && "$relative" != /* ]] ||
    fail "evidence paths must be non-empty and relative"
  resolved="$(realpath -e "${manifest_dir}/${relative}")" ||
    fail "evidence path does not exist: $relative"
  case "$resolved" in
    "${manifest_dir}"/*) ;;
    *) fail "evidence path escapes the manifest directory: $relative" ;;
  esac
  [[ -f "$resolved" && -s "$resolved" ]] ||
    fail "evidence path is not a non-empty file: $relative"
  printf '%s\n' "$resolved"
}

# require_single_object <file> <what>: `jq -e` judges only the last value of a
# multi-document stream, so a failing record followed by a passing one would
# pass. Every JSON input must be exactly one object.
require_single_object() {
  jq -se 'length == 1 and (.[0] | type == "object")' "$1" >/dev/null 2>&1 ||
    fail "$2 must be exactly one JSON object: $(basename "$1")"
}

# json_evidence_path <relative path>: evidence_path for a JSON document.
json_evidence_path() {
  local resolved
  resolved="$(evidence_path "$1")" || exit 2
  require_single_object "$resolved" "evidence"
  printf '%s\n' "$resolved"
}

verify_hash() {
  local path="$1"
  local expected="$2"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] ||
    fail "invalid SHA-256 for $(basename "$path")"
  local actual
  actual="$(sha256sum "$path" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] ||
    fail "SHA-256 mismatch for $(basename "$path")"
}

# iso_epoch <timestamp> <what>: strict UTC RFC 3339 (YYYY-MM-DDTHH:MM:SSZ) to
# epoch seconds; `date -d` alone accepts far looser input.
iso_epoch() {
  [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] ||
    fail "$2 is not a UTC timestamp: $1"
  date -u -d "$1" +%s 2>/dev/null || fail "$2 is not a valid timestamp: $1"
}

# md_field <file> <label>: the first backticked value on the single line that
# starts "- <label>: `" in a workflow-written Markdown note. A missing or
# repeated label fails closed.
md_field() {
  awk -v prefix="- $2: \`" '
    index($0, prefix) == 1 {
      n++
      rest = substr($0, length(prefix) + 1)
      value = substr(rest, 1, index(rest, "`") - 1)
    }
    END { if (n == 1 && value != "") print value; else exit 1 }
  ' "$1" || fail "$(basename "$1") must contain exactly one \"- $2: \`...\`\" line"
}

require_single_object "$input" "the input manifest"
jq -e '
  .schema_version == "v0.1" and
  (.release_version | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")) and
  (.campaigns | type == "array" and length == 4) and
  (.falco | type == "object") and
  (.candidate | type == "object") and
  (.candidate.checksums | type == "string" and length > 0) and
  (.canaries | type == "array" and length == 3) and
  ([.canaries[].milestone] == ["manual", "t-plus-24h", "t-plus-72h"]) and
  (.rollback.completed == true) and
  (.incident.completed == true) and
  (.operator.approval_mode == "solo-maintainer") and
  (.operator.confirmed == true)
' "$input" >/dev/null || fail "manifest schema or required gates are invalid"

release_version="$(jq -r '.release_version' "$input")"

candidate="$(json_evidence_path "$(jq -r '.candidate.evidence' "$input")")"
verify_hash "$candidate" "$(jq -r '.candidate.evidence_sha256' "$input")"
jq -e --arg release_version "$release_version" '
  .schema_version == "v0.1" and
  .repository == "Kernel-Guard/bpfcompat" and
  .channel == "prerelease" and
  (.tag | test("^v[0-9]+\\.[0-9]+\\.[0-9]+-rc\\.[1-9][0-9]*$")) and
  (.tag | startswith("v" + $release_version + "-rc.")) and
  (.commit_sha | test("^[0-9a-f]{40}$")) and
  (.image | test("@sha256:[0-9a-f]{64}$")) and
  (.checksums_sha256 | test("^[0-9a-f]{64}$")) and
  (.positive_report_sha256 | test("^[0-9a-f]{64}$")) and
  (.negative_report_sha256 | test("^[0-9a-f]{64}$")) and
  (.generated_at | fromdateiso8601 > 0)
' "$candidate" >/dev/null || fail "release-candidate evidence is invalid"

if [[ "${BPFCOMPAT_SKIP_READINESS_ATTESTATION:-0}" != "1" ]]; then
  command -v gh >/dev/null || fail "gh is required to verify candidate evidence"
  gh attestation --help >/dev/null 2>&1 ||
    fail "installed GitHub CLI lacks attestation support"
  gh attestation verify "$candidate" \
    --repo Kernel-Guard/bpfcompat \
    --signer-workflow Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml \
    --source-digest "$(jq -r '.commit_sha' "$candidate")" \
    --source-ref "refs/tags/$(jq -r '.tag' "$candidate")" \
    >/dev/null || fail "release-candidate evidence attestation verification failed"
fi

# The candidate's signed SHA256SUMS names the executables every campaign must
# have run. It is bound to the attested evidence by digest.
candidate_checksums="$(evidence_path "$(jq -r '.candidate.checksums' "$input")")"
verify_hash "$candidate_checksums" "$(jq -r '.checksums_sha256' "$candidate")"
checksum_entry() {
  awk -v f="$1" '$2 == f && $1 ~ /^[0-9a-f]{64}$/ {n++; h = $1} END {if (n == 1) print h; else exit 1}' \
    "$candidate_checksums" || fail "candidate SHA256SUMS must list $1 exactly once"
}
candidate_cli_sha="$(checksum_entry bpfcompat-linux-amd64)"
candidate_validator_sha="$(checksum_entry bpfcompat-validator-static-linux-amd64)"
candidate_evidence_sha="$(jq -r '.candidate.evidence_sha256' "$input")"
candidate_generated_epoch="$(date -u -d "$(jq -r '.generated_at' "$candidate")" +%s)" ||
  fail "release-candidate evidence has an invalid generated_at"
candidate_tag="$(jq -r '.tag' "$candidate")"
candidate_commit="$(jq -r '.commit_sha' "$candidate")"
candidate_image="$(jq -r '.image' "$candidate")"
candidate_digest="${candidate_image##*@}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
: >"$tmp/durations"
: >"$tmp/run_ids"
: >"$tmp/campaign_rows"
: >"$tmp/campaigns.ndjson"
: >"$tmp/started_epochs"

campaign_count="$(jq '.campaigns | length' "$input")"
total_targets=0
campaign_index=0

while IFS= read -r campaign; do
  campaign_index=$((campaign_index + 1))
  metadata_rel="$(jq -r '.metadata' <<<"$campaign")"
  report_rel="$(jq -r '.report' <<<"$campaign")"
  metadata="$(json_evidence_path "$metadata_rel")"
  report="$(json_evidence_path "$report_rel")"

  # A scheduled run executes the workflow from the default branch, so
  # workflow_sha identifies the workflow source only. What was tested is the
  # candidate block, written by that workflow after it verified the immutable
  # tag, the signed release assets and their attestations
  # (scripts/campaign-candidate-bind.sh). v0.1 campaign evidence recorded no
  # tested candidate at all and is never accepted.
  jq -e '
    .schema_version == "v0.2" and
    .marker == "[bpfcompat-campaign:v2]" and
    .repository == "Kernel-Guard/bpfcompat" and
    .workflow == "Kernel-Guard/bpfcompat/.github/workflows/latest-kernel-compatibility.yml@refs/heads/main" and
    .event == "schedule" and
    (.workflow_run_id | type == "number" and . > 0) and
    (.workflow_run_attempt | type == "number" and . > 0) and
    (.workflow_sha | test("^[0-9a-f]{40}$")) and
    (.report_sha256 | test("^[0-9a-f]{64}$")) and
    (.report_run_id | type == "string" and length > 0) and
    (.started_at | fromdateiso8601 > 0)
  ' "$metadata" >/dev/null ||
    fail "campaign ${campaign_index} metadata is invalid or is not scheduled v0.2 evidence"
  jq -e \
    --arg tag "$candidate_tag" \
    --arg commit "$candidate_commit" \
    --arg checksums "$(jq -r '.checksums_sha256' "$candidate")" \
    --arg evidence "$candidate_evidence_sha" \
    --arg cli "$candidate_cli_sha" \
    --arg validator "$candidate_validator_sha" '
      (.candidate | type == "object") and
      .candidate.tag == $tag and
      .candidate.commit_sha == $commit and
      .candidate.checksums_sha256 == $checksums and
      .candidate.candidate_evidence_sha256 == $evidence and
      (.executed | type == "object") and
      .executed.cli_sha256 == $cli and
      .executed.validator_sha256 == $validator
    ' "$metadata" >/dev/null ||
    fail "campaign ${campaign_index} did not test release candidate ${candidate_tag} (${candidate_commit}) with its released executables"

  expected_report="$(jq -r '.report' "$metadata")"
  [[ "$(basename "$report")" == "$expected_report" ]] ||
    fail "campaign ${campaign_index} report name does not match its metadata"
  verify_hash "$report" "$(jq -r '.report_sha256' "$metadata")"
  # The report itself must be this campaign's run, and its own record of the
  # validator that ran in the guests must be the candidate's validator.
  jq -e \
    --arg run_id "$(jq -r '.report_run_id' "$metadata")" \
    --arg started_at "$(jq -r '.started_at' "$metadata")" \
    --arg validator "$candidate_validator_sha" '
      .run.id == $run_id and .run.started_at == $started_at and
      .validator.sha256 == $validator
    ' "$report" >/dev/null ||
    fail "campaign ${campaign_index} report is not this campaign's run of the candidate validator"

  if [[ "${BPFCOMPAT_SKIP_READINESS_ATTESTATION:-0}" != "1" ]]; then
    campaign_run="$(jq -r '.workflow_run_id' "$metadata")"
    campaign_attempt="$(jq -r '.workflow_run_attempt' "$metadata")"
    attested="$(gh attestation verify "$metadata" \
      --repo Kernel-Guard/bpfcompat \
      --signer-workflow Kernel-Guard/bpfcompat/.github/workflows/latest-kernel-compatibility.yml \
      --source-digest "$(jq -r '.workflow_sha' "$metadata")" \
      --source-ref refs/heads/main \
      --format json)" ||
      fail "campaign ${campaign_index} evidence attestation verification failed"
    jq -e --arg inv "https://github.com/Kernel-Guard/bpfcompat/actions/runs/${campaign_run}/attempts/${campaign_attempt}" \
      'any(.[]; .verificationResult.statement.predicate.runDetails.metadata.invocationId == $inv)' \
      <<<"$attested" >/dev/null ||
      fail "campaign ${campaign_index} attestation was not produced by run ${campaign_run} attempt ${campaign_attempt}"
    # The event comes from the signed provenance, not from the evidence file.
    jq -e --arg inv "https://github.com/Kernel-Guard/bpfcompat/actions/runs/${campaign_run}/attempts/${campaign_attempt}" \
      'any(.[]; .verificationResult.statement.predicate.runDetails.metadata.invocationId == $inv and
                .verificationResult.statement.predicate.buildDefinition.internalParameters.github.event_name == "schedule")' \
      <<<"$attested" >/dev/null ||
      fail "campaign ${campaign_index} attestation does not show a scheduled run"
  fi

  jq -e '
    .schema_version == "v0.1" and
    .summary.status == "pass" and
    (.targets | length > 0) and
    ([.targets[] | select(.required and .status != "pass")] | length == 0) and
    ([.targets[] | select(.status == "infra_error" or (.infra_error // "") != "")] | length == 0)
  ' "$report" >/dev/null ||
    fail "campaign ${campaign_index} has a required failure or infrastructure error"

  run_id="$(jq -r '.workflow_run_id' "$metadata")"
  commit_sha="$(jq -r '.workflow_sha' "$metadata")"
  started_at="$(jq -r '.started_at' "$metadata")"
  started_epoch="$(date -u -d "$started_at" +%s)" ||
    fail "campaign ${campaign_index} has an invalid timestamp"
  [[ "$started_epoch" -gt "$candidate_generated_epoch" ]] ||
    fail "campaign ${campaign_index} started before release candidate ${candidate_tag} was built"
  target_count="$(jq '.targets | length' "$report")"
  total_targets=$((total_targets + target_count))
  printf '%s\n' "$run_id" >>"$tmp/run_ids"
  printf '%s\n' "$started_epoch" >>"$tmp/started_epochs"
  campaign_candidate_tag="$(jq -r '.candidate.tag' "$metadata")"
  campaign_candidate_commit="$(jq -r '.candidate.commit_sha' "$metadata")"
  campaign_cli_sha="$(jq -r '.executed.cli_sha256' "$metadata")"
  campaign_validator_sha="$(jq -r '.executed.validator_sha256' "$metadata")"
  jq -r '.targets[].duration_ms | select(. > 0)' "$report" >>"$tmp/durations"
  printf "| %s | \`%s\` | \`%s\` | %s | %s |\n" \
    "$campaign_index" "$run_id" "${commit_sha:0:12}" "$started_at" "$target_count" \
    >>"$tmp/campaign_rows"
  jq -n \
    --argjson workflow_run_id "$run_id" \
    --arg commit_sha "$commit_sha" \
    --arg started_at "$started_at" \
    --arg report_sha256 "$(jq -r '.report_sha256' "$metadata")" \
    --argjson target_count "$target_count" \
    --arg candidate_tag "$campaign_candidate_tag" \
    --arg candidate_commit "$campaign_candidate_commit" \
    --arg cli_sha256 "$campaign_cli_sha" \
    --arg validator_sha256 "$campaign_validator_sha" \
    '{
      workflow_run_id: $workflow_run_id,
      candidate_tag: $candidate_tag,
      candidate_commit: $candidate_commit,
      executed: {cli_sha256: $cli_sha256, validator_sha256: $validator_sha256},
      workflow_sha: $commit_sha,
      started_at: $started_at,
      report_sha256: $report_sha256,
      target_count: $target_count
    }' >>"$tmp/campaigns.ndjson"
done < <(jq -c '.campaigns[]' "$input")

[[ "$(sort -u "$tmp/run_ids" | wc -l)" -eq "$campaign_count" ]] ||
  fail "campaign workflow run IDs must be unique"

previous=0
while IFS= read -r epoch; do
  if [[ "$previous" -gt 0 ]]; then
    interval=$((epoch - previous))
    [[ "$interval" -ge 518400 && "$interval" -le 691200 ]] ||
      fail "campaigns must be chronological and 6-8 days apart"
  fi
  previous="$epoch"
done <"$tmp/started_epochs"

duration_count="$(wc -l <"$tmp/durations")"
[[ "$duration_count" -eq "$total_targets" ]] ||
  fail "every campaign target must record a positive duration"
sort -n "$tmp/durations" >"$tmp/durations.sorted"
p95_rank=$(((95 * duration_count + 99) / 100))
p95_ms="$(sed -n "${p95_rank}p" "$tmp/durations.sorted")"
[[ "$p95_ms" -le 720000 ]] ||
  fail "campaign target p95 ${p95_ms}ms exceeds the 12-minute budget"

falco_report="$(json_evidence_path "$(jq -r '.falco.report' "$input")")"
verify_hash "$falco_report" "$(jq -r '.falco.report_sha256' "$input")"
jq -e '
  (.falco.workflow_run_id | type == "number" and . > 0) and
  (.falco.commit_sha | test("^[0-9a-f]{40}$")) and
  (.falco.started_at | fromdateiso8601 > 0)
' "$input" >/dev/null || fail "Falco run identity is invalid"
jq -e '
  .schema_version == "v0.1" and
  .summary.status == "pass" and
  ([.targets[] | select(.status == "infra_error" or (.infra_error // "") != "")] | length == 0)
' "$falco_report" >/dev/null || fail "Falco report failed or contains an infrastructure error"
for profile in \
  ubuntu-22.04-5.15 \
  debian-12-6.1 \
  ubuntu-24.04-6.8 \
  almalinux-8-4.18 \
  almalinux-9-5.14; do
  jq -e --arg profile "$profile" '
    [.targets[] | select(.profile_id == $profile and .status == "pass")] | length == 1
  ' "$falco_report" >/dev/null || fail "Falco report is missing passing profile ${profile}"
done
# The manifest's start time is the report's own run.started_at, not a free
# value, and -- like every campaign -- the run must postdate the candidate.
# workflow_run_id and commit_sha cannot be cross-checked offline (the report
# does not record them) and stay operator-asserted.
falco_report_started_at="$(jq -r '.run.started_at // ""' "$falco_report")"
[[ "$(jq -r '.falco.started_at' "$input")" == "$falco_report_started_at" ]] ||
  fail "Falco started_at does not match the report's run.started_at (${falco_report_started_at:-missing})"
falco_started_epoch="$(iso_epoch "$falco_report_started_at" "Falco report run.started_at")"
# run.started_at is written when the report is assembled, after the targets
# ran, so it can postdate the candidate while the run itself began before it.
# The run started at the earliest of run.started_at and every target's
# started_at, and every target must record one.
jq -e '[.targets[] | select((.started_at // "") == "")] | length == 0' "$falco_report" >/dev/null ||
  fail "Falco report has a target without started_at, so when the run started cannot be established"
while IFS= read -r target_started_at; do
  target_epoch="$(iso_epoch "$target_started_at" "Falco report target started_at")"
  ((target_epoch < falco_started_epoch)) && falco_started_epoch="$target_epoch"
done < <(jq -r '.targets[].started_at' "$falco_report")
[[ "$falco_started_epoch" -gt "$candidate_generated_epoch" ]] ||
  fail "Falco run started before release candidate ${candidate_tag} was built"
# Written policy does not say the Falco run must execute the candidate's own
# bpfcompat (the upstream lane pins a released version). Record whether its
# report names the candidate validator instead of enforcing it.
falco_validator_sha="$(jq -r '.validator.sha256 // ""' "$falco_report")"
falco_candidate_bound=false
if [[ -n "$falco_validator_sha" && "$falco_validator_sha" == "$candidate_validator_sha" ]]; then
  falco_candidate_bound=true
fi

: >"$tmp/canary_rows"
: >"$tmp/canaries.ndjson"
: >"$tmp/canary_run_ids"
previous_canary_epoch=0
while IFS= read -r canary; do
  milestone="$(jq -r '.milestone' <<<"$canary")"
  evidence_rel="$(jq -r '.evidence' <<<"$canary")"
  canary_evidence="$(json_evidence_path "$evidence_rel")"
  canary_sha="$(jq -r '.evidence_sha256' <<<"$canary")"
  verify_hash "$canary_evidence" "$canary_sha"

  expected_event="schedule"
  if [[ "$milestone" == "manual" ]]; then
    expected_event="workflow_dispatch"
  fi
  jq -e \
    --arg milestone "$milestone" \
    --arg event "$expected_event" \
    --arg version "$candidate_tag" \
    --arg commit "$candidate_commit" \
    --arg digest "$candidate_digest" \
    '
      .schema_version == "v0.1" and
      .marker == "[bpfcompat-rc-canary:v1]" and
      .repository == "Kernel-Guard/bpfcompat" and
      .milestone == $milestone and
      .event == $event and
      (.workflow_run_id | type == "number" and . > 0) and
      (.external_consumer_run_id | type == "number" and . > 0) and
      (.completed_at | fromdateiso8601 > 0) and
      .version == $version and
      .commit == $commit and
      .image_digest == $digest and
      .checks.clean_install == "pass" and
      .checks.source_build == "pass" and
      .checks.published_action == "pass" and
      .checks.container == "pass" and
      .checks.external_consumers == "pass" and
      (.components | type == "array" and length > 0) and
      ([.components[] |
        (.sha256 | test("^[0-9a-f]{64}$")) and
        (.path | type == "string" and length > 0)
      ] | all)
    ' "$canary_evidence" >/dev/null ||
    fail "RC canary ${milestone} evidence is invalid or does not match the candidate"

  canary_run_id="$(jq '.workflow_run_id' "$canary_evidence")"
  canary_completed_at="$(jq -r '.completed_at' "$canary_evidence")"

  # Observation windows. The canary plan job admits T+24h only 20-30 whole
  # hours, and T+72h only 68-78 whole hours, after CANDIDATE_PUBLISHED_AT.
  # Publication time is not part of the attested candidate evidence, but it
  # cannot precede generated_at, so generated_at + 0/20/68h is a floor every
  # authentic observation meets. Upper bounds are left to the plan job.
  case "$milestone" in
    manual) floor_hours=0 ;;
    t-plus-24h) floor_hours=20 ;;
    t-plus-72h) floor_hours=68 ;;
  esac
  canary_completed_epoch="$(iso_epoch "$canary_completed_at" "RC canary ${milestone} completed_at")"
  [[ "$canary_completed_epoch" -ge $((candidate_generated_epoch + floor_hours * 3600)) ]] ||
    fail "RC canary ${milestone} completed before ${floor_hours}h after release candidate ${candidate_tag} was built"
  [[ "$canary_completed_epoch" -gt "$previous_canary_epoch" ]] ||
    fail "RC canaries must complete in manual, T+24h, T+72h order"
  previous_canary_epoch="$canary_completed_epoch"

  # Components: each is an artifact of this exact canary run (the workflow
  # downloads rc*-canary-component-<check>-<run id>), every check is
  # covered, and each check's own record -- shipped in the same artifact --
  # hashes to the manifest value and names the candidate.
  jq -e --arg run "$canary_run_id" '
    ([.components[].path] | length == (unique | length)) and
    ([.components[].path |
      test("^evidence/components/[a-z0-9.-]*canary-component-(clean-install|source-build|published-action|container|external-consumers)-" + $run + "/[^.][^/]*(/[^.][^/]*)*$")
    ] | all)
  ' "$canary_evidence" >/dev/null ||
    fail "RC canary ${milestone} components are not artifacts of run ${canary_run_id}"
  canary_dir_rel="$(dirname "$evidence_rel")"
  for check in clean-install source-build published-action container external-consumers; do
    component_rel="$(jq -r --arg run "$canary_run_id" --arg check "$check" '
      [.components[] | select(.path | test("canary-component-" + $check + "-" + $run + "/(.*/)?" + $check + "\\.json$"))]
      | if length == 1 then .[0].path else empty end
    ' "$canary_evidence")"
    [[ -n "$component_rel" ]] ||
      fail "RC canary ${milestone} must record exactly one ${check}.json component"
    component="$(json_evidence_path "${canary_dir_rel}/${component_rel#evidence/}")"
    verify_hash "$component" "$(jq -r --arg p "$component_rel" '.components[] | select(.path == $p) | .sha256' "$canary_evidence")"
    jq -e \
      --arg check "$check" \
      --arg version "$candidate_tag" \
      --arg commit "$candidate_commit" \
      --arg digest "$candidate_digest" \
      --argjson external "$(jq '.external_consumer_run_id' "$canary_evidence")" '
        .check == $check and .status == "pass" and
        .version == $version and .commit == $commit and
        (if $check == "container" then .digest == $digest else true end) and
        (if $check == "external-consumers" then .workflow_run_id == $external else true end)
      ' "$component" >/dev/null ||
      fail "RC canary ${milestone} ${check} component does not record a pass of ${candidate_tag}"
  done

  printf '%s\n' "$canary_run_id" >>"$tmp/canary_run_ids"
  printf "| %s | \`%s\` | %s |\n" \
    "$milestone" "$canary_run_id" "$canary_completed_at" >>"$tmp/canary_rows"
  jq -n \
    --arg milestone "$milestone" \
    --argjson workflow_run_id "$canary_run_id" \
    --arg completed_at "$canary_completed_at" \
    --arg evidence_sha256 "$canary_sha" \
    --argjson minutes "$(((canary_completed_epoch - candidate_generated_epoch) / 60))" \
    '{
      milestone: $milestone,
      workflow_run_id: $workflow_run_id,
      completed_at: $completed_at,
      minutes_after_candidate_generated: $minutes,
      components_verified: true,
      evidence_sha256: $evidence_sha256
    }' >>"$tmp/canaries.ndjson"
done < <(jq -c '.canaries[]' "$input")

[[ "$(sort -u "$tmp/canary_run_ids" | wc -l)" -eq 3 ]] ||
  fail "RC canary workflow run IDs must be unique"

rollback="$(evidence_path "$(jq -r '.rollback.evidence' "$input")")"
verify_hash "$rollback" "$(jq -r '.rollback.evidence_sha256' "$input")"
grep -Fq '[bpfcompat-rollback-drill:v1]' "$rollback" ||
  fail "rollback evidence is missing its completion marker"
# Bind the drill to this candidate through the fields rollback-drill.yml
# writes: the alias is the dedicated rollback-drill-<candidate tag> alias,
# the drilled digest is the candidate image digest, the alias ended on the
# known-good digest, and the drill ran after the candidate was built.
candidate_repository="${candidate_image%@*}"
rollback_alias="$(md_field "$rollback" "Drill alias")"
rollback_candidate_digest="$(md_field "$rollback" "Candidate digest")"
rollback_known_good="$(md_field "$rollback" "Known-good digest")"
rollback_final="$(md_field "$rollback" "Final digest")"
rollback_run_id="$(md_field "$rollback" "Workflow run")"
rollback_completed_at="$(md_field "$rollback" "Completed")"
[[ "$rollback_alias" == "${candidate_repository}:rollback-drill-${candidate_tag}" ]] ||
  fail "rollback drill alias ${rollback_alias} is not ${candidate_repository}:rollback-drill-${candidate_tag}"
[[ "$rollback_candidate_digest" == "$candidate_digest" ]] ||
  fail "rollback drill exercised ${rollback_candidate_digest}, not candidate ${candidate_tag} image ${candidate_digest}"
[[ "$rollback_known_good" =~ ^sha256:[0-9a-f]{64}$ &&
   "$rollback_known_good" != "$candidate_digest" &&
   "$rollback_final" == "$rollback_known_good" ]] ||
  fail "rollback drill did not end on a distinct known-good digest"
[[ "$rollback_run_id" =~ ^[1-9][0-9]*$ ]] ||
  fail "rollback drill workflow run is not a run ID: ${rollback_run_id}"
rollback_completed_epoch="$(iso_epoch "$rollback_completed_at" "rollback drill completion")"
[[ "$rollback_completed_epoch" -gt "$candidate_generated_epoch" ]] ||
  fail "rollback drill completed before release candidate ${candidate_tag} was built"

incident="$(evidence_path "$(jq -r '.incident.evidence' "$input")")"
verify_hash "$incident" "$(jq -r '.incident.evidence_sha256' "$input")"
grep -Fq '[bpfcompat-promotion-incident:v1]' "$incident" ||
  fail "incident evidence is missing its fail-closed completion marker"
# The incident must name the rejected promote-release run. Written policy does
# not require the drill to target the current candidate, so a fail-closed
# drill against an earlier candidate stays acceptable; whether it names this
# candidate is recorded as incident.candidate_bound.
grep -Fq 'promote-release' "$incident" ||
  fail "incident evidence does not name the promote-release workflow"
# Exactly one distinct run may be linked, so the rejected run is unambiguous.
incident_run_ids="$(
  grep -oE 'https://github\.com/Kernel-Guard/bpfcompat/actions/runs/[1-9][0-9]*' "$incident" |
    awk -F/ '{print $NF}' | sort -u || true
)"
[[ -n "$incident_run_ids" ]] ||
  fail "incident evidence does not link the rejected promote-release run (https://github.com/Kernel-Guard/bpfcompat/actions/runs/<id>)"
[[ "$(wc -l <<<"$incident_run_ids")" -eq 1 ]] ||
  fail "incident evidence links more than one workflow run; it must link only the rejected promote-release run"
incident_run_id="$incident_run_ids"
incident_candidate_bound=false
if grep -qE "(^|[^[:alnum:].-])${candidate_tag//./\\.}([^[:alnum:]]|$)" "$incident"; then
  incident_candidate_bound=true
fi

operator_evidence="$(evidence_path "$(jq -r '.operator.evidence' "$input")")"
verify_hash "$operator_evidence" "$(jq -r '.operator.evidence_sha256' "$input")"
# The confirmation must name the exact attested candidate evidence it covers.
# Whole token only: not a substring of a longer hex string.
grep -Eq "(^|[^0-9A-Fa-f])${candidate_evidence_sha}([^0-9A-Fa-f]|$)" "$operator_evidence" ||
  fail "operator evidence does not name candidate evidence SHA-256 ${candidate_evidence_sha}"
operator="$(jq -r '.operator.login' "$input")"
approval_mode="$(jq -r '.operator.approval_mode' "$input")"
metadata_operator="$(
  awk -F': ' '$1 == "release_operator" {print $2; exit}' release.yaml
)"
metadata_approval_mode="$(
  awk -F': ' '$1 == "approval_mode" {print $2; exit}' release.yaml
)"
[[ "$operator" == "$metadata_operator" ]] ||
  fail "operator does not match release metadata"
[[ "$approval_mode" == "solo-maintainer" &&
   "$approval_mode" == "$metadata_approval_mode" ]] ||
  fail "solo-maintainer approval mode is not recorded"
grep -Fq '[bpfcompat-solo-promotion:v1]' "$operator_evidence" ||
  fail "operator evidence is missing its solo-promotion marker"
grep -Fq "$operator" "$operator_evidence" ||
  fail "operator evidence does not identify ${operator}"

mkdir -p "$(dirname "$output")"
mkdir -p "$(dirname "$output_json")"
{
  echo "# bpfcompat ${release_version} Production Readiness"
  echo
  echo "- Gate status: **ready**"
  echo "- Supported boundary: CLI + GitHub Action + disposable QEMU/KVM validation"
  echo "- Scheduled campaigns: ${campaign_count}"
  echo "- Target executions: ${total_targets}"
  echo "- Infrastructure errors: 0"
  echo "- Target duration p95: ${p95_ms} ms"
  echo "- Release-candidate canary observations: 3"
  echo "- Release operator: \`${operator}\`"
  echo "- Approval mode: \`${approval_mode}\` (no independent human approval)"
  echo
  echo "## Scheduled Campaigns"
  echo
  echo "Every campaign tested release candidate \`${candidate_tag}\` (\`${candidate_commit}\`) with its released CLI and validator."
  echo
  echo "| # | Workflow run | Workflow source | Started (UTC) | Targets |"
  echo "|---:|---|---|---|---:|"
  cat "$tmp/campaign_rows"
  echo
  echo "## Release-Candidate Canaries"
  echo
  echo "| Milestone | Workflow run | Completed (UTC) |"
  echo "|---|---|---|"
  cat "$tmp/canary_rows"
  echo
  echo "## Required External Evidence"
  echo
  echo "- Falco expanded vendor-kernel matrix: PASS"
  echo "  - Report run \`$(jq -r '.run.id' "$falco_report")\` started ${falco_report_started_at}, after the candidate was built"
  echo "  - Ran the candidate's validator: ${falco_candidate_bound} (not required by policy; workflow run identity is operator-asserted)"
  echo "- Attested release candidate: PASS"
  echo "- RC manual, T+24h, and T+72h canaries: PASS"
  echo "- Rollback drill: PASS"
  echo "  - Run \`${rollback_run_id}\` drilled \`${rollback_alias}\` to candidate digest \`${rollback_candidate_digest}\`"
  echo "- Fail-closed promotion incident: PASS"
  echo "  - Rejected promote-release run \`${incident_run_id}\`; names ${candidate_tag}: ${incident_candidate_bound}"
  echo "- Deliberate solo-maintainer promotion confirmation: PASS"
  echo "  - Confirmation names candidate evidence \`${candidate_evidence_sha}\`"
  echo
  echo "Runtime loading, agent, API, registry, SaaS, Firecracker, and virtme-ng are excluded."
} >"$output"

campaigns_json="$(jq -s '.' "$tmp/campaigns.ndjson")"
canaries_json="$(jq -s '.' "$tmp/canaries.ndjson")"
falco_run_id="$(jq '.falco.workflow_run_id' "$input")"
falco_commit="$(jq -r '.falco.commit_sha' "$input")"
falco_started_at="$(jq -r '.falco.started_at' "$input")"
falco_sha="$(jq -r '.falco.report_sha256' "$input")"
candidate_sha="$(jq -r '.candidate.evidence_sha256' "$input")"
rollback_sha="$(jq -r '.rollback.evidence_sha256' "$input")"
incident_sha="$(jq -r '.incident.evidence_sha256' "$input")"
operator_sha="$(jq -r '.operator.evidence_sha256' "$input")"

attestations_verified=true
if [[ "${BPFCOMPAT_SKIP_READINESS_ATTESTATION:-0}" == "1" ]]; then
  attestations_verified=false
fi
jq -n \
  --arg schema_version "v0.2" \
  --argjson attestations_verified "$attestations_verified" \
  --arg gate_status "ready" \
  --arg release_version "$release_version" \
  --arg supported_boundary "CLI + GitHub Action + disposable QEMU/KVM validation" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson campaigns "$campaigns_json" \
  --argjson canaries "$canaries_json" \
  --argjson total_targets "$total_targets" \
  --argjson p95_ms "$p95_ms" \
  --argjson falco_run_id "$falco_run_id" \
  --arg falco_commit "$falco_commit" \
  --arg falco_started_at "$falco_started_at" \
  --arg falco_sha "$falco_sha" \
  --arg candidate_tag "$candidate_tag" \
  --arg candidate_commit "$candidate_commit" \
  --arg candidate_image "$candidate_image" \
  --arg candidate_sha "$candidate_sha" \
  --arg rollback_sha "$rollback_sha" \
  --arg incident_sha "$incident_sha" \
  --arg operator "$operator" \
  --arg approval_mode "$approval_mode" \
  --arg operator_sha "$operator_sha" \
  --arg falco_report_run_id "$(jq -r '.run.id // ""' "$falco_report")" \
  --arg falco_validator_sha "$falco_validator_sha" \
  --argjson falco_candidate_bound "$falco_candidate_bound" \
  --arg rollback_alias "$rollback_alias" \
  --arg rollback_candidate_digest "$rollback_candidate_digest" \
  --arg rollback_known_good "$rollback_known_good" \
  --argjson rollback_run_id "$rollback_run_id" \
  --arg rollback_completed_at "$rollback_completed_at" \
  --argjson incident_run_id "$incident_run_id" \
  --argjson incident_candidate_bound "$incident_candidate_bound" \
  '{
    schema_version: $schema_version,
    campaign_binding: "candidate-bound-v2",
    attestations_verified: $attestations_verified,
    gate_status: $gate_status,
    release_version: $release_version,
    supported_boundary: $supported_boundary,
    generated_at: $generated_at,
    campaigns: $campaigns,
    slo: {
      campaign_count: ($campaigns | length),
      target_executions: $total_targets,
      infrastructure_errors: 0,
      target_duration_p95_ms: $p95_ms,
      target_timeout_ms: 720000
    },
    falco: {
      workflow_run_id: $falco_run_id,
      commit_sha: $falco_commit,
      started_at: $falco_started_at,
      report_sha256: $falco_sha,
      report_run_id: $falco_report_run_id,
      run_identity: "operator-asserted",
      started_after_candidate: true,
      validator_sha256: (if $falco_validator_sha == "" then null else $falco_validator_sha end),
      candidate_bound: $falco_candidate_bound,
      required_profiles: [
        "ubuntu-22.04-5.15",
        "debian-12-6.1",
        "ubuntu-24.04-6.8",
        "almalinux-8-4.18",
        "almalinux-9-5.14"
      ]
    },
    candidate: {
      tag: $candidate_tag,
      commit_sha: $candidate_commit,
      image: $candidate_image,
      evidence_sha256: $candidate_sha
    },
    canaries: $canaries,
    rollback: {
      completed: true,
      workflow_run_id: $rollback_run_id,
      completed_at: $rollback_completed_at,
      alias: $rollback_alias,
      known_good_digest: $rollback_known_good,
      candidate_digest: $rollback_candidate_digest,
      candidate_bound: true,
      evidence_sha256: $rollback_sha
    },
    incident: {
      completed: true,
      promotion_run_id: $incident_run_id,
      candidate_bound: $incident_candidate_bound,
      evidence_sha256: $incident_sha
    },
    operator: {
      login: $operator,
      approval_mode: $approval_mode,
      confirmed: true,
      candidate_evidence_sha256: $candidate_sha,
      evidence_sha256: $operator_sha
    },
    excluded_surfaces: [
      "runtime-loading",
      "agent",
      "api",
      "registry",
      "saas",
      "firecracker",
      "virtme-ng"
    ]
  }' >"$output_json"

echo "[production-readiness] ready: $output and $output_json"
