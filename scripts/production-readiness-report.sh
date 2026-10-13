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

candidate="$(evidence_path "$(jq -r '.candidate.evidence' "$input")")"
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
  metadata="$(evidence_path "$metadata_rel")"
  report="$(evidence_path "$report_rel")"

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
    '{
      workflow_run_id: $workflow_run_id,
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

falco_report="$(evidence_path "$(jq -r '.falco.report' "$input")")"
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

: >"$tmp/canary_rows"
: >"$tmp/canaries.ndjson"
: >"$tmp/canary_run_ids"
while IFS= read -r canary; do
  milestone="$(jq -r '.milestone' <<<"$canary")"
  evidence_rel="$(jq -r '.evidence' <<<"$canary")"
  canary_evidence="$(evidence_path "$evidence_rel")"
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
  printf '%s\n' "$canary_run_id" >>"$tmp/canary_run_ids"
  printf "| %s | \`%s\` | %s |\n" \
    "$milestone" "$canary_run_id" "$canary_completed_at" >>"$tmp/canary_rows"
  jq -n \
    --arg milestone "$milestone" \
    --argjson workflow_run_id "$canary_run_id" \
    --arg completed_at "$canary_completed_at" \
    --arg evidence_sha256 "$canary_sha" \
    '{
      milestone: $milestone,
      workflow_run_id: $workflow_run_id,
      completed_at: $completed_at,
      evidence_sha256: $evidence_sha256
    }' >>"$tmp/canaries.ndjson"
done < <(jq -c '.canaries[]' "$input")

[[ "$(sort -u "$tmp/canary_run_ids" | wc -l)" -eq 3 ]] ||
  fail "RC canary workflow run IDs must be unique"

rollback="$(evidence_path "$(jq -r '.rollback.evidence' "$input")")"
verify_hash "$rollback" "$(jq -r '.rollback.evidence_sha256' "$input")"
grep -Fq '[bpfcompat-rollback-drill:v1]' "$rollback" ||
  fail "rollback evidence is missing its completion marker"
incident="$(evidence_path "$(jq -r '.incident.evidence' "$input")")"
verify_hash "$incident" "$(jq -r '.incident.evidence_sha256' "$input")"
grep -Fq '[bpfcompat-promotion-incident:v1]' "$incident" ||
  fail "incident evidence is missing its fail-closed completion marker"
operator_evidence="$(evidence_path "$(jq -r '.operator.evidence' "$input")")"
verify_hash "$operator_evidence" "$(jq -r '.operator.evidence_sha256' "$input")"
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
  echo "- Attested release candidate: PASS"
  echo "- RC manual, T+24h, and T+72h canaries: PASS"
  echo "- Rollback drill: PASS"
  echo "- Fail-closed promotion incident: PASS"
  echo "- Deliberate solo-maintainer promotion confirmation: PASS"
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

jq -n \
  --arg schema_version "v0.1" \
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
  '{
    schema_version: $schema_version,
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
      evidence_sha256: $rollback_sha
    },
    incident: {
      completed: true,
      evidence_sha256: $incident_sha
    },
    operator: {
      login: $operator,
      approval_mode: $approval_mode,
      confirmed: true,
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
