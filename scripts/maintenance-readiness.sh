# shellcheck shell=bash
# shellcheck disable=SC2154  # input, output, candidate, operator, ... come from the sourcing script
# Readiness "maintenance" channel (R1-R3). Sourced by
# production-readiness-report.sh, which provides fail, evidence_path,
# verify_hash, verify_observation, verify_candidate, verify_release_controls,
# ROOT_DIR, input, output and output_json.
#
# A maintenance release replaces the stable channel's four scheduled
# campaigns and three RC canary windows with:
#   - an eligible machine-verified scope (re-checked here, not trusted);
#   - the attested release-candidate evidence (unchanged);
#   - a stable commit that differs from the candidate only in release metadata;
#   - two producer-attested maintenance-evidence runs (E0, E1) from
#     maintenance-evidence.yml at the candidate tag, bound to the exact
#     candidate tag/commit/digest/checksums and at least 24 hours apart, each
#     carrying the VM gate (exact kernel 725, positive + expected-INCOMPATIBLE
#     negative) and the candidate canary;
#   - the rollback, incident and solo-operator controls (unchanged).
# There is no unattested path: third-party runs and `attested: false`
# observations are corroboration only and are rejected here.

jq -e '
  .schema_version == "v0.1" and
  .channel == "maintenance" and
  (.release_version | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")) and
  (.candidate | type == "object") and
  (.observations | type == "array" and length == 2) and
  ([.observations[].milestone] == ["e0", "e1"]) and
  (has("campaigns") | not) and
  (has("canaries") | not) and
  (has("falco") | not) and
  (.rollback.completed == true) and
  (.incident.completed == true) and
  (.operator.approval_mode == "solo-maintainer") and
  (.operator.confirmed == true)
' "$input" >/dev/null || fail "maintenance manifest schema or required gates are invalid"

release_version="$(jq -r '.release_version' "$input")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# 1. The channel is selectable only when the scope is eligible right now.
stable_commit="$(awk -F': ' '$1 == "stable_commit" {print $2; exit}' release.yaml)"
[[ "$stable_commit" =~ ^[0-9a-f]{40}$ ]] || fail "release.yaml stable_commit is invalid"
scope_cmd="${BPFCOMPAT_SCOPE_CHECK_CMD:-python3 scripts/check-maintenance-scope.py}"
# shellcheck disable=SC2086  # scope_cmd is a command line by design
$scope_cmd --out "$tmp/scope.json" >"$tmp/scope.log" 2>&1 ||
  fail "maintenance scope is not eligible; this release needs the stable channel"
jq -e --arg base "$stable_commit" '
  .eligible == true and (.violations | length == 0) and .baseline == $base
' "$tmp/scope.json" >/dev/null || fail "maintenance scope result is not eligible against stable_commit"

# 2. Attested release candidate (same check as the stable channel).
verify_candidate
candidate_tag="$(jq -r '.tag' "$candidate")"
candidate_commit="$(jq -r '.commit_sha' "$candidate")"
candidate_image="$(jq -r '.image' "$candidate")"
candidate_digest="${candidate_image##*@}"
candidate_checksums="$(jq -r '.checksums_sha256' "$candidate")"
candidate_sha="$(jq -r '.candidate.evidence_sha256' "$input")"

# 3. The commit being released is the candidate plus release metadata only.
git cat-file -e "${candidate_commit}^{commit}" 2>/dev/null ||
  fail "candidate commit is not in this checkout"
git merge-base --is-ancestor "$candidate_commit" HEAD ||
  fail "candidate commit is not an ancestor of the release commit"
while IFS= read -r path; do
  case "$path" in
    release.yaml | CHANGELOG.md | docs/releases/*) ;;
    *) fail "release commit changes ${path} after the candidate; only release metadata may change" ;;
  esac
done < <(git diff --name-only "$candidate_commit" HEAD)
diff \
  <(git show "${candidate_commit}:release.yaml" | grep -Ev '^release_(version|channel):') \
  <(git show "HEAD:release.yaml" | grep -Ev '^release_(version|channel):') >/dev/null ||
  fail "release.yaml changed beyond release_version/release_channel after the candidate"

# 4. Two producer-attested maintenance-evidence observations.
: >"$tmp/observations.ndjson"
: >"$tmp/observation_rows"
: >"$tmp/run_ids"
e0_completed_epoch=0
now_epoch="$(date -u +%s)"
while IFS= read -r observation; do
  milestone="$(jq -r '.milestone' <<<"$observation")"
  evidence="$(evidence_path "$(jq -r '.evidence' <<<"$observation")")"
  evidence_sha="$(jq -r '.evidence_sha256' <<<"$observation")"
  verify_hash "$evidence" "$evidence_sha"
  jq -e \
    --arg milestone "$milestone" \
    --arg tag "$candidate_tag" \
    --arg commit "$candidate_commit" \
    --arg digest "$candidate_digest" \
    --arg checksums "$candidate_checksums" \
    --arg candidate_sha "$candidate_sha" \
    --arg base "$stable_commit" \
    '
      .schema_version == "v0.1" and
      .marker == "[bpfcompat-maintenance-evidence:v1]" and
      .repository == "Kernel-Guard/bpfcompat" and
      (has("attested") | not) and
      .workflow_ref == ("Kernel-Guard/bpfcompat/.github/workflows/maintenance-evidence.yml@refs/tags/" + $tag) and
      .milestone == $milestone and
      (.workflow_run_id | type == "number" and . > 0) and
      (.workflow_run_attempt | type == "number" and . > 0) and
      (.started_at | fromdateiso8601 > 0) and
      ((.completed_at | fromdateiso8601) >= (.started_at | fromdateiso8601)) and
      .tag == $tag and
      .commit_sha == $commit and
      .image_digest == $digest and
      .checksums_sha256 == $checksums and
      .candidate_evidence_sha256 == $candidate_sha and
      (.cli_sha256 | test("^[0-9a-f]{64}$")) and
      (.validator_sha256 | test("^[0-9a-f]{64}$")) and
      .scope.eligible == true and
      .scope.baseline == $base and
      .vm.positive == "pass" and
      .vm.negative == "expected-incompatible" and
      .vm.exact_kernel == "5.14.0-725.el9.x86_64" and
      .canary["clean-install"] == "pass" and
      .canary["candidate-action"] == "pass" and
      .canary.container == "pass" and
      .acceptance.status == "pass" and
      .acceptance.required_infra_errors == 0
    ' "$evidence" >/dev/null ||
    fail "maintenance evidence ${milestone} is invalid or not bound to the candidate"
  run_id="$(jq -r '.workflow_run_id' "$evidence")"
  verify_observation "$evidence" Kernel-Guard/bpfcompat .github/workflows/maintenance-evidence.yml \
    "$run_id" "$candidate_commit" workflow_dispatch tags "$candidate_tag"

  started_at="$(jq -r '.started_at' "$evidence")"
  completed_at="$(jq -r '.completed_at' "$evidence")"
  started_epoch="$(date -u -d "$started_at" +%s)"
  completed_epoch="$(date -u -d "$completed_at" +%s)"
  [[ "$completed_epoch" -le "$now_epoch" ]] || fail "maintenance evidence ${milestone} completes in the future"
  if [[ "$milestone" == e0 ]]; then
    e0_completed_epoch="$completed_epoch"
  else
    [[ "$e0_completed_epoch" -gt 0 && $((started_epoch - e0_completed_epoch)) -ge 86400 ]] ||
      fail "E1 must start at least 24 hours after E0 completed"
  fi
  printf '%s\n' "$run_id" >>"$tmp/run_ids"
  printf "| %s | \`%s\` | %s | %s |\n" "$milestone" "$run_id" "$started_at" "$completed_at" >>"$tmp/observation_rows"
  jq -n --arg milestone "$milestone" --argjson workflow_run_id "$run_id" \
    --arg started_at "$started_at" --arg completed_at "$completed_at" --arg evidence_sha256 "$evidence_sha" \
    '{milestone: $milestone, workflow_run_id: $workflow_run_id, started_at: $started_at,
      completed_at: $completed_at, evidence_sha256: $evidence_sha256}' >>"$tmp/observations.ndjson"
done < <(jq -c '.observations[]' "$input")
[[ "$(sort -u "$tmp/run_ids" | wc -l)" -eq 2 ]] || fail "E0 and E1 must be distinct workflow runs"

# 5. Rollback, incident and operator controls (same as the stable channel).
verify_release_controls

mkdir -p "$(dirname "$output")" "$(dirname "$output_json")"
{
  echo "# bpfcompat ${release_version} Production Readiness"
  echo
  echo "- Gate status: **ready**"
  echo "- Channel: **maintenance** (machine-verified scope; baseline \`${stable_commit:0:12}\`)"
  echo "- Supported boundary: CLI + GitHub Action + disposable QEMU/KVM validation"
  echo "- Candidate: \`${candidate_tag}\` at \`${candidate_commit:0:12}\`, image \`${candidate_digest}\`"
  echo "- Producer-attested maintenance-evidence runs: 2 (>= 24h apart)"
  echo "- Release operator: \`${operator}\`"
  echo "- Approval mode: \`${approval_mode}\` (no independent human approval)"
  echo
  echo "## Maintenance Evidence"
  echo
  echo "| Milestone | Workflow run | Started (UTC) | Completed (UTC) |"
  echo "|---|---|---|---|"
  cat "$tmp/observation_rows"
  echo
  echo "## Required Evidence"
  echo
  echo "- Machine-verified maintenance scope: ELIGIBLE"
  echo "- Attested release candidate: PASS"
  echo "- Release commit differs from the candidate only in release metadata: PASS"
  echo "- E0/E1 VM gate (exact kernel 5.14.0-725.el9, classified negative) and candidate canary: PASS"
  echo "- Rollback drill: PASS"
  echo "- Fail-closed promotion incident: PASS"
  echo "- Deliberate solo-maintainer promotion confirmation: PASS"
  echo
  echo "Third-party (upstream) runs are operational corroboration only and are not readiness inputs."
  echo "Runtime loading, agent, API, registry, SaaS, Firecracker, and virtme-ng are excluded."
} >"$output"

jq -n \
  --arg release_version "$release_version" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg stable_commit "$stable_commit" \
  --argjson observations "$(jq -s '.' "$tmp/observations.ndjson")" \
  --arg candidate_tag "$candidate_tag" \
  --arg candidate_commit "$candidate_commit" \
  --arg candidate_image "$candidate_image" \
  --arg candidate_sha "$candidate_sha" \
  --arg rollback_sha "$(jq -r '.rollback.evidence_sha256' "$input")" \
  --arg incident_sha "$(jq -r '.incident.evidence_sha256' "$input")" \
  --arg operator "$operator" \
  --arg approval_mode "$approval_mode" \
  --arg operator_sha "$(jq -r '.operator.evidence_sha256' "$input")" \
  '{
    schema_version: "v0.1",
    gate_status: "ready",
    channel: "maintenance",
    release_version: $release_version,
    supported_boundary: "CLI + GitHub Action + disposable QEMU/KVM validation",
    generated_at: $generated_at,
    scope: {eligible: true, baseline: $stable_commit},
    candidate: {tag: $candidate_tag, commit_sha: $candidate_commit, image: $candidate_image, evidence_sha256: $candidate_sha},
    observations: $observations,
    rollback: {completed: true, evidence_sha256: $rollback_sha},
    incident: {completed: true, evidence_sha256: $incident_sha},
    operator: {login: $operator, approval_mode: $approval_mode, confirmed: true, evidence_sha256: $operator_sha},
    excluded_surfaces: ["runtime-loading", "agent", "api", "registry", "saas", "firecracker", "virtme-ng"]
  }' >"$output_json"

echo "[production-readiness] ready (maintenance): $output and $output_json"
