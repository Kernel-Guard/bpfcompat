#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${ROOT_DIR}/scripts/production-readiness-report.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_report() {
  local path="$1"
  shift
  jq -n --args '$ARGS.positional' "$@" |
    jq '{
      schema_version: "v0.1",
      run: {id: "fixture", started_at: "2026-08-03T03:21:00Z"},
      artifact: {path: "fixture", basename: "fixture", sha256: ("a" * 64), size_bytes: 1},
      matrix: {path: "fixture", profiles: .},
      targets: [.[] | {
        profile_id: .,
        required: true,
        status: "pass",
        duration_ms: 1000
      }],
      summary: {status: "pass"},
      paths: {run_dir: "fixture", json: "fixture"}
    }' >"$path"
}

campaigns='[]'
for index in 0 1 2 3; do
  dir="$tmp/campaign-${index}"
  mkdir -p "$dir"
  report="$dir/functional-execve-latest-kernel.json"
  make_report "$report" "ubuntu-22.04-5.15"
  report_sha="$(sha256sum "$report" | awk '{print $1}')"
  started_at="$(date -u -d "2026-08-03 03:21:00 UTC +${index} weeks" +%Y-%m-%dT%H:%M:%SZ)"
  jq -n \
    --arg workflow "Kernel-Guard/bpfcompat/.github/workflows/latest-kernel-compatibility.yml@refs/heads/main" \
    --argjson run_id "$((1000 + index))" \
    --arg commit_sha "$(printf '%040x' "$((index + 1))")" \
    --arg report_sha256 "$report_sha" \
    --arg started_at "$started_at" \
    '{
      schema_version: "v0.1",
      repository: "Kernel-Guard/bpfcompat",
      workflow: $workflow,
      event: "schedule",
      workflow_run_id: $run_id,
      workflow_run_attempt: 1,
      commit_sha: $commit_sha,
      report: "functional-execve-latest-kernel.json",
      report_sha256: $report_sha256,
      started_at: $started_at
    }' >"$dir/production-campaign.json"
  campaigns="$(jq \
    --arg metadata "campaign-${index}/production-campaign.json" \
    --arg report "campaign-${index}/functional-execve-latest-kernel.json" \
    '. + [{metadata: $metadata, report: $report}]' <<<"$campaigns")"
done

mkdir -p \
  "$tmp/falco" \
  "$tmp/candidate" \
  "$tmp/rollback" \
  "$tmp/incident" \
  "$tmp/operator"
falco_report="$tmp/falco/modern-bpf-compat.json"
make_report "$falco_report" \
  ubuntu-22.04-5.15 \
  debian-12-6.1 \
  ubuntu-24.04-6.8 \
  almalinux-8-4.18 \
  almalinux-9-5.14
candidate="$tmp/candidate/release-candidate-evidence.json"
jq -n --arg image "ghcr.io/kernel-guard/bpfcompat@sha256:$(printf 'b%.0s' {1..64})" '{
  schema_version: "v0.1",
  repository: "Kernel-Guard/bpfcompat",
  commit_sha: ("c" * 40),
  tag: "v0.4.0-rc.1",
  channel: "prerelease",
  image: $image,
  checksums_sha256: ("d" * 64),
  positive_report_sha256: ("e" * 64),
  negative_report_sha256: ("f" * 64)
}' >"$candidate"
printf '%s\n' '[bpfcompat-rollback-drill:v1] completed' >"$tmp/rollback/evidence.md"
printf '%s\n' '[bpfcompat-promotion-incident:v1] invalid promotion failed closed' >"$tmp/incident/evidence.md"
printf '%s\n' '[bpfcompat-solo-promotion:v1] ErenAri confirmed exact evidence' >"$tmp/operator/evidence.md"

canaries='[]'
for index in 0 1 2; do
  case "$index" in
    0)
      milestone="manual"
      event="workflow_dispatch"
      ;;
    1)
      milestone="t-plus-24h"
      event="schedule"
      ;;
    2)
      milestone="t-plus-72h"
      event="schedule"
      ;;
  esac
  dir="$tmp/canary-${index}"
  mkdir -p "$dir"
  jq -n \
    --arg milestone "$milestone" \
    --arg event "$event" \
    --argjson workflow_run_id "$((3000 + index))" \
    --argjson external_consumer_run_id "$((4000 + index))" \
    --arg completed_at "$(date -u -d "2026-07-30 15:05:34 UTC +$((index * (index + 1) / 2)) days" +%Y-%m-%dT%H:%M:%SZ)" \
    --arg image_digest "sha256:$(printf 'b%.0s' {1..64})" \
    '{
      schema_version: "v0.1",
      marker: "[bpfcompat-rc-canary:v1]",
      milestone: $milestone,
      event: $event,
      repository: "Kernel-Guard/bpfcompat",
      workflow_run_id: $workflow_run_id,
      external_consumer_run_id: $external_consumer_run_id,
      completed_at: $completed_at,
      version: "v0.4.0-rc.1",
      commit: ("c" * 40),
      image_digest: $image_digest,
      checks: {
        clean_install: "pass",
        source_build: "pass",
        published_action: "pass",
        container: "pass",
        external_consumers: "pass"
      },
      components: [{
        sha256: ("a" * 64),
        path: "evidence/component.json"
      }]
    }' >"$dir/release-candidate-canary.json"
  canaries="$(jq \
    --arg milestone "$milestone" \
    --arg evidence "canary-${index}/release-candidate-canary.json" \
    --arg evidence_sha256 "$(sha256sum "$dir/release-candidate-canary.json" | awk '{print $1}')" \
    '. + [{
      milestone: $milestone,
      evidence: $evidence,
      evidence_sha256: $evidence_sha256
    }]' <<<"$canaries")"
done

jq -n \
  --argjson campaigns "$campaigns" \
  --argjson canaries "$canaries" \
  --arg falco_sha "$(sha256sum "$falco_report" | awk '{print $1}')" \
  --arg candidate_sha "$(sha256sum "$candidate" | awk '{print $1}')" \
  --arg rollback_sha "$(sha256sum "$tmp/rollback/evidence.md" | awk '{print $1}')" \
  --arg incident_sha "$(sha256sum "$tmp/incident/evidence.md" | awk '{print $1}')" \
  --arg operator_sha "$(sha256sum "$tmp/operator/evidence.md" | awk '{print $1}')" \
  '{
    schema_version: "v0.1",
    release_version: "0.4.0",
    campaigns: $campaigns,
    falco: {
      workflow_run_id: 2000,
      commit_sha: ("a" * 40),
      started_at: "2026-08-03T06:00:00Z",
      report: "falco/modern-bpf-compat.json",
      report_sha256: $falco_sha
    },
    candidate: {
      evidence: "candidate/release-candidate-evidence.json",
      evidence_sha256: $candidate_sha
    },
    canaries: $canaries,
    rollback: {
      completed: true,
      evidence: "rollback/evidence.md",
      evidence_sha256: $rollback_sha
    },
    incident: {
      completed: true,
      evidence: "incident/evidence.md",
      evidence_sha256: $incident_sha
    },
    operator: {
      login: "ErenAri",
      approval_mode: "solo-maintainer",
      confirmed: true,
      evidence: "operator/evidence.md",
      evidence_sha256: $operator_sha
    }
  }' >"$tmp/input.json"

BPFCOMPAT_SKIP_READINESS_ATTESTATION=1 \
  "$script" "$tmp/input.json" "$tmp/readiness.md"
grep -Fq 'Gate status: **ready**' "$tmp/readiness.md"
grep -Fq 'Scheduled campaigns: 4' "$tmp/readiness.md"
grep -Fq 'Falco expanded vendor-kernel matrix: PASS' "$tmp/readiness.md"
grep -Fq 'RC manual, T+24h, and T+72h canaries: PASS' "$tmp/readiness.md"
grep -Fq 'Fail-closed promotion incident: PASS' "$tmp/readiness.md"
jq -e '
  .gate_status == "ready" and
  .release_version == "0.4.0" and
  .slo.campaign_count == 4 and
  .slo.infrastructure_errors == 0 and
  (.canaries | length == 3) and
  .incident.completed == true and
  .operator.login == "ErenAri" and
  .operator.approval_mode == "solo-maintainer" and
  .operator.confirmed == true
' "$tmp/readiness.json" >/dev/null

jq '.campaigns[3] = .campaigns[2]' "$tmp/input.json" >"$tmp/bad-duplicate.json"
if BPFCOMPAT_SKIP_READINESS_ATTESTATION=1 \
  "$script" "$tmp/bad-duplicate.json" "$tmp/bad.md" >/dev/null 2>&1; then
  echo "[production-readiness-test] duplicate campaign was accepted" >&2
  exit 1
fi

jq 'del(.canaries[2])' "$tmp/input.json" >"$tmp/bad-missing-canary.json"
if BPFCOMPAT_SKIP_READINESS_ATTESTATION=1 \
  "$script" "$tmp/bad-missing-canary.json" "$tmp/bad.md" >/dev/null 2>&1; then
  echo "[production-readiness-test] missing T+72h canary was accepted" >&2
  exit 1
fi

cp "$tmp/canary-1/release-candidate-canary.json" "$tmp/canary-1-valid.json"
jq '.event = "workflow_dispatch"' \
  "$tmp/canary-1/release-candidate-canary.json" >"$tmp/bad-canary.json"
mv "$tmp/bad-canary.json" "$tmp/canary-1/release-candidate-canary.json"
bad_canary_sha="$(sha256sum "$tmp/canary-1/release-candidate-canary.json" | awk '{print $1}')"
jq --arg sha "$bad_canary_sha" \
  '.canaries[1].evidence_sha256 = $sha' \
  "$tmp/input.json" >"$tmp/bad-canary-event.json"
if BPFCOMPAT_SKIP_READINESS_ATTESTATION=1 \
  "$script" "$tmp/bad-canary-event.json" "$tmp/bad.md" >/dev/null 2>&1; then
  echo "[production-readiness-test] non-scheduled T+24h canary was accepted" >&2
  exit 1
fi
mv "$tmp/canary-1-valid.json" "$tmp/canary-1/release-candidate-canary.json"

cp "$tmp/incident/evidence.md" "$tmp/incident-valid.md"
printf '%s\n' 'incident marker missing' >"$tmp/incident/evidence.md"
bad_incident_sha="$(sha256sum "$tmp/incident/evidence.md" | awk '{print $1}')"
jq --arg sha "$bad_incident_sha" \
  '.incident.evidence_sha256 = $sha' \
  "$tmp/input.json" >"$tmp/bad-incident.json"
if BPFCOMPAT_SKIP_READINESS_ATTESTATION=1 \
  "$script" "$tmp/bad-incident.json" "$tmp/bad.md" >/dev/null 2>&1; then
  echo "[production-readiness-test] unmarked incident evidence was accepted" >&2
  exit 1
fi
mv "$tmp/incident-valid.md" "$tmp/incident/evidence.md"

jq '.targets[0].infra_error = "fixture failure" | .targets[0].status = "infra_error"' \
  "$tmp/campaign-3/functional-execve-latest-kernel.json" >"$tmp/bad-report.json"
mv "$tmp/bad-report.json" "$tmp/campaign-3/functional-execve-latest-kernel.json"
new_sha="$(sha256sum "$tmp/campaign-3/functional-execve-latest-kernel.json" | awk '{print $1}')"
jq --arg sha "$new_sha" '.report_sha256 = $sha' \
  "$tmp/campaign-3/production-campaign.json" >"$tmp/metadata.json"
mv "$tmp/metadata.json" "$tmp/campaign-3/production-campaign.json"
if BPFCOMPAT_SKIP_READINESS_ATTESTATION=1 \
  "$script" "$tmp/input.json" "$tmp/bad.md" >/dev/null 2>&1; then
  echo "[production-readiness-test] infrastructure error was accepted" >&2
  exit 1
fi

echo "[production-readiness-test] PASS"
