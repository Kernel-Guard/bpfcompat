#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${ROOT_DIR}/scripts/production-readiness-report.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

VALIDATOR_SHA="$(printf '7%.0s' {1..64})"
CLI_SHA="$(printf '8%.0s' {1..64})"

make_report() {
  local path="$1" run_id="$2" started_at="$3"
  shift 3
  jq -n --args '$ARGS.positional' "$@" |
    jq --arg run_id "$run_id" --arg started_at "$started_at" --arg validator "$VALIDATOR_SHA" '{
      schema_version: "v0.1",
      run: {id: $run_id, started_at: $started_at},
      artifact: {path: "fixture", basename: "fixture", sha256: ("a" * 64), size_bytes: 1},
      validator: {basename: "bpfcompat-validator", sha256: $validator, size_bytes: 1},
      matrix: {path: "fixture", profiles: .},
      targets: [.[] | {
        profile_id: .,
        required: true,
        status: "pass",
        started_at: $started_at,
        duration_ms: 1000
      }],
      summary: {status: "pass"},
      paths: {run_dir: "fixture", json: "fixture"}
    }' >"$path"
}

mkdir -p \
  "$tmp/falco" \
  "$tmp/candidate" \
  "$tmp/rollback" \
  "$tmp/incident" \
  "$tmp/operator"
falco_report="$tmp/falco/modern-bpf-compat.json"
make_report "$falco_report" falco-run "2026-08-03T06:00:00Z" \
  ubuntu-22.04-5.15 \
  debian-12-6.1 \
  ubuntu-24.04-6.8 \
  almalinux-8-4.18 \
  almalinux-9-5.14
printf '%s  bpfcompat-linux-amd64\n%s  bpfcompat-validator-static-linux-amd64\n' \
  "$CLI_SHA" "$VALIDATOR_SHA" >"$tmp/candidate/SHA256SUMS"
CHECKSUMS_SHA="$(sha256sum "$tmp/candidate/SHA256SUMS" | awk '{print $1}')"
candidate="$tmp/candidate/release-candidate-evidence.json"
jq -n --arg checksums "$CHECKSUMS_SHA" --arg image "ghcr.io/kernel-guard/bpfcompat@sha256:$(printf 'b%.0s' {1..64})" '{
  schema_version: "v0.1",
  repository: "Kernel-Guard/bpfcompat",
  commit_sha: ("c" * 40),
  tag: "v0.4.0-rc.1",
  channel: "prerelease",
  image: $image,
  checksums_sha256: $checksums,
  positive_report_sha256: ("e" * 64),
  negative_report_sha256: ("f" * 64),
  generated_at: "2026-07-30T14:00:00Z"
}' >"$candidate"
CANDIDATE_SHA="$(sha256sum "$candidate" | awk '{print $1}')"
campaigns='[]'
for index in 0 1 2 3; do
  dir="$tmp/campaign-${index}"
  mkdir -p "$dir"
  report="$dir/functional-execve-latest-kernel.json"
  started_at="$(date -u -d "2026-08-03 03:21:00 UTC +${index} weeks" +%Y-%m-%dT%H:%M:%SZ)"
  make_report "$report" "campaign-report-${index}" "$started_at" "ubuntu-22.04-5.15"
  report_sha="$(sha256sum "$report" | awk '{print $1}')"
  jq -n \
    --arg workflow "Kernel-Guard/bpfcompat/.github/workflows/latest-kernel-compatibility.yml@refs/heads/main" \
    --argjson run_id "$((1000 + index))" \
    --arg workflow_sha "$(printf '%040x' "$((index + 1))")" \
    --arg report_sha256 "$report_sha" \
    --arg report_run_id "campaign-report-${index}" \
    --arg started_at "$started_at" \
    --arg checksums "$CHECKSUMS_SHA" \
    --arg evidence "$CANDIDATE_SHA" \
    --arg cli "$CLI_SHA" \
    --arg validator "$VALIDATOR_SHA" \
    '{
      schema_version: "v0.2",
      marker: "[bpfcompat-campaign:v2]",
      repository: "Kernel-Guard/bpfcompat",
      workflow: $workflow,
      workflow_sha: $workflow_sha,
      event: "schedule",
      workflow_run_id: $run_id,
      workflow_run_attempt: 1,
      candidate: {
        tag: "v0.4.0-rc.1",
        commit_sha: ("c" * 40),
        checksums_sha256: $checksums,
        candidate_evidence_sha256: $evidence
      },
      executed: {cli_sha256: $cli, validator_sha256: $validator},
      report: "functional-execve-latest-kernel.json",
      report_sha256: $report_sha256,
      report_run_id: $report_run_id,
      started_at: $started_at
    }' >"$dir/production-campaign.json"
  campaigns="$(jq \
    --arg metadata "campaign-${index}/production-campaign.json" \
    --arg report "campaign-${index}/functional-execve-latest-kernel.json" \
    '. + [{metadata: $metadata, report: $report}]' <<<"$campaigns")"
done

CANDIDATE_DIGEST="sha256:$(printf 'b%.0s' {1..64})"
KNOWN_GOOD_DIGEST="sha256:$(printf 'd%.0s' {1..64})"
# write_rollback_note <candidate digest> <alias tag> <final digest> <completed>:
# the exact evidence.md layout written by .github/workflows/rollback-drill.yml.
write_rollback_note() {
  cat >"$tmp/rollback/evidence.md" <<NOTE
# bpfcompat Release-Promotion Rollback Drill

[bpfcompat-rollback-drill:v1]

- Operator: \`ErenAri\`
- Workflow run: \`5000\`
- Completed: \`$4\`
- Drill alias: \`ghcr.io/kernel-guard/bpfcompat:rollback-drill-$2\`
- Known-good digest: \`${KNOWN_GOOD_DIGEST}\`
- Candidate digest: \`$1\`
- Final digest: \`$3\`
- Promotion elapsed: \`2222 ms\`
- Recovery elapsed: \`3327 ms\`
- Signature verification: PASS
- SLSA v1 provenance verification: PASS
- Embedded version verification: PASS
- Protected \`latest\` alias unchanged: \`${KNOWN_GOOD_DIGEST}\`
NOTE
}
write_rollback_note "$CANDIDATE_DIGEST" v0.4.0-rc.1 "$KNOWN_GOOD_DIGEST" 2026-07-30T16:00:00Z
cat >"$tmp/incident/evidence.md" <<'NOTE'
# fail-closed promotion incident drill (candidate v0.4.0-rc.1)

[bpfcompat-promotion-incident:v1]

- Workflow: `promote-release.yml` dispatched on `refs/tags/v0.4.0-rc.1`
- Rejected run: https://github.com/Kernel-Guard/bpfcompat/actions/runs/6000
- Deliberate fault: wrong confirmation text; the promotion failed closed.
NOTE
printf '%s\n' "[bpfcompat-solo-promotion:v1] ErenAri confirmed exact evidence; candidate evidence ${CANDIDATE_SHA}" \
  >"$tmp/operator/evidence.md"

# write_canary_components <canary dir> <run id> <external run id>: the five
# per-check component records the canary workflow downloads into
# evidence/components/rc*-canary-component-<check>-<run id>/; prints the
# manifest's components array.
write_canary_components() {
  local dir="$1" run="$2" external="$3" components='[]' check file
  for check in clean-install source-build published-action container external-consumers; do
    file="components/rc1-canary-component-${check}-${run}/${check}.json"
    [[ "$check" == published-action ]] &&
      file="components/rc1-canary-component-${check}-${run}/evidence/${check}.json"
    mkdir -p "$dir/$(dirname "$file")"
    jq -n --arg check "$check" --arg digest "$CANDIDATE_DIGEST" --argjson external "$external" '
      {check: $check, status: "pass", version: "v0.4.0-rc.1", commit: ("c" * 40)} +
      (if $check == "container" then {digest: $digest} else {} end) +
      (if $check == "external-consumers" then {workflow_run_id: $external} else {} end)
    ' >"$dir/$file"
    components="$(jq --arg sha "$(sha256sum "$dir/$file" | awk '{print $1}')" --arg path "evidence/$file" \
      '. + [{sha256: $sha, path: $path}]' <<<"$components")"
  done
  printf '%s\n' "$components"
}

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
    --arg image_digest "$CANDIDATE_DIGEST" \
    --argjson components "$(write_canary_components "$dir" "$((3000 + index))" "$((4000 + index))")" \
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
      components: $components
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
      evidence_sha256: $candidate_sha,
      checksums: "candidate/SHA256SUMS"
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
  .operator.confirmed == true and
  .falco.started_at == "2026-08-03T06:00:00Z" and .falco.candidate_bound == true and
  .falco.run_identity == "operator-asserted" and
  .rollback.candidate_bound == true and .rollback.workflow_run_id == 5000 and
  .incident.candidate_bound == true and .incident.promotion_run_id == 6000 and
  ([.canaries[].components_verified] | all) and
  ([.canaries[].minutes_after_candidate_generated] == [65, 1505, 4385])
' "$tmp/readiness.json" >/dev/null || {
  echo "[production-readiness-test] readiness output does not record the evidence bindings" >&2; exit 1; }

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

cp "$tmp/campaign-3/functional-execve-latest-kernel.json" "$tmp/infra-report.keep"
cp "$tmp/campaign-3/production-campaign.json" "$tmp/infra-meta.keep"
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
mv "$tmp/infra-report.keep" "$tmp/campaign-3/functional-execve-latest-kernel.json"
mv "$tmp/infra-meta.keep" "$tmp/campaign-3/production-campaign.json"


# --- Campaign <-> candidate binding (fail closed) -----------------------------
expect_refused() { # <label> <manifest> <message fragment>
  local out
  if out="$(BPFCOMPAT_SKIP_READINESS_ATTESTATION=1 "$script" "$2" "$tmp/bad.md" 2>&1)"; then
    echo "[production-readiness-test] $1 was accepted" >&2
    exit 1
  fi
  grep -Fq -- "$3" <<<"$out" || {
    echo "[production-readiness-test] $1 refused for the wrong reason: $out" >&2
    exit 1
  }
  echo "[production-readiness-test] refused: $1"
}
# mutate_campaign <index> <jq filter>: rewrite one campaign's metadata (its own
# hash is not pinned by the manifest; the report hash inside it is).
mutate_campaign() {
  cp "$tmp/campaign-$1/production-campaign.json" "$tmp/campaign-$1.keep"
  jq "$2" "$tmp/campaign-$1.keep" >"$tmp/campaign-$1/production-campaign.json"
}
restore_campaign() { mv "$tmp/campaign-$1.keep" "$tmp/campaign-$1/production-campaign.json"; }

mutate_campaign 2 '.candidate.commit_sha = ("e" * 40)'
expect_refused "a campaign that tested another commit" "$tmp/input.json" "did not test release candidate"
restore_campaign 2

mutate_campaign 1 '.candidate.tag = "v0.4.0-rc.2"'
expect_refused "a campaign that tested another RC tag" "$tmp/input.json" "did not test release candidate"
restore_campaign 1

mutate_campaign 0 '.candidate.candidate_evidence_sha256 = ("0" * 64)'
expect_refused "a campaign bound to different candidate evidence" "$tmp/input.json" "did not test release candidate"
restore_campaign 0

mutate_campaign 3 '.executed.cli_sha256 = ("1" * 64)'
expect_refused "a campaign that ran a CLI not in the candidate SHA256SUMS" "$tmp/input.json" "did not test release candidate"
restore_campaign 3

mutate_campaign 3 '.candidate = null | .executed = null'
expect_refused "an unbound campaign (no designated candidate)" "$tmp/input.json" "did not test release candidate"
restore_campaign 3

# Historical v0.1 evidence -- main's GITHUB_SHA only -- can never be relabelled.
mutate_campaign 0 '{schema_version: "v0.1", repository, workflow, event, workflow_run_id, workflow_run_attempt,
  commit_sha: .workflow_sha, report, report_sha256, started_at}'
expect_refused "historical v0.1 campaign evidence" "$tmp/input.json" "is not scheduled v0.2 evidence"
restore_campaign 0

mutate_campaign 0 '.schema_version = "v0.1"'
expect_refused "v0.2-shaped evidence labelled v0.1" "$tmp/input.json" "is not scheduled v0.2 evidence"
restore_campaign 0

mutate_campaign 2 '.workflow ="Kernel-Guard/bpfcompat/.github/workflows/latest-kernel-compatibility.yml@refs/heads/feature"'
expect_refused "a campaign from a non-default-branch workflow" "$tmp/input.json" "is not scheduled v0.2 evidence"
restore_campaign 2

# Substituted report: a different run's report whose bytes the metadata pins.
cp "$tmp/campaign-1/functional-execve-latest-kernel.json" "$tmp/report-1.keep"
jq '.run.id = "some-other-run"' "$tmp/report-1.keep" >"$tmp/campaign-1/functional-execve-latest-kernel.json"
cp "$tmp/campaign-1/production-campaign.json" "$tmp/campaign-1.keep"
jq --arg sha "$(sha256sum "$tmp/campaign-1/functional-execve-latest-kernel.json" | awk '{print $1}')" \
  '.report_sha256 = $sha' "$tmp/campaign-1.keep" >"$tmp/campaign-1/production-campaign.json"
expect_refused "a substituted report from another run" "$tmp/input.json" "is not this campaign's run"
restore_campaign 1
mv "$tmp/report-1.keep" "$tmp/campaign-1/functional-execve-latest-kernel.json"

# A report whose own validator record is not the candidate's validator, even
# though the metadata claims the candidate's.
cp "$tmp/campaign-3/functional-execve-latest-kernel.json" "$tmp/report-3.keep"
jq '.validator.sha256 = ("2" * 64)' "$tmp/report-3.keep" >"$tmp/campaign-3/functional-execve-latest-kernel.json"
cp "$tmp/campaign-3/production-campaign.json" "$tmp/campaign-3.keep"
jq --arg sha "$(sha256sum "$tmp/campaign-3/functional-execve-latest-kernel.json" | awk '{print $1}')" \
  '.report_sha256 = $sha' "$tmp/campaign-3.keep" >"$tmp/campaign-3/production-campaign.json"
expect_refused "a report that ran a different validator" "$tmp/input.json" "is not this campaign's run"
restore_campaign 3
mv "$tmp/report-3.keep" "$tmp/campaign-3/functional-execve-latest-kernel.json"

# Wrong or missing candidate evidence.
jq '.candidate.evidence_sha256 = ("0" * 64)' "$tmp/input.json" >"$tmp/bad-candidate-sha.json"
expect_refused "candidate evidence with the wrong digest" "$tmp/bad-candidate-sha.json" "SHA-256 mismatch"
jq 'del(.candidate.checksums)' "$tmp/input.json" >"$tmp/bad-no-sums.json"
expect_refused "a manifest without the candidate SHA256SUMS" "$tmp/bad-no-sums.json" "manifest schema or required gates are invalid"
cp "$tmp/candidate/SHA256SUMS" "$tmp/sums.keep"
printf '%s  bpfcompat-linux-amd64\n' "$(printf '9%.0s' {1..64})" >>"$tmp/candidate/SHA256SUMS"
expect_refused "a substituted candidate SHA256SUMS" "$tmp/input.json" "SHA-256 mismatch for SHA256SUMS"
mv "$tmp/sums.keep" "$tmp/candidate/SHA256SUMS"

# A campaign that started before the candidate existed.
cp "$candidate" "$tmp/candidate.keep"
jq '.generated_at = "2026-08-20T00:00:00Z"' "$tmp/candidate.keep" >"$candidate"
jq --arg sha "$(sha256sum "$candidate" | awk '{print $1}')" '.candidate.evidence_sha256 = $sha' \
  "$tmp/input.json" >"$tmp/bad-late-candidate.json"
for i in 0 1 2 3; do
  cp "$tmp/campaign-$i/production-campaign.json" "$tmp/campaign-$i.keep"
  jq --arg sha "$(sha256sum "$candidate" | awk '{print $1}')" '.candidate.candidate_evidence_sha256 = $sha' \
    "$tmp/campaign-$i.keep" >"$tmp/campaign-$i/production-campaign.json"
done
expect_refused "campaigns that predate the candidate" "$tmp/bad-late-candidate.json" "started before release candidate"
for i in 0 1 2 3; do restore_campaign "$i"; done
mv "$tmp/candidate.keep" "$candidate"

# --- Non-campaign evidence binding (fail closed) -------------------------------
# rehash <file> <manifest jq path> <out manifest>: a manifest that pins the
# current bytes of <file>, as an operator assembling the directory would.
rehash() {
  jq --arg sha "$(sha256sum "$1" | awk '{print $1}')" "$2 = \$sha" "$tmp/input.json" >"$3"
}
keep() { cp "$1" "$1.keep"; }
restore() { mv "$1.keep" "$1"; }

# Falco: started_at is the report's own run.started_at, after the candidate.
jq '.falco.started_at = "2020-01-01T00:00:00Z" | .falco.workflow_run_id = 1' \
  "$tmp/input.json" >"$tmp/bad-falco-start.json"
expect_refused "a Falco start time that is not the report's" "$tmp/bad-falco-start.json" \
  "Falco started_at does not match the report's run.started_at"
keep "$falco_report"
jq '.run.started_at = "2026-07-30T13:59:59Z"' "$falco_report.keep" >"$falco_report"
rehash "$falco_report" .falco.report_sha256 "$tmp/bad-falco-early.json"
jq '.falco.started_at = "2026-07-30T13:59:59Z"' "$tmp/bad-falco-early.json" >"$tmp/bad-falco-early2.json"
expect_refused "a Falco run that predates the candidate" "$tmp/bad-falco-early2.json" \
  "Falco run started before release candidate"
jq 'del(.run.started_at)' "$falco_report.keep" >"$falco_report"
rehash "$falco_report" .falco.report_sha256 "$tmp/bad-falco-nostart.json"
expect_refused "a Falco report without a run start" "$tmp/bad-falco-nostart.json" \
  "Falco started_at does not match the report's run.started_at"
# run.started_at is written when the report is assembled, after the targets
# ran: a run whose first target predates the candidate must not pass on it.
jq '.targets[0].started_at = "2026-07-30T13:59:59Z"' "$falco_report.keep" >"$falco_report"
rehash "$falco_report" .falco.report_sha256 "$tmp/bad-falco-early-target.json"
expect_refused "a Falco run whose first target predates the candidate" "$tmp/bad-falco-early-target.json" \
  "Falco run started before release candidate"
jq 'del(.targets[2].started_at)' "$falco_report.keep" >"$falco_report"
rehash "$falco_report" .falco.report_sha256 "$tmp/bad-falco-target-nostart.json"
expect_refused "a Falco report whose required target has no start time" "$tmp/bad-falco-target-nostart.json" \
  "Falco report has a target that ran without started_at"
# Shaped like a real report: targets start minutes before run.started_at, all
# after the candidate; an optional profile the runner never booted
# ("unsupported", no started_at) does not count.
jq '.targets |= map(.started_at = "2026-08-03T05:50:00Z") |
    .targets += [{profile_id: "talos-1.7", required: false, status: "unsupported", duration_ms: 0}]' \
  "$falco_report.keep" >"$falco_report"
rehash "$falco_report" .falco.report_sha256 "$tmp/good-falco-real-shape.json"
if BPFCOMPAT_SKIP_READINESS_ATTESTATION=1 "$script" "$tmp/good-falco-real-shape.json" "$tmp/good.md" >"$tmp/falco-real-shape.log" 2>&1; then
  echo "[production-readiness-test] accepted: a real-shaped Falco report with an unbooted optional profile"
else
  cat "$tmp/falco-real-shape.log" >&2
  echo "[production-readiness-test] a real-shaped Falco report with an unbooted optional profile was refused" >&2
  exit 1
fi
restore "$falco_report"

# Rollback: alias, drilled digest and recovery are this candidate's.
rollback_note="$tmp/rollback/evidence.md"
keep "$rollback_note"
write_rollback_note "sha256:$(printf '4%.0s' {1..64})" v0.4.0-rc.1 "$KNOWN_GOOD_DIGEST" 2026-07-30T16:00:00Z
rehash "$rollback_note" .rollback.evidence_sha256 "$tmp/bad-rollback.json"
expect_refused "a rollback drill of another image digest" "$tmp/bad-rollback.json" "rollback drill exercised"
write_rollback_note "$CANDIDATE_DIGEST" v0.3.8-rc.2 "$KNOWN_GOOD_DIGEST" 2026-07-30T16:00:00Z
rehash "$rollback_note" .rollback.evidence_sha256 "$tmp/bad-rollback.json"
expect_refused "a rollback drill on another candidate's alias" "$tmp/bad-rollback.json" "rollback drill alias"
write_rollback_note "$CANDIDATE_DIGEST" v0.4.0-rc.1 "$CANDIDATE_DIGEST" 2026-07-30T16:00:00Z
rehash "$rollback_note" .rollback.evidence_sha256 "$tmp/bad-rollback.json"
expect_refused "a rollback drill that never recovered" "$tmp/bad-rollback.json" "did not end on a distinct known-good digest"
write_rollback_note "$CANDIDATE_DIGEST" v0.4.0-rc.1 "$KNOWN_GOOD_DIGEST" 2026-07-30T13:00:00Z
rehash "$rollback_note" .rollback.evidence_sha256 "$tmp/bad-rollback.json"
expect_refused "a rollback drill that predates the candidate" "$tmp/bad-rollback.json" "rollback drill completed before"
printf '%s\n' '[bpfcompat-rollback-drill:v1]' >"$rollback_note"
rehash "$rollback_note" .rollback.evidence_sha256 "$tmp/bad-rollback.json"
expect_refused "a marker-only rollback note" "$tmp/bad-rollback.json" "must contain exactly one"
restore "$rollback_note"

# Incident: names the rejected promote-release run; another candidate's
# fail-closed drill stays acceptable but is recorded as not candidate-bound.
incident_note="$tmp/incident/evidence.md"
keep "$incident_note"
printf '%s\n' '[bpfcompat-promotion-incident:v1]' >"$incident_note"
rehash "$incident_note" .incident.evidence_sha256 "$tmp/bad-incident-bare.json"
expect_refused "a marker-only incident note" "$tmp/bad-incident-bare.json" "does not name the promote-release workflow"
printf '%s\n' '[bpfcompat-promotion-incident:v1] promote-release failed closed' >"$incident_note"
rehash "$incident_note" .incident.evidence_sha256 "$tmp/bad-incident-norun.json"
expect_refused "an incident note without the rejected run" "$tmp/bad-incident-norun.json" "does not link the rejected promote-release run"
sed 's/v0\.4\.0-rc\.1/v0.3.8-rc.2/g' "$incident_note.keep" >"$incident_note"
rehash "$incident_note" .incident.evidence_sha256 "$tmp/other-incident.json"
BPFCOMPAT_SKIP_READINESS_ATTESTATION=1 "$script" "$tmp/other-incident.json" "$tmp/other-incident-out.md" >/dev/null
jq -e '.incident.candidate_bound == false and .incident.promotion_run_id == 6000' "$tmp/other-incident-out.json" >/dev/null || {
  echo "[production-readiness-test] an earlier candidate's incident is not recorded as candidate_bound=false" >&2; exit 1; }
echo "[production-readiness-test] accepted and recorded: an earlier candidate's fail-closed incident (candidate_bound=false)"
restore "$incident_note"

# Canaries: observation floors, order, and run-bound component records.
canary1="$tmp/canary-1/release-candidate-canary.json"
canary2="$tmp/canary-2/release-candidate-canary.json"
keep "$canary1"
jq '.completed_at = "2020-01-01T00:00:00Z"' "$canary1.keep" >"$canary1"
rehash "$canary1" '.canaries[1].evidence_sha256' "$tmp/bad-canary-time.json"
expect_refused "a T+24h canary before the candidate existed" "$tmp/bad-canary-time.json" "RC canary t-plus-24h completed before 20h"
jq '.completed_at = "2026-07-31T09:59:59Z"' "$canary1.keep" >"$canary1"
rehash "$canary1" '.canaries[1].evidence_sha256' "$tmp/bad-canary-time.json"
expect_refused "a T+24h canary under 20h after the candidate" "$tmp/bad-canary-time.json" "RC canary t-plus-24h completed before 20h"
jq '.completed_at = "2026-08-03T00:00:00Z"' "$canary1.keep" >"$canary1"
rehash "$canary1" '.canaries[1].evidence_sha256' "$tmp/bad-canary-time.json"
expect_refused "canaries out of milestone order" "$tmp/bad-canary-time.json" "must complete in manual, T+24h, T+72h order"
jq '.components[0].path |= sub("-3001/"; "-9999/")' "$canary1.keep" >"$canary1"
rehash "$canary1" '.canaries[1].evidence_sha256' "$tmp/bad-canary-component.json"
expect_refused "a canary component from another run" "$tmp/bad-canary-component.json" "are not artifacts of run 3001"
jq 'del(.components[] | select(.path | endswith("/external-consumers.json")))' "$canary1.keep" >"$canary1"
rehash "$canary1" '.canaries[1].evidence_sha256' "$tmp/bad-canary-component.json"
expect_refused "a canary missing its external-consumers record" "$tmp/bad-canary-component.json" "must record exactly one external-consumers.json"
restore "$canary1"
container_component="$(find "$tmp/canary-2/components" -name container.json)"
keep "$container_component"
jq '.digest = ("sha256:" + ("4" * 64))' "$container_component.keep" >"$container_component"
expect_refused "a canary component whose bytes changed" "$tmp/input.json" "SHA-256 mismatch for container.json"
keep "$canary2"
jq --arg sha "$(sha256sum "$container_component" | awk '{print $1}')" \
  '(.components[] | select(.path | endswith("/container.json")) | .sha256) = $sha' "$canary2.keep" >"$canary2"
rehash "$canary2" '.canaries[2].evidence_sha256' "$tmp/bad-canary-container.json"
expect_refused "a canary container check of another image" "$tmp/bad-canary-container.json" "container component does not record a pass of v0.4.0-rc.1"
restore "$canary2"
restore "$container_component"

# Multi-document JSON: `jq -e` judges only the last value, so a failing record
# followed by a passing one must not pass.
keep "$container_component"
keep "$canary2"
{ jq '.status = "fail" | .digest = ("sha256:" + ("4" * 64))' "$container_component.keep"; cat "$container_component.keep"; } \
  >"$container_component"
jq --arg sha "$(sha256sum "$container_component" | awk '{print $1}')" \
  '(.components[] | select(.path | endswith("/container.json")) | .sha256) = $sha' "$canary2.keep" >"$canary2"
rehash "$canary2" '.canaries[2].evidence_sha256' "$tmp/bad-multidoc.json"
expect_refused "a failing component record followed by a passing one" "$tmp/bad-multidoc.json" "must be exactly one JSON object: container.json"
restore "$canary2"
restore "$container_component"
keep "$canary1"
{ jq '.checks.container = "fail"' "$canary1.keep"; cat "$canary1.keep"; } >"$canary1"
rehash "$canary1" '.canaries[1].evidence_sha256' "$tmp/bad-multidoc.json"
expect_refused "a failing canary manifest followed by a passing one" "$tmp/bad-multidoc.json" "must be exactly one JSON object: release-candidate-canary.json"
restore "$canary1"
keep "$falco_report"
{ jq '.summary.status = "fail"' "$falco_report.keep"; cat "$falco_report.keep"; } >"$falco_report"
rehash "$falco_report" .falco.report_sha256 "$tmp/bad-multidoc.json"
expect_refused "a failing Falco report followed by a passing one" "$tmp/bad-multidoc.json" "must be exactly one JSON object: modern-bpf-compat.json"
restore "$falco_report"
{ cat "$tmp/input.json"; cat "$tmp/input.json"; } >"$tmp/bad-multidoc-input.json"
expect_refused "a multi-document input manifest" "$tmp/bad-multidoc-input.json" "the input manifest must be exactly one JSON object"

# Incident: exactly one linked run, so the rejected run is unambiguous.
keep "$incident_note"
cat "$incident_note.keep" >"$incident_note"
printf '%s\n' '- Successful retry: https://github.com/Kernel-Guard/bpfcompat/actions/runs/6001' >>"$incident_note"
rehash "$incident_note" .incident.evidence_sha256 "$tmp/bad-incident-tworuns.json"
expect_refused "an incident note linking two runs" "$tmp/bad-incident-tworuns.json" "links more than one workflow run"
restore "$incident_note"

# Operator: the confirmation names the exact candidate evidence.
operator_note="$tmp/operator/evidence.md"
keep "$operator_note"
printf '%s\n' '[bpfcompat-solo-promotion:v1] ErenAri confirmed exact evidence' >"$operator_note"
rehash "$operator_note" .operator.evidence_sha256 "$tmp/bad-operator.json"
expect_refused "an operator confirmation not bound to the candidate evidence" "$tmp/bad-operator.json" "operator evidence does not name candidate evidence SHA-256"
printf '%s\n' "[bpfcompat-solo-promotion:v1] ErenAri confirmed evidence 0${CANDIDATE_SHA}" >"$operator_note"
rehash "$operator_note" .operator.evidence_sha256 "$tmp/bad-operator.json"
expect_refused "an operator note with the digest inside a longer hex string" "$tmp/bad-operator.json" "operator evidence does not name candidate evidence SHA-256"
restore "$operator_note"

# --- Attestation path, without the test bypass ---------------------------------
# gh stub: every verification is logged; campaign attestations report the
# invocation in $STUB_INVOCATION_RUN (default: the campaign's own run).
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == attestation && "$2" == --help ]] && exit 0
# Workflow run lookups: run 5000 is the rollback drill and 6000 the rejected
# promotion; STUB_* variables override their fields, any other run is a 404.
if [[ "$1" == api && "$2" =~ ^repos/Kernel-Guard/bpfcompat/actions/runs/([0-9]+)$ ]]; then
  printf '%s\n' "$*" >>"$STUB_LOG"
  case "${BASH_REMATCH[1]}" in
    5000) jq -n --arg p "${STUB_ROLLBACK_PATH:-.github/workflows/rollback-drill.yml}" \
            --arg b "${STUB_ROLLBACK_BRANCH:-main}" --arg c "${STUB_ROLLBACK_CONCLUSION:-success}" \
            --arg e "${STUB_ROLLBACK_EVENT:-workflow_dispatch}" --arg r "${STUB_ROLLBACK_REPO:-Kernel-Guard/bpfcompat}" \
            --arg s "${STUB_ROLLBACK_STARTED:-2026-07-30T15:55:00Z}" --arg u "${STUB_ROLLBACK_UPDATED:-2026-07-30T16:01:00Z}" \
            '{path: $p, head_branch: $b, event: $e, head_repository: {full_name: $r},
              run_started_at: $s, updated_at: $u, status: "completed", conclusion: $c}' ;;
    6000) jq -n --arg p "${STUB_INCIDENT_PATH:-.github/workflows/promote-release.yml}" \
            --arg c "${STUB_INCIDENT_CONCLUSION:-failure}" --arg e "${STUB_INCIDENT_EVENT:-workflow_dispatch}" \
            --arg r "${STUB_INCIDENT_REPO:-Kernel-Guard/bpfcompat}" \
            '{path: $p, head_branch: "v0.4.0-rc.1", event: $e, head_repository: {full_name: $r},
              status: "completed", conclusion: $c}' ;;
    *) echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;
  esac
  exit 0
fi
[[ "$1 $2" == "attestation verify" ]] || { echo "unexpected gh $*" >&2; exit 99; }
printf '%s\n' "$*" >>"$STUB_LOG"
[[ -n "${STUB_FAIL:-}" && "$3" == *"$STUB_FAIL"* ]] && exit 1
if [[ "$*" == *latest-kernel-compatibility.yml* ]]; then
  run="$(jq -r .workflow_run_id "$3")"
  attempt="$(jq -r .workflow_run_attempt "$3")"
  jq -n --arg inv "https://github.com/Kernel-Guard/bpfcompat/actions/runs/${STUB_INVOCATION_RUN:-$run}/attempts/$attempt" \
    --arg event "${STUB_EVENT:-schedule}" \
    '[{verificationResult: {statement: {predicate: {
       runDetails: {metadata: {invocationId: $inv}},
       buildDefinition: {internalParameters: {github: {event_name: $event}}}}}}}]'
fi
STUB
chmod +x "$tmp/bin/gh"
: >"$tmp/gh.log"
PATH="$tmp/bin:$PATH" STUB_LOG="$tmp/gh.log" "$script" "$tmp/input.json" "$tmp/attested.md" >/dev/null
grep -Fq -- "--source-digest $(printf 'c%.0s' {1..40}) --source-ref refs/tags/v0.4.0-rc.1" "$tmp/gh.log" || {
  echo "[production-readiness-test] candidate attestation is not bound to its tag and commit" >&2; exit 1; }
for i in 1 2 3 4; do
  grep -Fq -- "--signer-workflow Kernel-Guard/bpfcompat/.github/workflows/latest-kernel-compatibility.yml --source-digest $(printf '%040x' "$i") --source-ref refs/heads/main" "$tmp/gh.log" || {
    echo "[production-readiness-test] campaign $i attestation is not bound to its workflow source" >&2; exit 1; }
done
echo "[production-readiness-test] attested: candidate and four campaigns verified with exact bindings"
if PATH="$tmp/bin:$PATH" STUB_LOG="$tmp/gh.log" STUB_FAIL=campaign-2/ "$script" "$tmp/input.json" "$tmp/bad.md" >/dev/null 2>&1; then
  echo "[production-readiness-test] an unattested campaign was accepted" >&2; exit 1
fi
echo "[production-readiness-test] refused: an unattested campaign"
if PATH="$tmp/bin:$PATH" STUB_LOG="$tmp/gh.log" STUB_INVOCATION_RUN=999999 "$script" "$tmp/input.json" "$tmp/bad.md" >/dev/null 2>&1; then
  echo "[production-readiness-test] an attestation from another run was accepted" >&2; exit 1
fi
echo "[production-readiness-test] refused: campaign evidence attested by a different run"
if PATH="$tmp/bin:$PATH" STUB_LOG="$tmp/gh.log" STUB_EVENT=workflow_dispatch "$script" "$tmp/input.json" "$tmp/bad.md" >/dev/null 2>&1; then
  echo "[production-readiness-test] a dispatched run relabelled as scheduled was accepted" >&2; exit 1
fi
echo "[production-readiness-test] refused: evidence claiming schedule whose attestation shows workflow_dispatch"
grep -Fq "api repos/Kernel-Guard/bpfcompat/actions/runs/5000" "$tmp/gh.log" &&
  grep -Fq "api repos/Kernel-Guard/bpfcompat/actions/runs/6000" "$tmp/gh.log" || {
  echo "[production-readiness-test] the drill and incident runs were not looked up" >&2; exit 1; }
# Written policy: the rollback note comes from a rollback-drill.yml run and the
# incident links the rejected promote-release run. Both must be real runs.
for case in \
  "STUB_ROLLBACK_PATH=.github/workflows/ci.yml|a rollback drill run that is another workflow" \
  "STUB_ROLLBACK_CONCLUSION=failure|a rollback drill run that did not succeed" \
  "STUB_ROLLBACK_BRANCH=feature|a rollback drill run not on main" \
  "STUB_ROLLBACK_REPO=someone/bpfcompat|a rollback drill run from a fork" \
  "STUB_ROLLBACK_EVENT=pull_request|a rollback drill run that was not dispatched" \
  "STUB_ROLLBACK_STARTED=2026-07-30T13:00:00Z|a rollback drill run that started before the candidate" \
  "STUB_ROLLBACK_UPDATED=2026-07-30T15:59:00Z|a rollback note whose completion is outside its run" \
  "STUB_INCIDENT_REPO=someone/bpfcompat|an incident linking a run from a fork" \
  "STUB_INCIDENT_PATH=.github/workflows/ci.yml|an incident linking a run of another workflow" \
  "STUB_INCIDENT_CONCLUSION=success|an incident linking a promotion that succeeded"; do
  if env "${case%%|*}" PATH="$tmp/bin:$PATH" STUB_LOG="$tmp/gh.log" "$script" "$tmp/input.json" "$tmp/bad.md" >/dev/null 2>&1; then
    echo "[production-readiness-test] ${case#*|} was accepted" >&2; exit 1
  fi
  echo "[production-readiness-test] refused: ${case#*|}"
done
sed 's#/actions/runs/6000#/actions/runs/6999#' "$incident_note" >"$tmp/incident-404.md"
cp "$incident_note" "$incident_note.keep"; cp "$tmp/incident-404.md" "$incident_note"
rehash "$incident_note" .incident.evidence_sha256 "$tmp/bad-incident-404.json"
if PATH="$tmp/bin:$PATH" STUB_LOG="$tmp/gh.log" "$script" "$tmp/bad-incident-404.json" "$tmp/bad.md" >/dev/null 2>&1; then
  echo "[production-readiness-test] an incident linking a run that does not exist was accepted" >&2; exit 1
fi
echo "[production-readiness-test] refused: an incident linking a run that does not exist"
mv "$incident_note.keep" "$incident_note"

# --- Readiness output v0.2 and the real stable gate ----------------------------
jq -e --arg c "$(printf 'c%.0s' {1..40})" '
  .schema_version == "v0.2" and .campaign_binding == "candidate-bound-v2" and
  .attestations_verified == true and (.campaigns | length == 4) and
  ([.campaigns[] | .candidate_commit == $c and .candidate_tag == "v0.4.0-rc.1"] | all)
' "$tmp/attested.json" >/dev/null || {
  echo "[production-readiness-test] attested readiness output is not v0.2 with verified, bound campaigns" >&2; exit 1; }
jq -e '.attestations_verified == false' "$tmp/readiness.json" >/dev/null || {
  echo "[production-readiness-test] bypass readiness output does not say attestations were not verified" >&2; exit 1; }
# Extract the stable gate's jq program from release-artifacts.yml and run it.
gate="$(awk '
  /jq -e --arg version "\$version" .$/ {f=1; next}
  f && /^ *. --argjson c / {exit}
  f {print}
' "${ROOT_DIR}/.github/workflows/release-artifacts.yml")"
[[ -n "$gate" ]] || { echo "[production-readiness-test] could not extract the stable gate" >&2; exit 1; }
run_gate() { jq -e --arg version 0.4.0 --argjson c "$(jq -c '.candidate' "$1")" "$gate" "$1" >/dev/null; }
run_gate "$tmp/attested.json" || { echo "[production-readiness-test] stable gate refused valid attested readiness" >&2; exit 1; }
if run_gate "$tmp/readiness.json"; then
  echo "[production-readiness-test] stable gate accepted readiness produced with the attestation bypass" >&2; exit 1
fi
jq '.campaigns[2].candidate_commit = ("e" * 40)' "$tmp/attested.json" >"$tmp/gate-foreign.json"
if run_gate "$tmp/gate-foreign.json"; then
  echo "[production-readiness-test] stable gate accepted a campaign bound to another candidate" >&2; exit 1
fi
jq '.schema_version = "v0.1"' "$tmp/attested.json" >"$tmp/gate-old.json"
if run_gate "$tmp/gate-old.json"; then
  echo "[production-readiness-test] stable gate accepted v0.1 readiness output" >&2; exit 1
fi
echo "[production-readiness-test] stable gate: accepts attested v0.2; refuses bypass, foreign-candidate and v0.1 output"

echo "[production-readiness-test] PASS"
