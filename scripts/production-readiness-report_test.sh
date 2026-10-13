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

# --- Attestation path, without the test bypass ---------------------------------
# gh stub: every verification is logged; campaign attestations report the
# invocation in $STUB_INVOCATION_RUN (default: the campaign's own run).
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == attestation && "$2" == --help ]] && exit 0
[[ "$1 $2" == "attestation verify" ]] || { echo "unexpected gh $*" >&2; exit 99; }
printf '%s\n' "$*" >>"$STUB_LOG"
[[ -n "${STUB_FAIL:-}" && "$3" == *"$STUB_FAIL"* ]] && exit 1
if [[ "$*" == *latest-kernel-compatibility.yml* ]]; then
  run="$(jq -r .workflow_run_id "$3")"
  attempt="$(jq -r .workflow_run_attempt "$3")"
  jq -n --arg inv "https://github.com/Kernel-Guard/bpfcompat/actions/runs/${STUB_INVOCATION_RUN:-$run}/attempts/$attempt" \
    '[{verificationResult: {statement: {predicate: {runDetails: {metadata: {invocationId: $inv}}}}}}]'
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

echo "[production-readiness-test] PASS"
