#!/usr/bin/env bash
# Regression guard for the readiness "maintenance" channel (R1-R3).
#
# A maintenance release is ready only with two first-party, producer-attested
# maintenance-evidence runs (E0, E1) bound to the exact candidate and at least
# 24 hours apart, an eligible machine-verified scope, a stable commit that
# differs from the candidate only in release metadata, and the rollback,
# incident and operator controls. Third-party or unattested observations are
# never accepted as producer evidence.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${ROOT_DIR}/scripts/production-readiness-report.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

head_commit="$(git -C "$ROOT_DIR" rev-parse HEAD)"
# The published stable baseline is always an ancestor with code changes since.
code_commit="$(awk -F": " '$1 == "stable_commit" {print $2; exit}' "$ROOT_DIR/release.yaml")"
stable_commit="$(awk -F': ' '$1 == "stable_commit" {print $2; exit}' "$ROOT_DIR/release.yaml")"
operator="$(awk -F': ' '$1 == "release_operator" {print $2; exit}' "$ROOT_DIR/release.yaml")"
tag=v0.3.8-rc.1
digest="sha256:$(printf 'd%.0s' {1..64})"

mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == "attestation --help" ]]; then exit 0; fi
if [[ "$*" == api\ * ]]; then
  run_id="${2##*/}"
  case "$run_id" in
    500[0-1]) ;;
    *) exit 1;;
  esac
  jq -n --argjson id "$run_id" --arg sha "$TEST_RUN_SOURCE" --arg branch "${TEST_RUN_BRANCH:-v0.3.8-rc.1}" \
    --arg path "${TEST_RUN_WORKFLOW:-.github/workflows/maintenance-evidence.yml}" \
    '{id:$id,run_attempt:1,path:$path,head_sha:$sha,head_branch:$branch,status:"completed",conclusion:"success",event:"workflow_dispatch"}'
  exit 0
fi
[[ "$*" == attestation\ verify* ]]
[[ "$*" == *'--repo Kernel-Guard/bpfcompat'* ]]
# The mock attests whatever ref the run reports, so only the explicit
# candidate-tag binding in readiness can reject a run on another ref.
case "$*" in
  *'--signer-workflow Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml'*)
    [[ "$*" == *'--source-ref refs/tags/v0.3.8-rc.1'* ]];;
  *'--signer-workflow Kernel-Guard/bpfcompat/.github/workflows/maintenance-evidence.yml'*)
    [[ "$*" == *"--source-ref refs/tags/${TEST_RUN_BRANCH:-v0.3.8-rc.1}"* ]]
    [[ "${TEST_PROVENANCE:-pass}" == pass ]];;
  *) exit 1;;
esac
if [[ "$*" == *'--format json'* ]]; then
  id="$(jq -r '.workflow_run_id' "$3")"
  jq -n --arg invocation "https://github.com/Kernel-Guard/bpfcompat/actions/runs/$id/attempts/1" \
    '[{verificationResult:{statement:{predicate:{runDetails:{metadata:{invocationId:$invocation}}}}}}]'
fi
EOF
cat >"$tmp/bin/scope-ok" <<EOF
#!/usr/bin/env bash
printf '{"eligible": true, "violations": [], "baseline": "%s"}\n' "$stable_commit" >"\$2"
EOF
cat >"$tmp/bin/scope-bad" <<EOF
#!/usr/bin/env bash
printf '{"eligible": false, "violations": ["go.sum: FORBIDDEN"], "baseline": "%s"}\n' "$stable_commit" >"\$2"
exit 1
EOF
cat >"$tmp/bin/scope-crash" <<'EOF'
#!/usr/bin/env bash
exit 2
EOF
chmod 0700 "$tmp/bin/gh" "$tmp/bin/scope-ok" "$tmp/bin/scope-bad" "$tmp/bin/scope-crash"

sha() { sha256sum "$1" | awk '{print $1}'; }

# build CASE_DIR CANDIDATE_COMMIT [jq filter for e1] [jq filter for e0] [jq filter for manifest]
build() {
  local dir="$1" commit="$2" e1_filter="${3:-.}" e0_filter="${4:-.}" manifest_filter="${5:-.}"
  mkdir -p "$dir"
  jq -n --arg tag "$tag" --arg commit "$commit" --arg digest "$digest" '{
    schema_version: "v0.1", repository: "Kernel-Guard/bpfcompat", channel: "prerelease",
    tag: $tag, commit_sha: $commit, image: ("ghcr.io/kernel-guard/bpfcompat@" + $digest),
    checksums_sha256: ("e" * 64), positive_report_sha256: ("1" * 64), negative_report_sha256: ("2" * 64)
  }' >"$dir/candidate.json"
  local cand_sha
  cand_sha="$(sha "$dir/candidate.json")"
  observation() {
    jq -n --arg m "$1" --argjson id "$2" --arg started "$3" --arg completed "$4" \
      --arg tag "$tag" --arg commit "$commit" --arg digest "$digest" --arg base "$stable_commit" --arg cand "$cand_sha" '{
      schema_version: "v0.1", marker: "[bpfcompat-maintenance-evidence:v1]", repository: "Kernel-Guard/bpfcompat",
      workflow_ref: ("Kernel-Guard/bpfcompat/.github/workflows/maintenance-evidence.yml@refs/tags/" + $tag),
      milestone: $m, workflow_run_id: $id, workflow_run_attempt: 1, started_at: $started, completed_at: $completed,
      tag: $tag, commit_sha: $commit, image_digest: $digest, checksums_sha256: ("e" * 64),
      candidate_evidence_sha256: $cand, cli_sha256: ("1" * 64), validator_sha256: ("2" * 64),
      scope: {eligible: true, baseline: $base},
      vm: {profiles: ["centos-stream-10-6.12", "centos-stream-9-5.14", "centos-stream-9-5.14-k5.14.0-725.el9"],
           positive: "pass", negative: "expected-incompatible", exact_kernel: "5.14.0-725.el9.x86_64"},
      canary: {"clean-install": "pass", "candidate-action": "pass", container: "pass"},
      acceptance: {status: "pass", required_infra_errors: 0}
    }'
  }
  observation e0 5000 2026-10-01T10:00:00Z 2026-10-01T11:00:00Z | jq "$e0_filter" >"$dir/e0.json"
  observation e1 5001 2026-10-02T11:30:00Z 2026-10-02T12:30:00Z | jq "$e1_filter" >"$dir/e1.json"
  echo '[bpfcompat-rollback-drill:v1] restored known-good digest' >"$dir/rollback.md"
  echo '[bpfcompat-promotion-incident:v1] non-tag dispatch refused' >"$dir/incident.md"
  printf '[bpfcompat-solo-promotion:v1] %s\n' "$operator" >"$dir/operator.md"
  jq -n --arg op "$operator" \
    --arg c "$(sha "$dir/candidate.json")" --arg e0 "$(sha "$dir/e0.json")" --arg e1 "$(sha "$dir/e1.json")" \
    --arg r "$(sha "$dir/rollback.md")" --arg i "$(sha "$dir/incident.md")" --arg o "$(sha "$dir/operator.md")" '{
    schema_version: "v0.1", channel: "maintenance", release_version: "0.3.8",
    candidate: {evidence: "candidate.json", evidence_sha256: $c},
    observations: [
      {milestone: "e0", evidence: "e0.json", evidence_sha256: $e0},
      {milestone: "e1", evidence: "e1.json", evidence_sha256: $e1}
    ],
    rollback: {completed: true, evidence: "rollback.md", evidence_sha256: $r},
    incident: {completed: true, evidence: "incident.md", evidence_sha256: $i},
    operator: {login: $op, approval_mode: "solo-maintainer", confirmed: true, evidence: "operator.md", evidence_sha256: $o}
  }' | jq "$manifest_filter" >"$dir/input.json"
}

failures=0
run_case() { # name want(pass|fail) dir [env...]
  local name="$1" want="$2" dir="$3"
  shift 3
  local rc=0
  env PATH="$tmp/bin:$PATH" TEST_RUN_SOURCE="${TEST_RUN_SOURCE:-$head_commit}" \
    BPFCOMPAT_SCOPE_CHECK_CMD="$tmp/bin/scope-ok" "$@" \
    bash "$script" "$dir/input.json" "$dir/out.md" "$dir/out.json" >"$dir/log" 2>&1 || rc=$?
  if [[ "$want" == pass && "$rc" -eq 0 ]] || [[ "$want" == fail && "$rc" -ne 0 ]]; then
    printf "ok:   %s  [%s]\n" "$name" "$(tail -1 "$dir/log")"
  else
    printf 'FAIL: %s (rc=%s, want %s)\n' "$name" "$rc" "$want" >&2
    cat "$dir/log" >&2
    failures=$((failures + 1))
  fi
}

build "$tmp/ok" "$head_commit"
run_case "two attested runs 24h apart are ready" pass "$tmp/ok"
jq -e '.gate_status == "ready" and .channel == "maintenance" and .release_version == "0.3.8" and
  (.observations | length == 2) and .candidate.tag == "v0.3.8-rc.1"' "$tmp/ok/out.json" >/dev/null ||
  { echo 'FAIL: ready output does not record the maintenance channel' >&2; failures=$((failures + 1)); }
grep -Fq 'Channel: **maintenance**' "$tmp/ok/out.md" ||
  { echo 'FAIL: markdown does not name the maintenance channel' >&2; failures=$((failures + 1)); }

build "$tmp/spacing" "$head_commit" '.started_at = "2026-10-02T10:59:59Z" | .completed_at = "2026-10-02T12:00:00Z"'
run_case "E1 less than 24h after E0 is rejected" fail "$tmp/spacing"

build "$tmp/order" "$head_commit" '.started_at = "2026-09-30T10:00:00Z" | .completed_at = "2026-09-30T11:00:00Z"'
run_case "E1 before E0 is rejected" fail "$tmp/order"

build "$tmp/digest" "$head_commit" '.image_digest = "sha256:" + ("0" * 64)'
run_case "E1 bound to another image digest is rejected" fail "$tmp/digest"

build "$tmp/commit" "$head_commit" '.commit_sha = ("a" * 40)'
run_case "E1 bound to another commit is rejected" fail "$tmp/commit"

build "$tmp/tagged" "$head_commit" '.tag = "v0.3.8-rc.2"'
run_case "E1 bound to another candidate tag is rejected" fail "$tmp/tagged"

build "$tmp/third" "$head_commit" '.repository = "falcosecurity/libs"'
run_case "third-party run offered as producer evidence is rejected" fail "$tmp/third"

build "$tmp/unattested" "$head_commit" '.attested = false'
run_case "attested:false observation is rejected" fail "$tmp/unattested"

build "$tmp/noprov" "$head_commit"
run_case "observation without producer attestation is rejected" fail "$tmp/noprov" TEST_PROVENANCE=fail

build "$tmp/otherwf" "$head_commit"
run_case "observation from another workflow is rejected" fail "$tmp/otherwf" \
  TEST_RUN_WORKFLOW=.github/workflows/consumer-canary.yml

build "$tmp/branch" "$head_commit"
run_case "observation run on a branch instead of the rc tag is rejected" fail "$tmp/branch" TEST_RUN_BRANCH=main

build "$tmp/dup" "$head_commit" '.workflow_run_id = 5000'
run_case "E0 and E1 from the same run are rejected" fail "$tmp/dup"

build "$tmp/failed" "$head_commit" '.acceptance.status = "fail"'
run_case "failed acceptance is rejected" fail "$tmp/failed"

build "$tmp/rubber" "$head_commit" '.vm.negative = "pass"'
run_case "negative control that did not fail is rejected" fail "$tmp/rubber"

build "$tmp/baseline" "$head_commit" '.scope.baseline = ("b" * 40)'
run_case "evidence scope against another baseline is rejected" fail "$tmp/baseline"

build "$tmp/future" "$head_commit" '.started_at = "2099-01-02T00:00:00Z" | .completed_at = "2099-01-02T01:00:00Z"'
run_case "observation from the future is rejected" fail "$tmp/future"

build "$tmp/single" "$head_commit" . . '.observations = [.observations[0]]'
run_case "a single observation is rejected" fail "$tmp/single"

build "$tmp/mixed" "$head_commit" . . '.campaigns = []'
run_case "maintenance manifest carrying stable-channel fields is rejected" fail "$tmp/mixed"

build "$tmp/hash" "$head_commit"
echo ' ' >>"$tmp/hash/e1.json"
run_case "evidence hash mismatch is rejected" fail "$tmp/hash"

build "$tmp/scope" "$head_commit"
run_case "ineligible scope cannot use the maintenance channel" fail "$tmp/scope" \
  BPFCOMPAT_SCOPE_CHECK_CMD="$tmp/bin/scope-bad"
run_case "scope check that cannot run fails closed" fail "$tmp/scope" \
  BPFCOMPAT_SCOPE_CHECK_CMD="$tmp/bin/scope-crash"

build "$tmp/drift" "$code_commit"
run_case "stable commit with code changes after the candidate is rejected" fail "$tmp/drift" \
  TEST_RUN_SOURCE="$code_commit"

build "$tmp/channel" "$head_commit" . . '.channel = "fast-track"'
run_case "unknown readiness channel is rejected" fail "$tmp/channel"

if [[ "$failures" -ne 0 ]]; then
  echo "[maintenance-readiness-test] FAILED ($failures)" >&2
  exit 1
fi
echo "[maintenance-readiness-test] PASS"
