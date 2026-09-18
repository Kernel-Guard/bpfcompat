#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:-dist/research-corpus-v1}"
REPORTS="${2:-reports/research-v1}"
MATRIX="research/corpus/v1/execution-matrix.yaml"
PLAN="research/corpus/v1/study-plan.json"

fail() {
  echo "[research-pilot-v1] $*" >&2
  exit 1
}

[[ -x "$BUNDLE/bin/bpfcompat-linux-amd64" ]] || fail "missing materialized BPFCompat CLI"
[[ -x "$BUNDLE/bin/bpfcompat-validator-static-linux-amd64" ]] || fail "missing materialized validator"
[[ -s "$PLAN" && -s "$MATRIX" ]] || fail "missing frozen study plan or matrix"

bash scripts/research/verify-materialization-v1.sh "$BUNDLE"
bash scripts/research/verify-profile-lock-v1.sh
bash scripts/research/verify-study-matrix-v1.sh

expected_cli="1365337098474dc0a42484271ee6383d46cb1cd20da09d248f9a0063c5147f0e"
actual_cli="$(sha256sum "$BUNDLE/bin/bpfcompat-linux-amd64" | awk '{print $1}')"
[[ "$actual_cli" == "$expected_cli" ]] || fail "BPFCompat CLI identity drift"

export BPFCOMPAT_VALIDATOR_BIN="$PWD/$BUNDLE/bin/bpfcompat-validator-static-linux-amd64"
export BPFCOMPAT_VALIDATOR_SHA256="4ae1d5b838be07e6e7c304d753389a239c19eb92f6ba3bd77657e5c9583b9d04"

BPF="$PWD/$BUNDLE/bin/bpfcompat-linux-amd64"
mkdir -p "$REPORTS/logs" "$REPORTS/normalized"


write_execution_provenance() {
  local out="$REPORTS/execution-provenance.json"
  local cli_sha validator_sha materialization_sha plan_sha matrix_sha profile_lock_sha runner_sha
  cli_sha="sha256:$(sha256sum "$BUNDLE/bin/bpfcompat-linux-amd64" | awk '{print $1}')"
  validator_sha="sha256:$(sha256sum "$BUNDLE/bin/bpfcompat-validator-static-linux-amd64" | awk '{print $1}')"
  materialization_sha="sha256:$(sha256sum "$BUNDLE/materialization.json" | awk '{print $1}')"
  plan_sha="sha256:$(sha256sum "$PLAN" | awk '{print $1}')"
  matrix_sha="sha256:$(sha256sum "$MATRIX" | awk '{print $1}')"
  profile_lock_sha="sha256:$(sha256sum research/corpus/v1/profile-identities.json | awk '{print $1}')"
  runner_sha="sha256:$(sha256sum scripts/research/run-study-v1.sh | awk '{print $1}')"

  jq -n     --arg workflow_source_commit "$(git rev-parse HEAD)"     --arg cli_sha "$cli_sha"     --arg validator_sha "$validator_sha"     --arg materialization_sha "$materialization_sha"     --arg plan_sha "$plan_sha"     --arg matrix_sha "$matrix_sha"     --arg profile_lock_sha "$profile_lock_sha"     --arg runner_sha "$runner_sha"     --arg cilium_loader_sha "sha256:$(sha256sum "$BUNDLE/loaders/ebpf-go-loader" | awk '{print $1}')"     --arg falco_loader_sha "sha256:$(sha256sum "$BUNDLE/loaders/scap-open" | awk '{print $1}')"     '{
      schema_version:"bpfcompat.research.execution-provenance.v1",
      corpus_version:"v1",
      workflow_source_commit:$workflow_source_commit,
      bpfcompat_cli:{sha256:$cli_sha},
      validator:{sha256:$validator_sha},
      loaders:{
        "cilium-ebpf-v022-loader":{path:"loaders/ebpf-go-loader",sha256:$cilium_loader_sha},
        "falco-modern-bpf-scap-open":{path:"loaders/scap-open",sha256:$falco_loader_sha}
      },
      inputs:{
        materialization_json_sha256:$materialization_sha,
        study_plan_sha256:$plan_sha,
        execution_matrix_sha256:$matrix_sha,
        profile_lock_sha256:$profile_lock_sha,
        runner_script_sha256:$runner_sha
      }
    }' > "$out"
}

write_execution_provenance

run_case() {
  local case_id="$1"
  shift

  echo "[research-pilot-v1] === $case_id ==="
  rm -f     "$REPORTS/${case_id}.json"     "$REPORTS/${case_id}.md"     "$REPORTS/logs/${case_id}.stdout.log"     "$REPORTS/logs/${case_id}.stderr.log"     "$REPORTS/logs/${case_id}.exit-code"

  local rc=0
  if "$@" >"$REPORTS/logs/${case_id}.stdout.log" 2>"$REPORTS/logs/${case_id}.stderr.log"; then
    rc=0
  else
    rc=$?
  fi
  printf '%s\n' "$rc" > "$REPORTS/logs/${case_id}.exit-code"

  # Compatibility negatives are observations, not shell failures. A missing
  # report means the case itself did not execute far enough to enter the
  # research dataset and is left for the normalizer to flag.
  if [[ ! -s "$REPORTS/${case_id}.json" ]]; then
    echo "[research-pilot-v1] warning: $case_id exited $rc without a report" >&2
  else
    echo "[research-pilot-v1] $case_id report captured (CLI exit $rc)"
  fi
}

case_rows="$(mktemp)"
trap 'rm -f "$case_rows"' EXIT
if ! jq -ec '.cases[]' "$PLAN" > "$case_rows"; then
  fail "study plan cases could not be enumerated"
fi
[[ -s "$case_rows" ]] || fail "study plan contains no cases"

while IFS= read -r case_json; do
  case_id="$(jq -er '.id | select(type == "string" and length > 0)' <<<"$case_json")" ||
    fail "case without a valid id"
  mode="$(jq -er '.mode | select(type == "string" and length > 0)' <<<"$case_json")" ||
    fail "$case_id: missing mode"
  artifact_path="$(jq -r '.artifact_path // empty' <<<"$case_json")"
  manifest="$(jq -r '.manifest // empty' <<<"$case_json")"
  command_binary="$(jq -r '.command_binary // empty' <<<"$case_json")"
  command="$(jq -r '.command // empty' <<<"$case_json")"

  common=(
    --matrix "$MATRIX"
    --concurrency 2
    --timeout 8m
    --artifact-name "research-$case_id"
    --artifact-version v1
    --workdir ".bpfcompat/research-v1/$case_id"
    --out "$REPORTS/$case_id.json"
    --markdown "$REPORTS/$case_id.md"
  )

  case "$mode" in
    load_only|load_attach)
      [[ -n "$artifact_path" && -n "$manifest" ]] ||
        fail "$case_id: libbpf case requires artifact_path and manifest"
      run_case "$case_id"         "$BPF" test         --artifact "$BUNDLE/$artifact_path"         --manifest "$manifest"         --validation-mode "$mode"         "${common[@]}"
      ;;
    command)
      [[ -n "$command_binary" && -n "$command" ]] ||
        fail "$case_id: command case requires command_binary and command"
      args=(
        "$BPF" test-command
        --cmd "$command"
        --bin "$BUNDLE/$command_binary"
      )
      if [[ -n "$artifact_path" ]]; then
        args+=(--artifact "$BUNDLE/$artifact_path")
      fi
      args+=("${common[@]}")
      run_case "$case_id" "${args[@]}"
      ;;
    *)
      fail "$case_id: unsupported study mode $mode"
      ;;
  esac
done < "$case_rows"

python3 scripts/research/normalize-study-v1.py   --reports-dir "$REPORTS"   --out-dir "$REPORTS/normalized"

echo "[research-pilot-v1] collection normalization complete"
