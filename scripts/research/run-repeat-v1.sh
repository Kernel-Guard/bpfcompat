#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:-dist/research-corpus-v1}"
REPORTS="${2:-reports/research-repeat-v1}"
SAMPLE="${3:-research/repeat/v1/stability-sample.json}"
PLAN="research/corpus/v1/study-plan.json"

fail() {
  echo "[research-repeat-v1] $*" >&2
  exit 1
}

[[ -x "$BUNDLE/bin/bpfcompat-linux-amd64" ]] || fail "missing materialized BPFCompat CLI"
[[ -x "$BUNDLE/bin/bpfcompat-validator-static-linux-amd64" ]] || fail "missing materialized validator"
[[ -s "$SAMPLE" && -s "$PLAN" ]] || fail "missing repeat sample or study plan"

bash scripts/research/verify-materialization-v1.sh "$BUNDLE"
bash scripts/research/verify-profile-lock-v1.sh

export BPFCOMPAT_VALIDATOR_BIN="$PWD/$BUNDLE/bin/bpfcompat-validator-static-linux-amd64"
export BPFCOMPAT_VALIDATOR_SHA256="4ae1d5b838be07e6e7c304d753389a239c19eb92f6ba3bd77657e5c9583b9d04"

BPF="$PWD/$BUNDLE/bin/bpfcompat-linux-amd64"
mkdir -p "$REPORTS/raw" "$REPORTS/logs" "$REPORTS/matrices" "$REPORTS/normalized"

jq -n \
  --arg workflow_source_commit "$(git rev-parse HEAD)" \
  --arg sample_sha256 "sha256:$(sha256sum "$SAMPLE" | awk '{print $1}')" \
  --arg materialization_sha256 "sha256:$(sha256sum "$BUNDLE/materialization.json" | awk '{print $1}')" \
  --arg study_plan_sha256 "sha256:$(sha256sum "$PLAN" | awk '{print $1}')" \
  --arg profile_lock_sha256 "sha256:$(sha256sum research/corpus/v1/profile-identities.json | awk '{print $1}')" \
  --arg cli_sha256 "sha256:$(sha256sum "$BUNDLE/bin/bpfcompat-linux-amd64" | awk '{print $1}')" \
  --arg validator_sha256 "sha256:$(sha256sum "$BUNDLE/bin/bpfcompat-validator-static-linux-amd64" | awk '{print $1}')" \
  --arg cilium_loader_sha256 "sha256:$(sha256sum "$BUNDLE/loaders/ebpf-go-loader" | awk '{print $1}')" \
  --arg falco_loader_sha256 "sha256:$(sha256sum "$BUNDLE/loaders/scap-open" | awk '{print $1}')" \
  '{
    schema_version:"bpfcompat.research.repeat-provenance.v1",
    corpus_version:"v1",
    workflow_source_commit:$workflow_source_commit,
    sample_sha256:$sample_sha256,
    materialization_sha256:$materialization_sha256,
    study_plan_sha256:$study_plan_sha256,
    profile_lock_sha256:$profile_lock_sha256,
    bpfcompat_cli_sha256:$cli_sha256,
    validator_sha256:$validator_sha256,
    loaders:{
      "cilium-ebpf-v022-loader":$cilium_loader_sha256,
      "falco-modern-bpf-scap-open":$falco_loader_sha256
    }
  }' > "$REPORTS/repeat-provenance.json"

repeats="$(jq -er '.repeats_per_tuple | select(type == "number" and . > 0)' "$SAMPLE")"
tuple_rows="$(mktemp)"
trap 'rm -f "$tuple_rows"' EXIT
jq -ec '.tuples[]' "$SAMPLE" > "$tuple_rows"
[[ -s "$tuple_rows" ]] || fail "repeat sample contains no tuples"

run_once() {
  local tuple_id="$1"
  local repeat="$2"
  shift 2

  local outdir="$REPORTS/raw/$tuple_id"
  local logdir="$REPORTS/logs/$tuple_id"
  mkdir -p "$outdir" "$logdir"
  rm -f "$outdir/repeat-$repeat.json" "$logdir/repeat-$repeat.stdout.log" \
    "$logdir/repeat-$repeat.stderr.log" "$logdir/repeat-$repeat.exit-code"

  local rc=0
  if "$@" >"$logdir/repeat-$repeat.stdout.log" 2>"$logdir/repeat-$repeat.stderr.log"; then
    rc=0
  else
    rc=$?
  fi
  printf '%s\n' "$rc" > "$logdir/repeat-$repeat.exit-code"

  if [[ ! -s "$outdir/repeat-$repeat.json" ]]; then
    echo "[research-repeat-v1] warning: $tuple_id repeat $repeat exited $rc without report" >&2
  else
    echo "[research-repeat-v1] $tuple_id repeat $repeat captured (CLI exit $rc)"
  fi
}

while IFS= read -r tuple_json; do
  tuple_id="$(jq -er '.id | select(type == "string" and length > 0)' <<<"$tuple_json")" ||
    fail "repeat tuple missing id"
  case_id="$(jq -er '.case_id | select(type == "string" and length > 0)' <<<"$tuple_json")" ||
    fail "$tuple_id: missing case_id"
  profile_id="$(jq -er '.profile_id | select(type == "string" and length > 0)' <<<"$tuple_json")" ||
    fail "$tuple_id: missing profile_id"

  [[ "$tuple_id" =~ ^[A-Za-z0-9._-]+$ ]] || fail "unsafe tuple id: $tuple_id"
  [[ "$profile_id" =~ ^[A-Za-z0-9._-]+$ ]] || fail "unsafe profile id: $profile_id"

  case_json="$(jq -ec --arg id "$case_id" '.cases[] | select(.id == $id)' "$PLAN")" ||
    fail "$tuple_id: case not found in study plan: $case_id"
  [[ -n "$case_json" ]] || fail "$tuple_id: case not found in study plan: $case_id"

  mode="$(jq -er '.mode' <<<"$case_json")"
  artifact_path="$(jq -r '.artifact_path // empty' <<<"$case_json")"
  manifest="$(jq -r '.manifest // empty' <<<"$case_json")"
  command_binary="$(jq -r '.command_binary // empty' <<<"$case_json")"
  command="$(jq -r '.command // empty' <<<"$case_json")"

  matrix="$REPORTS/matrices/$tuple_id.yaml"
  cat > "$matrix" <<EOF
name: research-repeat-v1-$tuple_id
profiles:
  - id: $profile_id
    required: false
EOF

  for repeat in $(seq 1 "$repeats"); do
    common=(
      --matrix "$matrix"
      --concurrency 1
      --timeout 8m
      --artifact-name "repeat-$tuple_id"
      --artifact-version "v1-repeat-$repeat"
      --workdir ".bpfcompat/research-repeat-v1/$profile_id"
      --out "$REPORTS/raw/$tuple_id/repeat-$repeat.json"
    )

    case "$mode" in
      load_only|load_attach)
        [[ -n "$artifact_path" && -n "$manifest" ]] ||
          fail "$tuple_id: libbpf case requires artifact_path and manifest"
        run_once "$tuple_id" "$repeat" \
          "$BPF" test \
          --artifact "$BUNDLE/$artifact_path" \
          --manifest "$manifest" \
          --validation-mode "$mode" \
          "${common[@]}"
        ;;
      command)
        [[ -n "$command_binary" && -n "$command" ]] ||
          fail "$tuple_id: command case requires command_binary and command"
        args=(
          "$BPF" test-command
          --cmd "$command"
          --bin "$BUNDLE/$command_binary"
        )
        if [[ -n "$artifact_path" ]]; then
          args+=(--artifact "$BUNDLE/$artifact_path")
        fi
        args+=("${common[@]}")
        run_once "$tuple_id" "$repeat" "${args[@]}"
        ;;
      *)
        fail "$tuple_id: unsupported study mode $mode"
        ;;
    esac
  done
done < "$tuple_rows"

python3 scripts/research/analyze-repeat-v1.py \
  --reports-dir "$REPORTS" \
  --sample "$SAMPLE" \
  --out-dir "$REPORTS/normalized"

echo "[research-repeat-v1] repeat stability collection complete"
