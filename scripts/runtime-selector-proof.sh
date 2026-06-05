#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BPFCOMPAT_BIN:-./bin/bpfcompat}"
ARTIFACT_NAME="${BPFCOMPAT_PROOF_ARTIFACT_NAME:-aegis-bpf}"
EVIDENCE_ROOT="${BPFCOMPAT_RUNTIME_SELECTOR_EVIDENCE_DIR:-evidence/runtime-selector}"
RINGBUF_REPORT="${BPFCOMPAT_RINGBUF_REPORT:-reports/ringbuf-modern-mvp.json}"
PERFBUF_REPORT="${BPFCOMPAT_PERFBUF_REPORT:-reports/perfbuf-fallback-mvp.json}"

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "[runtime-selector-proof] missing file: $path" >&2
    exit 1
  fi
}

if ! command -v jq >/dev/null 2>&1; then
  echo "[runtime-selector-proof] jq is required" >&2
  exit 1
fi

require_file "$RINGBUF_REPORT"
require_file "$PERFBUF_REPORT"

if [[ ! -x "$BIN" ]]; then
  mkdir -p bin
  go build -o bin/bpfcompat ./cmd/bpfcompat
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
proof_dir="${EVIDENCE_ROOT}/${timestamp}"
workdir="${proof_dir}/workdir"
fetch_dir="${proof_dir}/fetched"
log_dir="${proof_dir}/logs"
index_path="${workdir}/registry/artifact_versions.jsonl"
verify_json="${proof_dir}/history-verify.json"
select_json="${proof_dir}/runtime-select.json"
fetch_json="${proof_dir}/runtime-fetch.json"
report_md="${proof_dir}/runtime-selector-proof.md"

mkdir -p "${workdir}/registry" "$fetch_dir" "$log_dir"
: > "$index_path"

build_record() {
  local report="$1"
  local version="$2"
  local variant="$3"
  local created_at="$4"

  local artifact_path
  artifact_path="$(jq -r '.artifact.path' "$report")"
  require_file "$artifact_path"

  local artifact_abs
  artifact_abs="$(realpath "$artifact_path")"

  local artifact_sha
  artifact_sha="$(jq -r '.artifact.sha256' "$report")"
  local run_id
  run_id="$(jq -r '.run.id' "$report")"
  local run_started
  run_started="$(jq -r '.run.started_at' "$report")"
  local matrix_path
  matrix_path="$(jq -r '.matrix.path' "$report")"
  local matrix_name
  matrix_name="$(jq -r '.matrix.name // ""' "$report")"
  local summary_status
  summary_status="$(jq -r '.summary.status' "$report")"
  local json_report_path
  json_report_path="$(jq -r '.paths.json // empty' "$report")"
  local markdown_path
  markdown_path="$(jq -r '.paths.markdown // empty' "$report")"

  local required_passed
  required_passed="$(jq '[.targets[] | select(.required == true and .status == "pass")] | length' "$report")"
  local required_failed
  required_failed="$(jq '[.targets[] | select(.required == true and .status != "pass")] | length' "$report")"
  local total_profiles
  total_profiles="$(jq '.targets | length' "$report")"

  local supported_profiles_json
  supported_profiles_json="$(jq -c '[.targets[] | select(.status == "pass") | .profile_id] | unique | sort' "$report")"
  local failed_profiles_json
  failed_profiles_json="$(jq -c '[.targets[] | select(.status != "pass") | .profile_id] | unique | sort' "$report")"
  local classification_codes_json
  classification_codes_json="$(jq -c '[.targets[] | .classification_code // empty] | map(select(. != "")) | unique | sort' "$report")"

  local fake_local_path
  fake_local_path="/nonexistent/runtime-selector-proof/$(basename "$artifact_abs")"
  local artifact_uri
  artifact_uri="file://${artifact_abs}"

  jq -cn \
    --arg schema_version "artifact_history.v0.1" \
    --arg run_id "$run_id" \
    --arg run_started_at "$run_started" \
    --arg created_at "$created_at" \
    --arg artifact_name "$ARTIFACT_NAME" \
    --arg artifact_version "$version" \
    --arg artifact_variant "$variant" \
    --arg artifact_path "$fake_local_path" \
    --arg artifact_uri "$artifact_uri" \
    --arg artifact_sha256 "$artifact_sha" \
    --arg matrix_path "$matrix_path" \
    --arg matrix_name "$matrix_name" \
    --arg summary_status "$summary_status" \
    --arg json_report_path "$json_report_path" \
    --arg markdown_path "$markdown_path" \
    --argjson required_passed "$required_passed" \
    --argjson required_failed "$required_failed" \
    --argjson total_profiles "$total_profiles" \
    --argjson supported_profiles "$supported_profiles_json" \
    --argjson failed_profiles "$failed_profiles_json" \
    --argjson classification_codes "$classification_codes_json" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      run_started_at: $run_started_at,
      created_at: $created_at,
      artifact_name: $artifact_name,
      artifact_version: $artifact_version,
      artifact_variant: $artifact_variant,
      artifact_path: $artifact_path,
      artifact_uri: $artifact_uri,
      artifact_sha256: $artifact_sha256,
      matrix_path: $matrix_path,
      matrix_name: $matrix_name,
      summary_status: $summary_status,
      required_passed: $required_passed,
      required_failed: $required_failed,
      total_profiles: $total_profiles,
      supported_profiles: $supported_profiles,
      failed_profiles: $failed_profiles,
      classification_codes: $classification_codes,
      json_report_path: $json_report_path,
      markdown_path: $markdown_path
    }'
}

created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
build_record "$RINGBUF_REPORT" "v1.0.0-ringbuf" "ringbuf-modern" "$created_at" >> "$index_path"
build_record "$PERFBUF_REPORT" "v1.0.0-perfbuf" "perfbuf-fallback" "$created_at" >> "$index_path"

"$BIN" history sign --workdir "$workdir" > "${log_dir}/history-sign.log" 2>&1
"$BIN" history verify --workdir "$workdir" --json > "$verify_json" 2> "${log_dir}/history-verify.log"

"$BIN" runtime select \
  --workdir "$workdir" \
  --artifact-name "$ARTIFACT_NAME" \
  --limit 2 \
  --out "$select_json" \
  > "${log_dir}/runtime-select.log" 2>&1

BPFCOMPAT_FETCH_ALLOW_FILE_URI=true "$BIN" runtime fetch \
  --workdir "$workdir" \
  --artifact-name "$ARTIFACT_NAME" \
  --out-dir "$fetch_dir" \
  --out "$fetch_json" \
  > "${log_dir}/runtime-fetch.log" 2>&1

selected_version="$(jq -r '.selection.selected.artifact_version // empty' "$select_json")"
selected_variant="$(jq -r '.selection.selected.artifact_variant // empty' "$select_json")"
if [[ "$selected_version" != "v1.0.0-perfbuf" ]]; then
  echo "[runtime-selector-proof] unexpected selected version: ${selected_version}" >&2
  exit 2
fi
if [[ "$selected_variant" != "perfbuf-fallback" ]]; then
  echo "[runtime-selector-proof] unexpected selected variant: ${selected_variant}" >&2
  exit 2
fi

fetched_version="$(jq -r '.fetch.artifact_version // empty' "$fetch_json")"
fetched_source="$(jq -r '.fetch.source_path // empty' "$fetch_json")"
fetched_output="$(jq -r '.fetch.output_path // empty' "$fetch_json")"
fetched_actual_sha="$(jq -r '.fetch.actual_sha256 // empty' "$fetch_json")"
fetched_expected_sha="$(jq -r '.fetch.expected_sha256 // empty' "$fetch_json")"

if [[ "$fetched_version" != "$selected_version" ]]; then
  echo "[runtime-selector-proof] fetched version mismatch: selected=${selected_version} fetched=${fetched_version}" >&2
  exit 2
fi
if [[ "${fetched_source}" != file://* ]]; then
  echo "[runtime-selector-proof] expected fetch source to use artifact_uri file://, got: ${fetched_source}" >&2
  exit 2
fi
if [[ ! -f "$fetched_output" ]]; then
  echo "[runtime-selector-proof] fetched artifact missing at: ${fetched_output}" >&2
  exit 2
fi
if [[ -n "$fetched_expected_sha" && "$fetched_actual_sha" != "$fetched_expected_sha" ]]; then
  echo "[runtime-selector-proof] fetched hash mismatch: expected=${fetched_expected_sha} actual=${fetched_actual_sha}" >&2
  exit 2
fi

verify_total="$(jq 'length' "$verify_json")"
verify_failed="$(jq '[.[] | select(.verified != true)] | length' "$verify_json")"
select_trace="$(jq -r '.audit.trace_path // empty' "$select_json")"
fetch_trace="$(jq -r '.audit.trace_path // empty' "$fetch_json")"
decision_events="${workdir}/registry/runtime_decisions.jsonl"
decision_count="0"
if [[ -f "$decision_events" ]]; then
  decision_count="$(wc -l < "$decision_events" | tr -d ' ')"
fi

# Signing keys are generated for proof-only history signing. Remove them from
# persisted evidence output to avoid key-material sprawl.
keys_removed="no"
if [[ -d "${workdir}/keys" ]]; then
  rm -rf "${workdir}/keys"
  keys_removed="yes"
fi

cat > "$report_md" <<EOF
# Runtime Selector End-to-End Proof

- Timestamp (UTC): ${timestamp}
- Artifact family: ${ARTIFACT_NAME}
- Seed reports:
  - ${RINGBUF_REPORT}
  - ${PERFBUF_REPORT}

## Result

- history verify records: ${verify_total}
- history verify failed: ${verify_failed}
- selected version: ${selected_version}
- selected variant: ${selected_variant}
- fetched version: ${fetched_version}
- fetch source: ${fetched_source}
- fetched output: ${fetched_output}
- fetched sha256: ${fetched_actual_sha}
- decision events appended: ${decision_count}
- signing keys removed from evidence workdir: ${keys_removed}

## Decision Trace Files

- select trace: ${select_trace}
- fetch trace: ${fetch_trace}
- event stream: ${decision_events}

## Generated Files

- history verify JSON: ${verify_json}
- select JSON: ${select_json}
- fetch JSON: ${fetch_json}
- logs: ${log_dir}
EOF

echo "[runtime-selector-proof] wrote ${report_md}"
