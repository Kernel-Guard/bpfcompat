#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BPFCOMPAT_BIN:-./bin/bpfcompat}"
ARTIFACT_NAME="${BPFCOMPAT_PROOF_ARTIFACT_NAME:-aegis-bpf}"
EVIDENCE_ROOT="${BPFCOMPAT_RUNTIME_DELIVERY_EVIDENCE_DIR:-evidence/runtime-delivery}"
RINGBUF_REPORT="${BPFCOMPAT_RINGBUF_REPORT:-reports/ringbuf-modern-mvp.json}"
PERFBUF_REPORT="${BPFCOMPAT_PERFBUF_REPORT:-reports/perfbuf-fallback-mvp.json}"

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "[runtime-delivery-proof] missing file: $path" >&2
    exit 1
  fi
}

if ! command -v jq >/dev/null 2>&1; then
  echo "[runtime-delivery-proof] jq is required" >&2
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
history_verify_json="${proof_dir}/history-verify.json"
probe_json="${proof_dir}/runtime-probe.json"
select_json="${proof_dir}/runtime-select.json"
fetch_json="${proof_dir}/runtime-fetch.json"
execute_json="${proof_dir}/runtime-execute.json"
report_md="${proof_dir}/runtime-delivery-proof.md"

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
  fake_local_path="/nonexistent/runtime-delivery-proof/$(basename "$artifact_abs")"
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

create_mock_validator() {
  local out_path="$1"
  cat >"$out_path" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

out=""
log_dir=""
attach_mode="best-effort"
probe_features="true"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact)
      shift 2
      ;;
    --manifest)
      shift 2
      ;;
    --out)
      out="${2:-}"
      shift 2
      ;;
    --log-dir)
      log_dir="${2:-}"
      shift 2
      ;;
    --attach-mode)
      attach_mode="${2:-best-effort}"
      shift 2
      ;;
    --probe-features)
      probe_features="${2:-true}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$out" ]]; then
  echo "missing --out" >&2
  exit 2
fi
mkdir -p "$(dirname "$out")"
if [[ -n "$log_dir" ]]; then
  mkdir -p "$log_dir"
fi

cat >"$out" <<JSON
{
  "status": "pass",
  "load": {
    "status": "pass",
    "error_code": 0,
    "error": ""
  },
  "attach": {
    "mode": "${attach_mode}",
    "status": "pass",
    "attempted": 1,
    "passed": 1,
    "failed": 0
  },
  "btf": {
    "kernel_btf_available": true,
    "artifact_has_btf": true,
    "artifact_has_btf_ext": false
  },
  "logs": {
    "libbpf": ""
  },
  "mock": {
    "probe_features": "${probe_features}"
  }
}
JSON
EOF
  chmod +x "$out_path"
}

created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
build_record "$RINGBUF_REPORT" "v1.0.0-ringbuf" "ringbuf-modern" "$created_at" >> "$index_path"
build_record "$PERFBUF_REPORT" "v1.0.0-perfbuf" "perfbuf-fallback" "$created_at" >> "$index_path"

"$BIN" history sign --workdir "$workdir" > "${log_dir}/history-sign.log" 2>&1
"$BIN" history verify --workdir "$workdir" --json > "$history_verify_json" 2> "${log_dir}/history-verify.log"
"$BIN" runtime probe --out "$probe_json" > "${log_dir}/runtime-probe.log" 2>&1

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
  --require-verified-history=true \
  --out "$fetch_json" \
  > "${log_dir}/runtime-fetch.log" 2>&1

mock_validator="${proof_dir}/mock-validator.sh"
create_mock_validator "$mock_validator"

BPFCOMPAT_FETCH_ALLOW_FILE_URI=true "$BIN" runtime execute \
  --workdir "$workdir" \
  --artifact-name "$ARTIFACT_NAME" \
  --out-dir "$fetch_dir" \
  --allow-host-load \
  --require-verified-history=true \
  --use-sudo=false \
  --validator "$mock_validator" \
  --timeout 30s \
  --out "$execute_json" \
  > "${log_dir}/runtime-execute.log" 2>&1

selected_version="$(jq -r '.selection.selected.artifact_version // empty' "$select_json")"
selected_variant="$(jq -r '.selection.selected.artifact_variant // empty' "$select_json")"
if [[ "$selected_version" != "v1.0.0-perfbuf" ]]; then
  echo "[runtime-delivery-proof] unexpected selected version: ${selected_version}" >&2
  exit 2
fi
if [[ "$selected_variant" != "perfbuf-fallback" ]]; then
  echo "[runtime-delivery-proof] unexpected selected variant: ${selected_variant}" >&2
  exit 2
fi

probe_mode="$(jq -r '.probe_mode // empty' "$probe_json")"
if [[ -z "$probe_mode" ]]; then
  echo "[runtime-delivery-proof] runtime probe did not return probe_mode" >&2
  exit 2
fi

fetched_version="$(jq -r '.fetch.artifact_version // empty' "$fetch_json")"
fetched_source="$(jq -r '.fetch.source_path // empty' "$fetch_json")"
fetched_output="$(jq -r '.fetch.output_path // empty' "$fetch_json")"
fetched_actual_sha="$(jq -r '.fetch.actual_sha256 // empty' "$fetch_json")"
fetched_expected_sha="$(jq -r '.fetch.expected_sha256 // empty' "$fetch_json")"
fetch_history_failed="$(jq -r '.history_verification.failed // -1' "$fetch_json")"

if [[ "$fetched_version" != "$selected_version" ]]; then
  echo "[runtime-delivery-proof] fetched version mismatch: selected=${selected_version} fetched=${fetched_version}" >&2
  exit 2
fi
if [[ "${fetched_source}" != file://* ]]; then
  echo "[runtime-delivery-proof] expected fetch source to use artifact_uri file://, got: ${fetched_source}" >&2
  exit 2
fi
if [[ ! -f "$fetched_output" ]]; then
  echo "[runtime-delivery-proof] fetched artifact missing at: ${fetched_output}" >&2
  exit 2
fi
if [[ -n "$fetched_expected_sha" && "$fetched_actual_sha" != "$fetched_expected_sha" ]]; then
  echo "[runtime-delivery-proof] fetched hash mismatch: expected=${fetched_expected_sha} actual=${fetched_actual_sha}" >&2
  exit 2
fi
if [[ "$fetch_history_failed" != "0" ]]; then
  echo "[runtime-delivery-proof] expected fetch history_verification.failed=0, got ${fetch_history_failed}" >&2
  exit 2
fi

execute_status="$(jq -r '.execution.status // empty' "$execute_json")"
execute_selected_version="$(jq -r '.selection.selected.artifact_version // empty' "$execute_json")"
execute_history_failed="$(jq -r '.history_verification.failed // -1' "$execute_json")"
if [[ "$execute_status" != "pass" ]]; then
  echo "[runtime-delivery-proof] expected execution status=pass, got ${execute_status}" >&2
  exit 2
fi
if [[ "$execute_selected_version" != "$selected_version" ]]; then
  echo "[runtime-delivery-proof] execute selected version mismatch: expected=${selected_version} got=${execute_selected_version}" >&2
  exit 2
fi
if [[ "$execute_history_failed" != "0" ]]; then
  echo "[runtime-delivery-proof] expected execute history_verification.failed=0, got ${execute_history_failed}" >&2
  exit 2
fi

verify_total="$(jq 'length' "$history_verify_json")"
verify_failed="$(jq '[.[] | select(.verified != true)] | length' "$history_verify_json")"
select_trace="$(jq -r '.audit.trace_path // empty' "$select_json")"
fetch_trace="$(jq -r '.audit.trace_path // empty' "$fetch_json")"
execute_trace="$(jq -r '.audit.trace_path // empty' "$execute_json")"
decision_events="${workdir}/registry/runtime_decisions.jsonl"
decision_count="0"
if [[ -f "$decision_events" ]]; then
  decision_count="$(wc -l < "$decision_events" | tr -d ' ')"
fi

keys_removed="no"
if [[ -d "${workdir}/keys" ]]; then
  rm -rf "${workdir}/keys"
  keys_removed="yes"
fi

cat > "$report_md" <<EOF
# Runtime Delivery End-to-End Proof

- Timestamp (UTC): ${timestamp}
- Artifact family: ${ARTIFACT_NAME}
- Seed reports:
  - ${RINGBUF_REPORT}
  - ${PERFBUF_REPORT}

## Result

- history verify records: ${verify_total}
- history verify failed: ${verify_failed}
- probe mode: ${probe_mode}
- selected version: ${selected_version}
- selected variant: ${selected_variant}
- fetched version: ${fetched_version}
- fetch source: ${fetched_source}
- fetched output: ${fetched_output}
- fetched sha256: ${fetched_actual_sha}
- execute status: ${execute_status}
- execute selected version: ${execute_selected_version}
- decision events appended: ${decision_count}
- signing keys removed from evidence workdir: ${keys_removed}

## Decision Trace Files

- select trace: ${select_trace}
- fetch trace: ${fetch_trace}
- execute trace: ${execute_trace}
- event stream: ${decision_events}

## Generated Files

- history verify JSON: ${history_verify_json}
- runtime probe JSON: ${probe_json}
- select JSON: ${select_json}
- fetch JSON: ${fetch_json}
- execute JSON: ${execute_json}
- logs: ${log_dir}
EOF

echo "[runtime-delivery-proof] wrote ${report_md}"
