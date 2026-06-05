#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EVIDENCE_DIR="${BPFCOMPAT_BETA_EVIDENCE_DIR:-evidence/beta-tech}"
WORKDIR="${BPFCOMPAT_WORKDIR:-.bpfcompat}"
MATRIX="${BPFCOMPAT_EXTENDED_MATRIX:-matrices/extended-15.yaml}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVIDENCE_DIR"
report_file="${EVIDENCE_DIR}/beta-tech-check-${timestamp}.md"
log_dir="${EVIDENCE_DIR}/logs-${timestamp}"
mkdir -p "$log_dir"

overall="ready"

go_test_result="FAIL"
history_result="FAIL"
hostile_result="FAIL"
matrix_count_result="FAIL"
profile_audit_result="FAIL"
oss_result="FAIL"
selector_result="FAIL"
runtime_selector_e2e_result="FAIL"

profile_count="-"
profile_reachable="-"
profile_unreachable="-"
selector_selected="-"
runtime_selector_e2e_selected="-"
runtime_selector_e2e_fetch_source="-"
runtime_selector_e2e_verify_failed="-"
runtime_selector_e2e_report="-"
cilium_run_id="-"
bcc_run_id="-"
bcc_codes="-"

run_check() {
  local result_var="$1"
  local name="$2"
  shift 2
  if "$@" >"${log_dir}/${name}.log" 2>&1; then
    printf -v "$result_var" "PASS"
  else
    overall="not-ready"
    printf -v "$result_var" "FAIL"
  fi
}

if [[ ! -x ./bin/bpfcompat ]]; then
  mkdir -p bin
  go build -o bin/bpfcompat ./cmd/bpfcompat >"${log_dir}/build.log" 2>&1 || {
    overall="not-ready"
  }
fi

run_check go_test_result go-test go test ./...
run_check history_result history-verify ./bin/bpfcompat history verify --workdir "$WORKDIR"
run_check hostile_result hostile-suite scripts/hostile-artifact-suite.sh

if matrix_profiles="$(./bin/bpfcompat profile list --matrix "$MATRIX" 2>"${log_dir}/matrix-count.log")"; then
  profile_count="$(printf "%s\n" "$matrix_profiles" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
  if [[ "$profile_count" == "15" ]]; then
    matrix_count_result="PASS"
  else
    matrix_count_result="FAIL"
    overall="not-ready"
  fi
else
  matrix_count_result="FAIL"
  overall="not-ready"
fi

if make profile-catalog-audit >"${log_dir}/profile-audit.log" 2>&1; then
  latest_audit="$(ls -1 evidence/profile-catalog/profile-catalog-audit-*.md | sort | tail -n1)"
  profile_reachable="$(awk -F': ' '/Reachable \(200\/302\):/ {print $2}' "$latest_audit" | tr -d ' ' || true)"
  profile_unreachable="$(awk -F': ' '/Unreachable\/timeout\/other:/ {print $2}' "$latest_audit" | tr -d ' ' || true)"
  if [[ "$profile_reachable" == "15" && "$profile_unreachable" == "0" ]]; then
    profile_audit_result="PASS"
  else
    profile_audit_result="FAIL"
    overall="not-ready"
  fi
else
  profile_audit_result="FAIL"
  overall="not-ready"
fi

cilium_report="evidence/oss-validation/reports/cilium-tracepoint-in-c-mvp.json"
bcc_report="evidence/oss-validation/reports/bcc-execsnoop-mvp.json"
if [[ -f "$cilium_report" && -f "$bcc_report" ]]; then
  cilium_status="$(jq -r '.summary.status // "unknown"' "$cilium_report" 2>"${log_dir}/oss-evidence.log" || true)"
  cilium_targets="$(jq -r '.targets | length' "$cilium_report" 2>>"${log_dir}/oss-evidence.log" || true)"
  cilium_run_id="$(jq -r '.run.id // "-"' "$cilium_report" 2>>"${log_dir}/oss-evidence.log" || true)"
  bcc_status="$(jq -r '.summary.status // "unknown"' "$bcc_report" 2>>"${log_dir}/oss-evidence.log" || true)"
  bcc_targets="$(jq -r '.targets | length' "$bcc_report" 2>>"${log_dir}/oss-evidence.log" || true)"
  bcc_run_id="$(jq -r '.run.id // "-"' "$bcc_report" 2>>"${log_dir}/oss-evidence.log" || true)"
  bcc_required_fail="$(jq -r '[.targets[] | select(.required == true and .status == "fail") | .profile_id] | if length == 0 then "-" else join(",") end' "$bcc_report" 2>>"${log_dir}/oss-evidence.log" || true)"
  bcc_codes="$(jq -r '[.targets[] | .classification_code // empty] | unique | if length == 0 then "-" else join(",") end' "$bcc_report" 2>>"${log_dir}/oss-evidence.log" || true)"

  if [[ "$cilium_status" == "pass" && "$cilium_targets" == "8" && "$bcc_status" == "fail" && "$bcc_targets" == "8" && "$bcc_required_fail" == *"ubuntu-18.04-4.15"* ]]; then
    oss_result="PASS"
  else
    oss_result="FAIL"
    overall="not-ready"
  fi
else
  oss_result="FAIL"
  overall="not-ready"
fi

if selector_output="$(scripts/select-artifact-variant.sh reports/ringbuf-modern-mvp.json reports/perfbuf-fallback-mvp.json 2>"${log_dir}/selector.log")"; then
  selector_selected="$(printf "%s\n" "$selector_output" | awk -F'report=' '/\[selector\] selected/{print $2}' | awk '{print $1}' | tail -n1)"
  if [[ "$selector_selected" == "reports/perfbuf-fallback-mvp.json" ]]; then
    selector_result="PASS"
  else
    selector_result="FAIL"
    overall="not-ready"
  fi
  printf "%s\n" "$selector_output" >>"${log_dir}/selector.log"
else
  selector_result="FAIL"
  overall="not-ready"
fi

if make runtime-selector-proof >"${log_dir}/runtime-selector-proof.log" 2>&1; then
  runtime_selector_e2e_report="$(find evidence/runtime-selector -maxdepth 2 -type f -name 'runtime-selector-proof.md' | sort | tail -n1)"
  if [[ -n "$runtime_selector_e2e_report" && -f "$runtime_selector_e2e_report" ]]; then
    proof_dir="$(dirname "$runtime_selector_e2e_report")"
    proof_select_json="${proof_dir}/runtime-select.json"
    proof_fetch_json="${proof_dir}/runtime-fetch.json"
    proof_verify_json="${proof_dir}/history-verify.json"

    runtime_selector_e2e_selected="$(jq -r '.selection.selected.artifact_version // "-"' "$proof_select_json" 2>>"${log_dir}/runtime-selector-proof.log" || true)"
    runtime_selector_e2e_fetch_source="$(jq -r '.fetch.source_path // "-"' "$proof_fetch_json" 2>>"${log_dir}/runtime-selector-proof.log" || true)"
    runtime_selector_e2e_verify_failed="$(jq '[.[] | select(.verified != true)] | length' "$proof_verify_json" 2>>"${log_dir}/runtime-selector-proof.log" || true)"

    if [[ "$runtime_selector_e2e_selected" == "v1.0.0-perfbuf" && "$runtime_selector_e2e_fetch_source" == file://* && "$runtime_selector_e2e_verify_failed" == "0" ]]; then
      runtime_selector_e2e_result="PASS"
    else
      runtime_selector_e2e_result="FAIL"
      overall="not-ready"
    fi
  else
    runtime_selector_e2e_result="FAIL"
    overall="not-ready"
  fi
else
  runtime_selector_e2e_result="FAIL"
  overall="not-ready"
fi

{
  echo "# Technical Beta Check"
  echo
  echo "- Timestamp (UTC): ${timestamp}"
  echo "- Gate status: ${overall}"
  echo
  echo "| Control | Result | Key Output |"
  echo "|---|---|---|"
  echo "| go test ./... | ${go_test_result} | ${log_dir}/go-test.log |"
  echo "| history verify | ${history_result} | ${log_dir}/history-verify.log |"
  echo "| hostile suite | ${hostile_result} | ${log_dir}/hostile-suite.log |"
  echo "| extended matrix profile count (${MATRIX}) | ${matrix_count_result} | count=${profile_count} |"
  echo "| profile catalog URL audit | ${profile_audit_result} | reachable=${profile_reachable}, unreachable=${profile_unreachable} |"
  echo "| OSS evidence expectations | ${oss_result} | cilium_run=${cilium_run_id}, bcc_run=${bcc_run_id}, bcc_codes=${bcc_codes} |"
  echo "| runtime selector outcome | ${selector_result} | selected=${selector_selected} |"
  echo "| runtime selector e2e proof | ${runtime_selector_e2e_result} | selected=${runtime_selector_e2e_selected}, verify_failed=${runtime_selector_e2e_verify_failed}, source=${runtime_selector_e2e_fetch_source}, report=${runtime_selector_e2e_report} |"
  echo
  echo "## Notes"
  echo
  echo "- This gate is technical-only and covers local engineering readiness only."
  echo "- Full command logs are archived in \`${log_dir}\`."
} >"$report_file"

echo "[beta-tech] ${overall}: ${report_file}"
if [[ "$overall" == "ready" ]]; then
  exit 0
fi
exit 2
