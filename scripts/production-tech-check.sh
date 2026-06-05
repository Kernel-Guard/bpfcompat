#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${BPFCOMPAT_PRODUCTION_TECH_EVIDENCE_DIR:-evidence/production-tech}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"
report_file="${OUT_DIR}/production-tech-check-${timestamp}.md"
log_dir="${OUT_DIR}/logs-${timestamp}"
mkdir -p "$log_dir"

overall="ready"

beta_gate_result="FAIL"
stability_result="FAIL"
registry_external_signer_result="FAIL"
ops_docs_result="FAIL"
upgrade_docs_result="FAIL"

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

run_check beta_gate_result beta-tech-check make beta-tech-check
run_check stability_result tech-stability scripts/tech-stability-report.sh
run_check registry_external_signer_result registry-external-signer-tests go test ./internal/registry -run 'TestPersistArtifactVersionWithExternalSigner' -count=1

if [[ -f docs/production-slo-runbook.md && -f docs/incident-response-runbook.md ]]; then
  ops_docs_result="PASS"
else
  ops_docs_result="FAIL"
  overall="not-ready"
fi

if [[ -f docs/upgrade-backward-compat-playbook.md && -f docs/production-hardening-checklist.md ]]; then
  upgrade_docs_result="PASS"
else
  upgrade_docs_result="FAIL"
  overall="not-ready"
fi

{
  echo "# Production Technical Check"
  echo
  echo "- Timestamp (UTC): ${timestamp}"
  echo "- Gate status: ${overall}"
  echo
  echo "| Control | Result | Output |"
  echo "|---|---|---|"
  echo "| Technical beta gate | ${beta_gate_result} | ${log_dir}/beta-tech-check.log |"
  echo "| Stability trend gate | ${stability_result} | ${log_dir}/tech-stability.log |"
  echo "| Registry external signer integration tests | ${registry_external_signer_result} | ${log_dir}/registry-external-signer-tests.log |"
  echo "| Ops/SLO + incident runbooks present | ${ops_docs_result} | docs/production-slo-runbook.md, docs/incident-response-runbook.md |"
  echo "| Upgrade + hardening playbooks present | ${upgrade_docs_result} | docs/upgrade-backward-compat-playbook.md, docs/production-hardening-checklist.md |"
  echo
  echo "## Notes"
  echo
  echo "- This gate is technical-only and covers local engineering readiness only."
  echo "- Stability gate expects consecutive beta-tech checks (default minimum: 3)."
} > "$report_file"

echo "[production-tech] ${overall}: ${report_file}"
if [[ "$overall" == "ready" ]]; then
  exit 0
fi
exit 2
