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
go_test_result="FAIL"
go_vet_result="FAIL"
hostile_result="FAIL"
release_result="FAIL"
docs_result="FAIL"
contract_docs_result="FAIL"

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

run_check go_test_result go-test go test ./...
run_check go_vet_result go-vet go vet ./...
run_check hostile_result hostile-suite scripts/hostile-artifact-suite.sh
run_check release_result release-consistency make check-release-consistency
run_check docs_result docs-consistency env BPFCOMPAT_DOCS_COMPARE=worktree make check-docs-drift

required_docs=(
  docs/production-support-boundary.md
  docs/production-slo-runbook.md
  docs/incident-response-runbook.md
  docs/upgrade-backward-compat-playbook.md
  docs/schema-stability-contract.md
  docs/production-hardening-checklist.md
  docs/production-release-process.md
)
contract_docs_result="PASS"
: >"${log_dir}/contract-docs.log"
for path in "${required_docs[@]}"; do
  if [[ ! -f "$path" ]]; then
    contract_docs_result="FAIL"
    overall="not-ready"
    printf 'missing %s\n' "$path" >>"${log_dir}/contract-docs.log"
  else
    printf 'present %s\n' "$path" >>"${log_dir}/contract-docs.log"
  fi
done

{
  echo "# Production Technical Check"
  echo
  echo "- Timestamp (UTC): ${timestamp}"
  echo "- Gate status: ${overall}"
  echo "- Supported boundary: CLI + GitHub Action + disposable QEMU/KVM validation"
  echo
  echo "| Control | Result | Output |"
  echo "|---|---|---|"
  echo "| Go tests | ${go_test_result} | ${log_dir}/go-test.log |"
  echo "| Go vet | ${go_vet_result} | ${log_dir}/go-vet.log |"
  echo "| Hostile artifact/configuration suite | ${hostile_result} | ${log_dir}/hostile-suite.log |"
  echo "| Release metadata consistency | ${release_result} | ${log_dir}/release-consistency.log |"
  echo "| Generated documentation consistency | ${docs_result} | ${log_dir}/docs-consistency.log |"
  echo "| Support/SLO/incident/schema/upgrade documents | ${contract_docs_result} | ${log_dir}/contract-docs.log |"
  echo
  echo "## External Evidence"
  echo
  echo "- Release candidate VM evidence is produced by \`.github/workflows/release-artifacts.yml\`."
  echo "- Weekly operational evidence is produced by \`.github/workflows/latest-kernel-compatibility.yml\`."
  echo "- Runtime loading, agent, API, registry, and SaaS are excluded and retain separate failing gates."
} >"$report_file"

echo "[production-tech] ${overall}: ${report_file}"
if [[ "$overall" == "ready" ]]; then
  exit 0
fi
exit 2
