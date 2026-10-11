#!/usr/bin/env bash
# Maintenance technical gate (R1).
#
# Replaces the inherited production-tech-check ONLY for maintenance releases.
# That check's stability subgate needs three historical beta-tech reports a
# fresh runner never has, and its beta gate exercises experimental surfaces
# (runtime selector, Cilium/BCC corpora) that a maintenance release does not
# touch. Instead of trusting that claim, this gate requires the
# machine-verified maintenance scope (scripts/check-maintenance-scope.py) to
# be ELIGIBLE: no forbidden or unclassified path, every runtime change
# declared, targeted and exercised by the VM gate, and the toolchain change
# advisory-backed.
#
# Everything else the release workflow runs in "Release quality gates"
# (go vet, go test -race, coverage floor, govulncheck, docs drift, release
# control tests) is unchanged and not duplicated here. Kept from the inherited
# gate: registry external-signer tests and the ops/upgrade runbooks.
#
# Exit 0 ready, 2 not-ready. Evidence: <dir>/maintenance-tech-check-<ts>.md
# and <dir>/maintenance-scope.json.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${BPFCOMPAT_PRODUCTION_TECH_EVIDENCE_DIR:-evidence/production-tech}"
SCOPE_CMD="${BPFCOMPAT_SCOPE_CHECK_CMD:-python3 scripts/check-maintenance-scope.py}"
SIGNER_CMD="${BPFCOMPAT_SIGNER_TEST_CMD:-go test ./internal/registry -run TestPersistArtifactVersionWithExternalSigner -count=1}"
RUNBOOKS="${BPFCOMPAT_REQUIRED_RUNBOOKS:-docs/production-slo-runbook.md docs/incident-response-runbook.md docs/upgrade-backward-compat-playbook.md docs/production-hardening-checklist.md}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"
report_file="${OUT_DIR}/maintenance-tech-check-${timestamp}.md"
scope_json="${OUT_DIR}/maintenance-scope.json"
log_dir="${OUT_DIR}/maintenance-logs-${timestamp}"
mkdir -p "$log_dir"
overall="ready"

scope_result="FAIL"
# shellcheck disable=SC2086  # SCOPE_CMD is a command line by design
if $SCOPE_CMD --out "$scope_json" >"${log_dir}/maintenance-scope.log" 2>&1; then
  if [[ -s "$scope_json" ]] && python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("eligible") is True else 1)' "$scope_json"; then
    scope_result="PASS"
  fi
fi
[[ "$scope_result" == "PASS" ]] || overall="not-ready"

signer_result="FAIL"
# shellcheck disable=SC2086  # SIGNER_CMD is a command line by design
if $SIGNER_CMD >"${log_dir}/registry-external-signer-tests.log" 2>&1; then
  signer_result="PASS"
else
  overall="not-ready"
fi

runbook_result="PASS"
missing=""
for doc in $RUNBOOKS; do
  if [[ ! -f "$doc" ]]; then
    runbook_result="FAIL"
    missing="${missing} ${doc}"
  fi
done
[[ "$runbook_result" == "PASS" ]] || overall="not-ready"

{
  echo "# Maintenance Technical Check"
  echo
  echo "- Timestamp (UTC): ${timestamp}"
  echo "- Gate status: ${overall}"
  echo
  echo "| Control | Result | Output |"
  echo "|---|---|---|"
  echo "| Machine-verified maintenance scope | ${scope_result} | ${scope_json} |"
  echo "| Registry external signer integration tests | ${signer_result} | ${log_dir}/registry-external-signer-tests.log |"
  echo "| Ops/SLO, incident, upgrade and hardening runbooks present | ${runbook_result} | ${missing:- all present} |"
  echo
  echo "## Notes"
  echo
  echo "- Applies to maintenance releases only; a release whose scope is not eligible needs the full stable gate."
  echo "- go vet, go test -race, coverage, govulncheck and docs drift run separately in the release quality gates."
} >"$report_file"

echo "[maintenance-tech] ${overall}: ${report_file}"
if [[ "$overall" == "ready" ]]; then
  exit 0
fi
exit 2
