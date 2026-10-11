#!/usr/bin/env bash
# Regression guard for scripts/maintenance-tech-check.sh (R1).
#
# The maintenance tech gate replaces the inherited beta-history subgate ONLY
# when the machine-verified scope says the release is maintenance-eligible.
# It must:
#   1. exit 0 and record "ready" when scope, signer tests and runbooks pass;
#   2. exit 2 ("not-ready") when the scope check reports ineligible;
#   3. exit 2 when the scope check cannot run at all (never pass by default);
#   4. exit 2 when a required runbook is missing;
#   5. keep the scope result JSON as evidence next to the report.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/maintenance-tech-check.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat >"$work/scope-ok.sh" <<'SH'
#!/usr/bin/env bash
out="${2:?}"; printf '{"eligible": true, "violations": []}\n' >"$out"; exit 0
SH
cat >"$work/scope-bad.sh" <<'SH'
#!/usr/bin/env bash
out="${2:?}"; printf '{"eligible": false, "violations": ["go.sum: FORBIDDEN"]}\n' >"$out"; exit 1
SH
cat >"$work/scope-crash.sh" <<'SH'
#!/usr/bin/env bash
exit 2
SH
cat >"$work/signer-ok.sh" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$work"/*.sh

fail=0
expect() { # name want_rc env...
  local name="$1" want="$2"; shift 2
  local rc=0 dir="$work/evidence-$RANDOM"
  env BPFCOMPAT_PRODUCTION_TECH_EVIDENCE_DIR="$dir" BPFCOMPAT_SIGNER_TEST_CMD="$work/signer-ok.sh" \
    "$@" bash "$SCRIPT" >"$work/out.txt" 2>&1 || rc=$?
  if [[ "$rc" -eq "$want" ]]; then
    printf 'ok:   %s (rc=%s)\n' "$name" "$rc"
  else
    printf 'FAIL: %s (rc=%s want %s)\n' "$name" "$rc" "$want" >&2
    cat "$work/out.txt" >&2
    fail=1
  fi
  last_dir="$dir"
}

expect "eligible scope with passing controls is ready" 0 BPFCOMPAT_SCOPE_CHECK_CMD="$work/scope-ok.sh"
if [[ -s "$last_dir/maintenance-scope.json" ]] && grep -q 'Gate status: ready' "$last_dir"/maintenance-tech-check-*.md; then
  printf 'ok:   scope evidence and ready report are written\n'
else
  printf 'FAIL: scope evidence or report missing\n' >&2; fail=1
fi
expect "ineligible scope is not-ready" 2 BPFCOMPAT_SCOPE_CHECK_CMD="$work/scope-bad.sh"
expect "scope check that cannot run is not-ready" 2 BPFCOMPAT_SCOPE_CHECK_CMD="$work/scope-crash.sh"
expect "missing runbook is not-ready" 2 BPFCOMPAT_SCOPE_CHECK_CMD="$work/scope-ok.sh" \
  BPFCOMPAT_REQUIRED_RUNBOOKS="docs/does-not-exist.md"
expect "failing signer test is not-ready" 2 BPFCOMPAT_SCOPE_CHECK_CMD="$work/scope-ok.sh" \
  BPFCOMPAT_SIGNER_TEST_CMD=false

if [[ "$fail" -ne 0 ]]; then
  echo "maintenance-tech-check_test: FAILED" >&2
  exit 1
fi
echo "maintenance-tech-check_test: all checks passed"
