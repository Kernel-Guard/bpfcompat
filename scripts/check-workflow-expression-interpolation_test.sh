#!/usr/bin/env bash
# Fixture reasons quote literal GitHub expressions, not shell expansions.
# shellcheck disable=SC2016
# Regression suite for scripts/check-workflow-expression-interpolation.sh.
#
# The repository's non-frozen workflows must pass. Every fixture workflow is
# scanned default-deny: any ${{ }} in a run: script fails unless it is one of
# the narrowly allowlisted run-identity values. The frozen workflows are
# skipped by name, and a missing frozen file is an error so a rename cannot
# silently move a workflow out of (or into) the exemption.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$ROOT/scripts/check-workflow-expression-interpolation.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

FROZEN=(
  release-artifacts.yml
  promote-release.yml
  release-candidate-canary.yml
  consumer-canary.yml
  external-consumer-canary.yml
  latest-kernel-compatibility.yml
  rollback-drill.yml
)

bash "$script" >"$tmp/real.log" 2>&1 || { cat "$tmp/real.log" >&2; echo "FAIL: repository workflows" >&2; exit 1; }
grep -Fq 'PASS' "$tmp/real.log"
echo "ok:   repository non-frozen workflows pass"

fail=0
# fresh_dir: a workflows dir holding benign stand-ins for every frozen file.
fresh_dir() {
  rm -rf "$tmp/wf" "$tmp/actions"
  mkdir -p "$tmp/wf" "$tmp/actions"
  local f
  for f in "${FROZEN[@]}"; do
    printf 'on: workflow_dispatch\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' >"$tmp/wf/$f"
  done
}

run_guard() {
  BPFCOMPAT_WORKFLOWS_DIR="$tmp/wf" BPFCOMPAT_ACTIONS_DIR="$tmp/actions" \
    bash "$script" >"$tmp/out.log" 2>&1
}

# expect <pass|fail|error> <description> [reason]
expect() {
  local want="$1" desc="$2" reason="${3:-}" got rc=0
  run_guard || rc=$?
  case "$rc" in 0) got=pass ;; 1) got=fail ;; *) got=error ;; esac
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: ${desc}: expected ${want}, got ${got} (rc=${rc})" >&2
    cat "$tmp/out.log" >&2
    fail=1
    return
  fi
  if [[ -n "$reason" ]] && ! grep -Fq -- "$reason" "$tmp/out.log"; then
    echo "FAIL: ${desc}: ${got}, but output lacks: ${reason}" >&2
    cat "$tmp/out.log" >&2
    fail=1
    return
  fi
  echo "ok:   ${desc} -> ${got}"
}

# wf <file> <run-line>: one job, one step whose run: is <run-line>.
wf() {
  printf 'on: workflow_dispatch\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: S\n        run: |\n          set -euo pipefail\n          %s\n' "$2" >"$tmp/wf/$1"
}

# Default-deny: contexts the action.yml guard tolerates are not provably safe
# in a workflow (a matrix can be fromJSON(needs.x.outputs.y); a step output
# can echo a PR title), so they must go through env: too.
fresh_dir; wf a.yml 'make "${{ matrix.image_target }}"'
expect fail "matrix value in run" 'matrix.image_target'
fresh_dir; wf a.yml 'echo "${{ steps.meta.outputs.title }}"'
expect fail "step output in run" 'steps.meta.outputs.title'
fresh_dir; wf a.yml 'echo "${{ needs.plan.outputs.kernels }}"'
expect fail "job output in run" 'needs.plan.outputs.kernels'
fresh_dir; wf a.yml 'echo "${{ github.event.pull_request.title }}"'
expect fail "event data in run" 'github.event.pull_request.title'
fresh_dir; wf a.yml 'echo "${{ inputs.ref }}"'
expect fail "dispatch input in run" 'inputs.ref'
fresh_dir; wf a.yml 'echo "${{ github.action_path }}"'
expect fail "non-allowlisted github property in run" 'github.action_path'
fresh_dir; wf a.yml "echo \"\${{ format('{0}', github.sha) }}\""
expect fail "allowlisted value wrapped in a function" "format('{0}', github.sha)"
fresh_dir; wf a.yml 'echo "${{ github.sha || inputs.ref }}"'
expect fail "allowlisted value OR-ed with a tainted one" 'inputs.ref'
fresh_dir; wf a.yml 'echo "${{ matrix.x"'
expect fail "unterminated expression" 'matrix.x'
fresh_dir; wf b.yaml 'echo "${{ matrix.x }}"'
expect fail ".yaml extension is scanned" 'b.yaml'
fresh_dir; wf a.yml 'echo ok'; wf z.yml 'echo "${{ matrix.x }}"'
expect fail "every non-frozen file is reported" 'z.yml'

# Composite actions under .github/actions are held to the same rule.
fresh_dir; mkdir -p "$tmp/actions/setup"
printf 'runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo "${{ inputs.version }}"\n' >"$tmp/actions/setup/action.yml"
expect fail "local composite action" 'actions/setup/action.yml'

# Must stay allowed.
fresh_dir; wf a.yml 'echo "${{ github.sha }} ${{ github.run_id }} ${{github.run_attempt}} ${{ github.run_number }} ${{ runner.os }} ${{ runner.arch }}"'
expect pass "allowlisted run-identity values"
fresh_dir
printf 'on: pull_request\njobs:\n  build:\n    if: ${{ github.event.pull_request.head.repo.full_name == github.repository }}\n    runs-on: ${{ matrix.os }}\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n          IMG: ${{ matrix.image }}\n        run: echo "$TITLE" "$IMG"\n' >"$tmp/wf/a.yml"
expect pass "expressions only in env/with/if/runs-on"

# Frozen workflows are exempt by name until v0.4.0 graduation ...
fresh_dir; wf release-artifacts.yml 'echo "${{ inputs.tag }}"'
expect pass "frozen workflow is skipped" 'skipped frozen'
# ... and the exemption cannot drift: a missing frozen file is an error.
fresh_dir; rm "$tmp/wf/rollback-drill.yml"
expect error "missing frozen workflow" 'rollback-drill.yml'

if [[ "$fail" -ne 0 ]]; then
  echo "workflow expression-interpolation guard regression: FAILED" >&2
  exit 1
fi
echo "workflow expression-interpolation guard regression: all cases pass"
