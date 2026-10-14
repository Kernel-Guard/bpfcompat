#!/usr/bin/env bash
# Fixture reasons quote literal GitHub expressions, not shell expansions.
# shellcheck disable=SC2016
# Regression suite for scripts/check-action-input-interpolation.sh.
#
# The real action.yml must pass. Each injection fixture must be rejected for
# the stated reason; each safe fixture (expressions only in env:/with:/if:)
# must pass, so the guard cannot be satisfied by rejecting everything.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$ROOT/scripts/check-action-input-interpolation.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bash "$script" >"$tmp/real.log"
grep -Fq 'PASS' "$tmp/real.log"
echo "ok:   repository action.yml passes"

fail=0
# check <expect pass|fail> <description> [reason]; reads the fixture from stdin.
check() {
  local expect="$1" desc="$2" reason="${3:-}" got
  cat >"$tmp/action.yml"
  if bash "$script" "$tmp/action.yml" >"$tmp/out.log" 2>&1; then
    got=pass
  else
    got=fail
  fi
  if [[ "$got" != "$expect" ]]; then
    echo "FAIL: ${desc}: expected ${expect}, got ${got}" >&2
    cat "$tmp/out.log" >&2
    fail=1
    return
  fi
  if [[ -n "$reason" ]] && ! grep -Fq -- "$reason" "$tmp/out.log"; then
    echo "FAIL: ${desc}: rejected, but not for: ${reason}" >&2
    cat "$tmp/out.log" >&2
    fail=1
    return
  fi
  echo "ok:   ${desc} -> ${got}"
}

check fail "input in a single-line run" '${{ inputs.artifact }}' <<'EOF'
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "${{ inputs.artifact }}"
EOF

check fail "input in a multi-line run" 'run line 3' <<'EOF'
runs:
  using: composite
  steps:
    - name: Run
      shell: bash
      env:
        INPUT_COMMAND: ${{ inputs.command }}
      run: |
        set -euo pipefail
        echo "$INPUT_COMMAND"
        out_path="$(resolve_path "${{ inputs.out }}")"
EOF

check fail "input without spaces, odd case" 'inputs.Disk-Resize' <<'EOF'
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        x=${{inputs.Disk-Resize}}
EOF

check fail "input via index syntax" "inputs['timeout']" <<'EOF'
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        t="${{ inputs['timeout'] }}"
EOF

check fail "input wrapped in a function" 'format(' <<'EOF'
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        t="${{ format('{0}s', inputs.timeout) }}"
EOF

check fail "github.head_ref in run" 'github.head_ref' <<'EOF'
runs:
  using: composite
  steps:
    - shell: bash
      run: git checkout "${{ github.head_ref }}"
EOF

check fail "github.event data in a workflow job run" 'jobs.build.steps[0]' <<'EOF'
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
EOF

check pass "input only in env" <<'EOF'
runs:
  using: composite
  steps:
    - shell: bash
      env:
        INPUT_ARTIFACT: ${{ inputs.artifact }}
      run: |
        artifact_input="$INPUT_ARTIFACT"
EOF

check pass "input only in if and with" <<'EOF'
runs:
  using: composite
  steps:
    - if: ${{ inputs.build == 'true' && github.event_name == 'push' }}
      shell: bash
      run: make build
    - uses: actions/upload-artifact@v4
      with:
        name: ${{ inputs.out }}
EOF

check pass "trusted contexts in run" <<'EOF'
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        echo "${{ github.action_path }} ${{ runner.os }} ${{ steps.run.outputs.result }}"
        echo "${{ github.event_name }}"
EOF

# run_fixture <expect> <desc> <reason> <run-line>: composite action, one step.
fx() {
  local expect="$1" desc="$2" reason="$3" line="$4"
  printf 'runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n        %s\n' "$line" \
    | check "$expect" "$desc" "$reason"
}

# Whole-context references: no property needed to leak caller data.
fx fail "toJSON(inputs) in run" 'toJSON(inputs)' 'echo "${{ toJSON(inputs) }}"'
fx fail "toJSON(github) in run" 'toJSON(github)' 'echo "${{ toJSON(github) }}"'
fx fail "bare inputs in run" '${{ inputs }}' 'echo "${{ inputs }}"'
fx fail "bare github in run" '${{ github }}' 'echo "${{ github }}"'
fx fail "github['event'] index in run" "github['event']" "echo \"\${{ github['event'].pull_request.title }}\""
fx fail "computed github index in run" 'github[format(' "echo \"\${{ github[format('{0}', 'event')] }}\""

# Indirect: env values are often set from inputs; read \$X in the shell instead.
fx fail "env.X in run" '${{ env.INPUT_ARTIFACT }}' 'a="${{ env.INPUT_ARTIFACT }}"'
fx fail "env[...] in run" "env['INPUT_ARTIFACT']" "a=\"\${{ env['INPUT_ARTIFACT'] }}\""

# A '}}' inside a string literal must not end the expression early.
fx fail "}} inside a string literal" "inputs.x" "t=\"\${{ format('}}', inputs.x) }}\""
fx fail "}} after an escaped quote" "inputs.x" "t=\"\${{ format('it''s }}', inputs.x) }}\""
fx fail "unterminated expression" 'inputs.x' 'echo "${{ inputs.x"'

# Must stay allowed: safe github properties, properties merely named like a
# tainted context, and tainted words in plain shell outside expressions.
fx pass "safe github properties" '' "echo \"\${{ github.action_path }} \${{ github['action_path'] }} \${{ github.event_name }}\""
fx pass "outputs named env/inputs" '' 'echo "${{ steps.run.outputs.env }} ${{ steps.run.outputs.inputs }}"'
fx pass "shell env var, no expression" '' 'echo "$INPUT_ARTIFACT" "${env:-x}" "${inputs:-y}"'

check fail "unparseable file" 'cannot parse' <<'EOF'
runs: [unterminated
EOF

if [[ "$fail" -ne 0 ]]; then
  echo "action input-interpolation guard regression: FAILED" >&2
  exit 1
fi
echo "action input-interpolation guard regression: all cases pass"
