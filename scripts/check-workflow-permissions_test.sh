#!/usr/bin/env bash
# Regression suite for scripts/check-workflow-permissions.sh.
#
# The real repository must pass. Each fixture below must be rejected: they
# are the ways a write-scoped GITHUB_TOKEN can reach jobs that never asked for
# it (top-level grants, shorthands, an omitted block) or slip past review
# (an unlisted job grant, a stale allowlist entry).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$ROOT/scripts/check-workflow-permissions.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bash "$script" >"$tmp/real.log"
grep -Fq 'PASS' "$tmp/real.log"
echo "ok:   repository workflows pass"

allow="$tmp/allow"
cat >"$allow" <<'EOF'
# fixture allowlist
w.yml build packages push the image
EOF

# check <expect pass|fail> <description> [reason] [file-name]; reads the
# fixture workflow from stdin. A rejected fixture must be rejected for the
# stated reason, so an unrelated failure or a crash cannot pass for one.
check() {
  local expect="$1" desc="$2" reason="${3:-}" file="${4:-w.yml}"
  rm -rf "$tmp/wf"; mkdir -p "$tmp/wf"
  cat >"$tmp/wf/$file"
  if BPFCOMPAT_WORKFLOWS_DIR="$tmp/wf" BPFCOMPAT_WORKFLOW_WRITE_ALLOWLIST="$allow" \
    bash "$script" >"$tmp/out.log" 2>&1; then
    got=pass
  else
    got=fail
  fi
  if [[ "$got" != "$expect" ]]; then
    echo "FAIL: ${desc}: expected ${expect}, got ${got}" >&2
    cat "$tmp/out.log" >&2
    exit 1
  fi
  if [[ -n "$reason" ]] && ! grep -Fq -- "$reason" "$tmp/out.log"; then
    echo "FAIL: ${desc}: rejected, but not for: ${reason}" >&2
    cat "$tmp/out.log" >&2
    exit 1
  fi
  echo "ok:   ${desc} -> ${expect}"
}

base_job='jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      packages: write
    steps:
      - run: true'

check pass "read-only top level with allowlisted job write" <<EOF
on: push
permissions:
  contents: read
$base_job
EOF

check pass "empty top-level permissions" <<EOF
on: push
permissions: {}
$base_job
EOF

check pass "read-all top level" <<EOF
on: push
permissions: read-all
$base_job
EOF

check fail "top-level contents: write" "grants write to every job" <<EOF
on: push
permissions:
  contents: write
$base_job
EOF

check fail "top-level write hidden among reads" "grants write to every job" <<EOF
on: push
permissions:
  contents: read
  actions: read
  id-token: write
$base_job
EOF

check fail "top-level flow-mapping write" "grants write to every job" <<EOF
on: push
permissions: {contents: read, issues: write}
$base_job
EOF

check fail "top-level quoted write" "grants write to every job" <<EOF
on: push
permissions:
  contents: "write"
$base_job
EOF

check fail "top-level write-all" "is not read-only" <<EOF
on: push
permissions: write-all
$base_job
EOF

check fail "missing top-level permissions" "no top-level permissions" <<EOF
on: push
$base_job
EOF

check fail "unknown top-level shorthand" "is not read-only" <<EOF
on: push
permissions: admin
$base_job
EOF

check fail "job-level write-all" "is not allowed" <<'EOF'
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions: write-all
    steps:
      - run: true
EOF

check fail "job-level write not in the allowlist" "'contents: write' is not in" <<'EOF'
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      packages: write
      contents: write
    steps:
      - run: true
EOF

check fail "allowlisted permission granted on a different job" "w.yml/other: job-level 'packages: write' is not in" <<'EOF'
on: push
permissions:
  contents: read
jobs:
  other:
    runs-on: ubuntu-24.04
    permissions:
      packages: write
    steps:
      - run: true
EOF

check fail "stale allowlist entry (grant removed)" "stale allowlist entry" <<'EOF'
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - run: true
EOF

check fail "duplicate permission key (write then read)" "duplicate key" <<EOF
on: push
permissions:
  contents: write
  contents: read
$base_job
EOF

check fail "duplicate top-level permissions block" "duplicate key" <<EOF
on: push
permissions: write-all
permissions: {}
$base_job
EOF

check fail "uppercase .YML extension is scanned" "grants write to every job" evil.YML <<EOF
on: push
permissions:
  contents: write
$base_job
EOF

check fail "capitalised Write level" "unknown permission level" <<'EOF'
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      packages: Write
    steps:
      - run: true
EOF

# The strict loader is a SafeLoader: python tags are refused, never executed.
check fail "python object tag is refused" "invalid or ambiguous YAML" <<EOF
on: push
permissions: !!python/object/apply:os.system ["touch $tmp/pwned"]
$base_job
EOF
if [[ -e "$tmp/pwned" ]]; then
  echo "FAIL: a python tag in a workflow was executed" >&2
  exit 1
fi

# An allowlist line without a justification is rejected.
printf 'w.yml build packages\n' >"$allow"
check fail "allowlist entry without justification" "expected '<workflow> <job> <permission> <justification>'" <<EOF
on: push
permissions:
  contents: read
$base_job
EOF

echo "check-workflow-permissions_test: all checks passed"
