#!/usr/bin/env bash
# Regression guard for the composite action's OCI-artifact handling.
#
# v0.3.2 shipped an action that ran the `artifact` input through workspace path
# resolution + a local-file existence check unconditionally, so a remote OCI
# reference (ghcr.io/org/gadget:latest) was mangled into "$WORKSPACE/ghcr.io/..."
# and rejected as "artifact not found" before the CLI could pull it — this broke
# every gadget-by-OCI-reference lane (e.g. Inspektor Gadget). The fix added
# is_remote_artifact() so remote refs pass through untouched.
#
# This test EXTRACTS that function straight out of action.yml (the single source
# of truth — no duplicated logic to drift) and asserts its classification, so
# the bug cannot silently return.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="$ROOT/action.yml"

fn="$(awk '
  /^        is_remote_artifact\(\) \{/ {f=1}
  f {print}
  f && /^        \}/ {exit}
' "$ACTION")"

if [[ -z "$fn" ]]; then
  echo "FAIL: could not extract is_remote_artifact() from $ACTION" >&2
  exit 1
fi
# shellcheck disable=SC2086
eval "$fn"

fail=0
assert() { # $1=ref  $2=REMOTE|local
  local got
  if is_remote_artifact "$1"; then got=REMOTE; else got=local; fi
  if [[ "$got" != "$2" ]]; then
    printf 'FAIL: %-55s -> %s (want %s)\n' "$1" "$got" "$2" >&2
    fail=1
  else
    printf 'ok:   %-55s -> %s\n' "$1" "$got"
  fi
}

# Remote OCI references — must pass through to the CLI verbatim.
assert "ghcr.io/inspektor-gadget/gadget/trace_open:latest" REMOTE
assert "ghcr.io/inspektor-gadget/gadget/trace_exec:latest" REMOTE
assert "docker.io/library/foo@sha256:0123456789abcdef" REMOTE
assert "quay.io/org/repo:tag" REMOTE
assert "registry.example.com:443/a/b:1" REMOTE
assert "localhost:5000/repo:tag" REMOTE
assert "localhost/repo" REMOTE

# Local paths — must keep going through path resolution + existence check.
assert "build/probe.bpf.o" local
assert "./build/probe.bpf.o" local
assert "../artifacts/x.bpf.o" local
assert "/abs/path/x.bpf.o" local
assert "simple_pass.bpf.o" local
assert "reports/out.json" local

if [[ "$fail" -ne 0 ]]; then
  echo "artifact-ref detection regression: FAILED" >&2
  exit 1
fi
echo "artifact-ref detection regression: all cases pass"
