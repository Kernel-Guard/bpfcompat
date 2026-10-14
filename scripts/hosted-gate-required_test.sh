#!/usr/bin/env bash
# Regression suite for scripts/hosted-gate-required.sh.
#
# "Compatibility Gate (hosted runner)" is a required check, but it reports
# green without running the VM gate when its path classifier says a PR is not
# compatibility-relevant. The original inline allowlist omitted pkg/
# (imported by cmd/bpfcompat and internal/) and scripts/ (executed by
# action.yml), so PRs touching only those passed the required gate without
# any VM validation. This table pins the classification, and checks that the
# workflow really delegates to the classifier under test.
#
# BPFCOMPAT_HOSTED_GATE_CLASSIFIER overrides the classifier path so the table
# can be run against an older classification to show what it catches.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
classifier="${BPFCOMPAT_HOSTED_GATE_CLASSIFIER:-$ROOT/scripts/hosted-gate-required.sh}"
workflow="$ROOT/.github/workflows/bpfcompat-example-hosted.yml"

fail=0

# check <expected true|false> <paths...>: all paths form one PR's diff.
check() {
  local expect="$1"; shift
  local got
  got="$(printf '%s\n' "$@" | bash "$classifier")"
  if [[ "$got" == "required=$expect" ]]; then
    printf 'ok:   %-5s <- %s\n' "$expect" "$*"
  else
    printf 'FAIL: expected required=%s, got %q <- %s\n' "$expect" "$got" "$*" >&2
    fail=1
  fi
}

# Single-path diffs.
check true  pkg/schema/x.go
check true  scripts/x.sh
check true  scripts/verify-release-assets.sh
check true  scripts/action-diff.sh
check true  internal/x.go
check true  cmd/bpfcompat/main.go
check true  validator/x.c
check true  vm/scripts/fetch-cloud-image.sh
check true  vendor/modules.txt
check true  action.yml
check true  Makefile
check true  go.mod
check true  .github/workflows/bpfcompat-example-hosted.yml
check false scripts/research/x.py
check false scripts/research/run-study-v1.sh
check false docs/x.md
check false README.md
check false .github/workflows/ci.yml
check false pkgfoo/x.go
check false scripts-old/x.sh

# Multi-path diffs: any relevant path wins, research/docs alone do not.
check true  docs/x.md pkg/schema/x.go
check true  scripts/research/x.py scripts/x.sh
check false docs/x.md README.md scripts/research/x.py

# A last line without a trailing newline is still classified.
got="$(printf 'docs/x.md\npkg/schema/x.go' | bash "$classifier")"
if [[ "$got" == "required=true" ]]; then
  echo "ok:   final path without newline is classified"
else
  echo "FAIL: final path without newline was ignored (got $got)" >&2
  fail=1
fi

# An empty diff does not require the gate.
got="$(bash "$classifier" </dev/null)"
if [[ "$got" == "required=false" ]]; then
  echo "ok:   empty diff -> false"
else
  echo "FAIL: empty diff should not require the gate (got $got)" >&2
  fail=1
fi

# The workflow must use this classifier, not an inline copy that can drift.
if grep -Fq 'bash scripts/hosted-gate-required.sh' "$workflow" \
   && ! grep -Eq '^[[:space:]]*cmd/\*\|' "$workflow"; then
  echo "ok:   hosted workflow delegates to scripts/hosted-gate-required.sh"
else
  echo "FAIL: $workflow does not delegate path classification to scripts/hosted-gate-required.sh" >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo "hosted-gate-required_test: FAILED" >&2
  exit 1
fi
echo "hosted-gate-required_test: all checks passed"
