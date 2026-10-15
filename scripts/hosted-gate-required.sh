#!/usr/bin/env bash
# Decide whether a pull request needs the hosted VM compatibility gate.
#
#   git diff --name-only BASE HEAD | scripts/hosted-gate-required.sh
#
# Reads changed repository paths (one per line) on stdin and prints exactly
# one line, `required=true` or `required=false`, ready to append to
# $GITHUB_OUTPUT. Used by .github/workflows/bpfcompat-example-hosted.yml
# ("Compatibility Gate (hosted runner)", a required check) and exercised by
# scripts/hosted-gate-required_test.sh, so the test covers the production
# classification rather than a copy of it.
#
# A path requires the gate when it can change what the gate builds or runs:
#   - Go sources and modules: cmd/, internal/, pkg/ (pkg/ is imported by
#     cmd/bpfcompat and internal/), vendor/, go.mod/go.sum/go.work*;
#   - the validator, fixtures and VM inputs: validator/, examples/,
#     matrices/, suites/, vm/, Makefile;
#   - the published action and the scripts it and the Makefile execute:
#     action.yml, scripts/ (e.g. scripts/verify-release-assets.sh,
#     scripts/action-diff.sh). Every scripts/ path counts, including docs or
#     data under it, because it is cheaper to run the gate than to keep a
#     per-file list of what the action calls in sync;
#   - this classifier's caller: the hosted workflow itself.
# Exception: scripts/research/ holds the offline research-study tooling. It
# is not referenced by action.yml, the Makefile, cmd/, internal/ or pkg/,
# and never runs in the gate, so changes there alone do not require it.
#
# Anything else (docs/, README.md, other workflows, ...) does not require
# the gate. The whole of stdin is consumed even after a match so that a
# producer such as `git diff` never dies of SIGPIPE under `set -o pipefail`.
set -euo pipefail

required=false
while IFS= read -r path || [[ -n "$path" ]]; do
  case "$path" in
    \"*)
      # git C-quotes paths with unusual characters (non-ASCII, quotes,
      # tabs, newlines). They cannot be classified reliably, so require
      # the gate rather than silently skip it.
      required=true
      ;;
    scripts/research/*)
      ;;
    cmd/*|internal/*|pkg/*|validator/*|examples/*|matrices/*|suites/*|vm/*|vendor/*|scripts/*|action.yml|Makefile|go.mod|go.sum|go.work|go.work.sum|.github/workflows/bpfcompat-example-hosted.yml)
      required=true
      ;;
  esac
done
echo "required=$required"
