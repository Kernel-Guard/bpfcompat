#!/usr/bin/env bash
# Fail if generated support docs have drifted from their source of truth.
#
# Today this guards docs/support-matrix.md: it is generated deterministically
# from vm/profiles/*.yaml, so if a profile is added, removed, or reclassified
# without regenerating the page, the committed page no longer matches reality.
# That is exactly the "docs say one thing, the repo does another" drift that
# erodes trust.
#
# The check compares generator output against the COMMITTED page (HEAD), not the
# working tree or index: that catches a stale committed page, an uncommitted
# (never-added) page, and a deleted page alike, independent of local staging.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DOC="docs/support-matrix.md"
fail=0

fresh="$(mktemp)"
head_copy="$(mktemp)"
trap 'rm -f "$fresh" "$head_copy"' EXIT

echo "[check-docs-drift] regenerating ${DOC}"
BPFCOMPAT_SUPPORT_MATRIX_OUT="$fresh" bash scripts/support-matrix.sh >/dev/null

if ! git show "HEAD:${DOC}" > "$head_copy" 2>/dev/null; then
  echo "::error::${DOC} is not committed. Run 'make support-matrix' and commit it." >&2
  fail=1
elif ! diff -u "$head_copy" "$fresh" >/dev/null; then
  echo "::error::${DOC} is out of date. Run 'make support-matrix' and commit the result." >&2
  echo "----- committed (HEAD) vs generated -----" >&2
  diff -u "$head_copy" "$fresh" >&2 || true
  fail=1
fi

if [[ "$fail" -eq 0 ]]; then
  echo "[check-docs-drift] generated support docs are in sync"
fi
exit "$fail"
