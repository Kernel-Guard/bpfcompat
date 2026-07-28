#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

base="${BPFCOMPAT_FREEZE_BASE:-${1:-}}"
approved="${BPFCOMPAT_EXPERIMENTAL_CHANGE_APPROVED:-0}"

if [[ -z "$base" ]]; then
  echo "[experimental-freeze] base revision is required" >&2
  exit 2
fi
git rev-parse --verify "$base^{commit}" >/dev/null

changed="$(git diff --name-only "${base}...HEAD")"
protected="$(
  printf '%s\n' "$changed" |
    grep -E '^(internal/(api|runtime|cloudregistry|agent)/|cmd/bpfcompat/(agent(_test)?|admin(_audit)?(_test)?)\.go$|packaging/systemd/bpfcompat-agent|docs/(openapi\.yaml|api-web-ui|runtime-|production-runtime-agent))' ||
    true
)"

if [[ -z "$protected" ]]; then
  echo "[experimental-freeze] PASS no frozen-surface changes"
  exit 0
fi
if [[ "$approved" == "1" ]]; then
  echo "[experimental-freeze] PASS approved maintenance/security change"
  printf '%s\n' "$protected"
  exit 0
fi

echo "[experimental-freeze] frozen runtime/API files changed:" >&2
printf '%s\n' "$protected" >&2
echo "[experimental-freeze] add the experimental-change-approved label after explicit maintainer review" >&2
exit 1
