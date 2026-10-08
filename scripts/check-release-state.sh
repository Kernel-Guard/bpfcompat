#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 <owner/repo> <release-tag>" >&2
  exit 2
fi

repo="$1"
tag="$2"

[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "[release-state] invalid repository: ${repo}" >&2
  exit 2
}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || {
  echo "[release-state] invalid release tag: ${tag}" >&2
  exit 2
}
command -v gh >/dev/null 2>&1 || {
  echo "[release-state] GitHub CLI is required" >&2
  exit 1
}

lookup_error="$(mktemp)"
trap 'rm -f "$lookup_error"' EXIT

set +e
is_draft="$(gh api "repos/${repo}/releases/tags/${tag}" --jq .draft 2>"$lookup_error")"
lookup_rc=$?
set -e

if [[ "$lookup_rc" -eq 0 ]]; then
  if [[ "$is_draft" != "true" ]]; then
    echo "[release-state] release ${tag} is already public; refusing mutation" >&2
    exit 1
  fi
  echo "[release-state] existing draft ${tag} may be resumed"
  exit 0
fi

if grep -q "HTTP 404" "$lookup_error"; then
  echo "[release-state] no existing release for ${tag}; candidate staging may proceed"
  exit 0
fi

cat "$lookup_error" >&2
echo "[release-state] could not establish release state; refusing to proceed" >&2
exit 1
