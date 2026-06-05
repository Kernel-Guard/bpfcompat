#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BPFCOMPAT_BIN:-./bin/bpfcompat}"
MATRIX="${BPFCOMPAT_MATRIX:-matrices/expanded-2026.yaml}"
DRY_RUN="${BPFCOMPAT_DRY_RUN:-0}"

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN="1"
fi

if [[ ! -x "$BIN" ]]; then
  echo "[fetch-matrix-images] missing CLI binary at $BIN (run: make build)" >&2
  exit 1
fi

if [[ ! -f "$MATRIX" ]]; then
  echo "[fetch-matrix-images] missing matrix file: $MATRIX" >&2
  exit 1
fi

tmp_profiles="$(mktemp)"
trap 'rm -f "$tmp_profiles"' EXIT
"$BIN" profile list --matrix "$MATRIX" > "$tmp_profiles"

total=0
cached=0
downloaded=0
manual_local=0
failed=0

echo "[fetch-matrix-images] matrix=$MATRIX dry_run=$DRY_RUN"

while IFS= read -r profile_id; do
  [[ -z "$profile_id" ]] && continue
  total=$((total + 1))
  profile_path="vm/profiles/${profile_id}.yaml"

  if [[ ! -f "$profile_path" ]]; then
    echo "[fetch-matrix-images] ${profile_id}: missing profile file"
    failed=$((failed + 1))
    continue
  fi

  source_url="$(awk -F'"' '/source_url:/ {print $2; exit}' "$profile_path")"
  local_path="$(awk -F'"' '/local_path:/ {print $2; exit}' "$profile_path")"
  distro="$(awk -F': ' '/^distro:/ {gsub(/"/, "", $2); print $2; exit}' "$profile_path")"

  if [[ -z "$local_path" ]]; then
    echo "[fetch-matrix-images] ${profile_id}: missing local_path in profile"
    failed=$((failed + 1))
    continue
  fi

  if [[ -f "$local_path" ]]; then
    echo "[fetch-matrix-images] ${profile_id}: cached (${local_path})"
    cached=$((cached + 1))
    continue
  fi

  if [[ -z "$source_url" ]]; then
    echo "[fetch-matrix-images] ${profile_id}: manual-local image required (${local_path})"
    manual_local=$((manual_local + 1))
    continue
  fi

  if [[ "${distro,,}" == "talos" || "${distro,,}" == "bottlerocket" ]]; then
    echo "[fetch-matrix-images] ${profile_id}: source exists but transport is currently unsupported by SSH runner; skipping prefetch"
    manual_local=$((manual_local + 1))
    continue
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[fetch-matrix-images] ${profile_id}: would download -> ${local_path}"
    continue
  fi

  echo "[fetch-matrix-images] ${profile_id}: downloading"
  if bash vm/scripts/fetch-cloud-image.sh "$source_url" "$local_path"; then
    downloaded=$((downloaded + 1))
  else
    failed=$((failed + 1))
  fi
done < "$tmp_profiles"

echo
echo "[fetch-matrix-images] summary:"
echo "  total profiles:         $total"
echo "  already cached:         $cached"
echo "  downloaded this run:    $downloaded"
echo "  manual-local remaining: $manual_local"
echo "  failed:                 $failed"

if [[ "$failed" -gt 0 ]]; then
  exit 2
fi

