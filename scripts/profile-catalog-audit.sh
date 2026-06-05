#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BPFCOMPAT_BIN:-./bin/bpfcompat}"
MATRIX="${BPFCOMPAT_MATRIX:-matrices/extended-15.yaml}"
MAX_TIME="${BPFCOMPAT_AUDIT_CURL_TIMEOUT:-60}"
OUT_DIR="${BPFCOMPAT_AUDIT_OUT_DIR:-evidence/profile-catalog}"

probe_http_code() {
  local url="$1"
  local code="000"
  local attempt
  for attempt in 1 2 3; do
    code="$(curl -L -I -o /dev/null -s -w '%{http_code}' --max-time "$MAX_TIME" "$url" || true)"
    if [[ "$code" != "000" ]]; then
      break
    fi
    sleep 1
  done
  printf '%s' "$code"
}

if [[ ! -x "$BIN" ]]; then
  echo "[profile-audit] missing CLI binary at $BIN (run: make build)" >&2
  exit 1
fi

if [[ ! -f "$MATRIX" ]]; then
  echo "[profile-audit] missing matrix file: $MATRIX" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "[profile-audit] curl is required" >&2
  exit 1
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"
out_file="${OUT_DIR}/profile-catalog-audit-${timestamp}.md"

tmp_profiles="$(mktemp)"
trap 'rm -f "$tmp_profiles"' EXIT

"$BIN" profile list --matrix "$MATRIX" > "$tmp_profiles"

profile_count="$(wc -l < "$tmp_profiles" | tr -d ' ')"
ok_count=0
bad_count=0
manual_ready=0
manual_missing=0

{
  echo "# Profile Catalog Audit"
  echo
  echo "- Timestamp (UTC): ${timestamp}"
  echo "- Matrix: ${MATRIX}"
  echo "- Profile count: ${profile_count}"
  echo
  echo "| Profile ID | Mode | HTTP | Local Image | Source URL |"
  echo "|---|---|---:|---|---|"
} > "$out_file"

while IFS= read -r profile_id; do
  profile_path="vm/profiles/${profile_id}.yaml"
  if [[ ! -f "$profile_path" ]]; then
    echo "| ${profile_id} | missing | 000 | - | profile file missing |" >> "$out_file"
    bad_count=$((bad_count + 1))
    continue
  fi

  source_url="$(awk -F'"' '/source_url:/ {print $2}' "$profile_path")"
  local_path="$(awk -F'"' '/local_path:/ {print $2}' "$profile_path")"
  local_state="missing"
  if [[ -n "$local_path" && -f "$local_path" ]]; then
    local_state="cached"
  fi

  if [[ -n "$source_url" ]]; then
    http_code="$(probe_http_code "$source_url")"
    if [[ "$http_code" == "200" || "$http_code" == "302" ]]; then
      ok_count=$((ok_count + 1))
    else
      bad_count=$((bad_count + 1))
    fi
    echo "| ${profile_id} | url | ${http_code} | ${local_state} | ${source_url} |" >> "$out_file"
  else
    http_code="n/a"
    if [[ "$local_state" == "cached" ]]; then
      manual_ready=$((manual_ready + 1))
    else
      manual_missing=$((manual_missing + 1))
    fi
    echo "| ${profile_id} | manual-local | ${http_code} | ${local_state} | - |" >> "$out_file"
  fi
done < "$tmp_profiles"

{
  echo
  echo "## Summary"
  echo
  echo "- Reachable (200/302): ${ok_count}"
  echo "- Unreachable/timeout/other: ${bad_count}"
  echo "- Manual-local profiles with cached image: ${manual_ready}"
  echo "- Manual-local profiles missing image: ${manual_missing}"
} >> "$out_file"

echo "[profile-audit] wrote ${out_file}"
