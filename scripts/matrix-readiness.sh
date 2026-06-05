#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BPFCOMPAT_BIN:-./bin/bpfcompat}"
MATRIX="${BPFCOMPAT_MATRIX:-matrices/expanded-2026.yaml}"
OUT_DIR="${BPFCOMPAT_READINESS_OUT_DIR:-evidence/profile-catalog}"

if [[ ! -x "$BIN" ]]; then
  echo "[matrix-readiness] missing CLI binary at $BIN (run: make build)" >&2
  exit 1
fi

if [[ ! -f "$MATRIX" ]]; then
  echo "[matrix-readiness] missing matrix file: $MATRIX" >&2
  exit 1
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"
out_file="${OUT_DIR}/matrix-readiness-${timestamp}.md"

tmp_profiles="$(mktemp)"
trap 'rm -f "$tmp_profiles"' EXIT

"$BIN" profile list --matrix "$MATRIX" > "$tmp_profiles"

profile_count="$(wc -l < "$tmp_profiles" | tr -d ' ')"
ready_count=0
auto_download_count=0
manual_import_count=0
unsupported_transport_count=0
missing_profile_count=0

{
  echo "# Matrix Readiness"
  echo
  echo "- Timestamp (UTC): ${timestamp}"
  echo "- Matrix: ${MATRIX}"
  echo "- Profile count: ${profile_count}"
  echo
  echo "| Profile ID | Distro | Kernel Family | Transport | Source Mode | Image State | Ready | Notes |"
  echo "|---|---|---|---|---|---|---|---|"
} > "$out_file"

while IFS= read -r profile_id; do
  profile_path="vm/profiles/${profile_id}.yaml"
  if [[ ! -f "$profile_path" ]]; then
    echo "| ${profile_id} | - | - | - | - | - | no | profile file missing |" >> "$out_file"
    missing_profile_count=$((missing_profile_count + 1))
    continue
  fi

  distro="$(awk -F': ' '/^distro:/ {gsub(/"/, "", $2); print $2; exit}' "$profile_path")"
  kernel_family="$(awk -F': ' '/^kernel_family:/ {gsub(/"/, "", $2); print $2; exit}' "$profile_path")"
  local_path="$(awk -F'"' '/local_path:/ {print $2; exit}' "$profile_path")"
  source_url="$(awk -F'"' '/source_url:/ {print $2; exit}' "$profile_path")"

  source_mode="manual-local"
  if [[ -n "$source_url" ]]; then
    source_mode="url"
  fi

  image_state="missing"
  if [[ -n "$local_path" && -f "$local_path" ]]; then
    image_state="cached"
  fi

  transport="ssh"
  transport_ready="yes"
  case "$(echo "${distro}" | tr '[:upper:]' '[:lower:]')" in
    talos)
      transport="unsupported"
      transport_ready="no"
      ;;
    bottlerocket)
      transport="unsupported"
      transport_ready="no"
      ;;
    flatcar)
      transport="unsupported"
      transport_ready="no"
      ;;
  esac

  case "${profile_id}" in
    amazon-linux-2-4.14)
      transport="unsupported"
      transport_ready="no"
      ;;
  esac

  notes=""
  ready="no"
  if [[ "$transport_ready" != "yes" ]]; then
    unsupported_transport_count=$((unsupported_transport_count + 1))
    notes="transport unsupported by current SSH executor"
  elif [[ "$image_state" == "cached" ]]; then
    ready="yes"
    ready_count=$((ready_count + 1))
    notes="ready to run"
  elif [[ "$source_mode" == "url" ]]; then
    auto_download_count=$((auto_download_count + 1))
    notes="will auto-download on first run (slower cold start)"
  else
    manual_import_count=$((manual_import_count + 1))
    notes="manual image import required (${local_path})"
  fi

  echo "| ${profile_id} | ${distro:--} | ${kernel_family:--} | ${transport} | ${source_mode} | ${image_state} | ${ready} | ${notes} |" >> "$out_file"
done < "$tmp_profiles"

{
  echo
  echo "## Summary"
  echo
  echo "- Ready now (cached image + supported transport): ${ready_count}"
  echo "- Auto-download candidates (supported transport + source URL): ${auto_download_count}"
  echo "- Manual image import required: ${manual_import_count}"
  echo "- Unsupported transport profiles (non-SSH): ${unsupported_transport_count}"
  echo "- Missing profile files: ${missing_profile_count}"
} >> "$out_file"

echo "[matrix-readiness] wrote ${out_file}"
