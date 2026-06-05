#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REPORT_DIR="${BPFCOMPAT_BETA_REPORT_DIR:-evidence/beta-tech}"
OUT_DIR="${BPFCOMPAT_STABILITY_EVIDENCE_DIR:-evidence/production-tech}"
MIN_REPORTS="${BPFCOMPAT_STABILITY_MIN_REPORTS:-3}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"
out_file="${OUT_DIR}/tech-stability-${timestamp}.md"

mapfile -t reports < <(find "$REPORT_DIR" -maxdepth 1 -type f -name 'beta-tech-check-*.md' | sort -r)

overall="ready"
if [[ "${#reports[@]}" -lt "$MIN_REPORTS" ]]; then
  overall="not-ready"
fi

ready_count=0
not_ready_count=0
inspected=0

{
  echo "# Technical Stability Report"
  echo
  echo "- Timestamp (UTC): ${timestamp}"
  echo "- Required report count: ${MIN_REPORTS}"
  echo "- Available report count: ${#reports[@]}"
  echo
  echo "| Report | Gate Status |"
  echo "|---|---|"
} > "$out_file"

for report in "${reports[@]}"; do
  if [[ "$inspected" -ge "$MIN_REPORTS" ]]; then
    break
  fi
  gate_status="$(awk -F': ' '/Gate status:/ {print $2; exit}' "$report" | tr -d '\r' || true)"
  if [[ "$gate_status" == "ready" ]]; then
    ready_count=$((ready_count + 1))
  else
    not_ready_count=$((not_ready_count + 1))
    overall="not-ready"
  fi
  echo "| ${report} | ${gate_status:-unknown} |" >> "$out_file"
  inspected=$((inspected + 1))
done

{
  echo
  echo "## Summary"
  echo
  echo "- inspected reports: ${inspected}"
  echo "- ready reports: ${ready_count}"
  echo "- not-ready reports: ${not_ready_count}"
  echo "- gate status: ${overall}"
} >> "$out_file"

echo "[tech-stability] ${overall}: ${out_file}"
if [[ "$overall" == "ready" ]]; then
  exit 0
fi
exit 2

