#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${1:-${GITHUB_REPOSITORY:-}}"
REF="${2:-${GITHUB_REF:-refs/heads/main}}"
FIXTURE="${BPFCOMPAT_CODE_SCANNING_ALERTS_JSON:-}"

if [[ -z "$REPOSITORY" ]]; then
  echo "usage: $0 <owner/repository> [git-ref]" >&2
  exit 2
fi

tmp_alerts="$(mktemp)"
trap 'rm -f "$tmp_alerts"' EXIT

if [[ -n "$FIXTURE" ]]; then
  if [[ ! -f "$FIXTURE" ]]; then
    echo "[production-code-scanning] fixture not found: $FIXTURE" >&2
    exit 2
  fi
  python3 - "$FIXTURE" > "$tmp_alerts" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    alerts = json.load(handle)
for alert in alerts:
    instance = alert.get("most_recent_instance") or {}
    location = instance.get("location") or {}
    rule = alert.get("rule") or {}
    fields = (
        alert.get("number", ""),
        rule.get("security_severity_level") or rule.get("severity") or "unknown",
        rule.get("id", "unknown"),
        location.get("path", ""),
        alert.get("html_url", ""),
    )
    print("\t".join(str(field).replace("\t", " ") for field in fields))
PY
else
  if ! command -v gh >/dev/null 2>&1; then
    echo "[production-code-scanning] gh is required" >&2
    exit 2
  fi
  gh api --method GET --paginate \
    "repos/${REPOSITORY}/code-scanning/alerts" \
    -f state=open \
    -f ref="$REF" \
    -f per_page=100 \
    --jq '.[] | [.number, (.rule.security_severity_level // .rule.severity // "unknown"), .rule.id, (.most_recent_instance.location.path // ""), .html_url] | @tsv' \
    > "$tmp_alerts"
fi

is_production_path() {
  case "$1" in
    internal/vm/firecracker.go|internal/vm/virtme_ng.go)
      return 1
      ;;
    internal/artifact/*|internal/classifier/*|internal/compare/*|internal/envref/*|\
    internal/freshness/*|internal/manifest/*|internal/matrix/*|internal/report/*|\
    internal/runner/*|internal/safepath/*|internal/suite/*|internal/version/*|\
    internal/vm/*|cmd/bpfcompat/main.go|cmd/bpfcompat/kernel_freshness.go|\
    cmd/bpfcompat/kernel_sweep.go|cmd/bpfcompat/report_summary.go|cmd/bpfcompat/suite.go)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

failure_count=0
while IFS=$'\t' read -r number severity rule path url; do
  [[ -n "$number" ]] || continue
  if is_production_path "$path"; then
    echo "::error file=${path}::Open production-boundary code-scanning alert #${number} (${severity}, ${rule}): ${url}"
    failure_count=$((failure_count + 1))
  fi
done < "$tmp_alerts"

if (( failure_count > 0 )); then
  echo "[production-code-scanning] FAIL: ${failure_count} open production-boundary alert(s) for ${REF}" >&2
  exit 1
fi

echo "[production-code-scanning] PASS: no open production-boundary alerts for ${REF}"
