#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

fixture() {
  local path="$1"
  local number="$2"
  cat > "$tmp_dir/alerts.json" <<JSON
[
  {
    "number": ${number},
    "html_url": "https://example.invalid/alerts/${number}",
    "rule": {"id": "go/example", "security_severity_level": "high"},
    "most_recent_instance": {"location": {"path": "${path}"}}
  }
]
JSON
}

fixture "internal/api/server.go" 1
BPFCOMPAT_CODE_SCANNING_ALERTS_JSON="$tmp_dir/alerts.json" \
  bash scripts/check-production-code-scanning.sh Kernel-Guard/bpfcompat refs/heads/main

fixture "internal/vm/virtme_ng.go" 2
BPFCOMPAT_CODE_SCANNING_ALERTS_JSON="$tmp_dir/alerts.json" \
  bash scripts/check-production-code-scanning.sh Kernel-Guard/bpfcompat refs/heads/main

fixture "internal/vm/ssh.go" 3
if BPFCOMPAT_CODE_SCANNING_ALERTS_JSON="$tmp_dir/alerts.json" \
  bash scripts/check-production-code-scanning.sh Kernel-Guard/bpfcompat refs/heads/main; then
  echo "expected supported VM alert to fail the gate" >&2
  exit 1
fi

fixture "cmd/bpfcompat/main.go" 4
if BPFCOMPAT_CODE_SCANNING_ALERTS_JSON="$tmp_dir/alerts.json" \
  bash scripts/check-production-code-scanning.sh Kernel-Guard/bpfcompat refs/heads/main; then
  echo "expected supported CLI entrypoint alert to fail the gate" >&2
  exit 1
fi

echo "[production-code-scanning-test] PASS"
