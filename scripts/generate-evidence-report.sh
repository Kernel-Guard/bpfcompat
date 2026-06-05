#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUTPUT="docs/mvp-acceptance-evidence.md"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

fixtures=(
  "simple-pass"
  "ringbuf-modern"
  "perfbuf-fallback"
  "core-relocation"
  "unsupported-attach"
  "unknown-load-fail"
)

for fixture in "${fixtures[@]}"; do
  report="reports/${fixture}-mvp.json"
  if [[ ! -f "$report" ]]; then
    echo "[evidence] missing report: $report (run: make acceptance)" >&2
    exit 1
  fi
done

libbpf_log_count="$(find .bpfcompat/runs -name 'libbpf.log' | wc -l | tr -d ' ')"
raw_json_count="$(find .bpfcompat/runs -name '*.json' | wc -l | tr -d ' ')"

cat >"$OUTPUT" <<EOF
# MVP Acceptance Evidence

Generated at: \`$GENERATED_AT\` (UTC)

## Scope

- Matrix: \`matrices/mvp.yaml\`
- Profiles: \`ubuntu-18.04-4.15\`, \`ubuntu-20.04-5.4\`, \`ubuntu-22.04-5.15\`, \`ubuntu-22.04-minimal-5.15\`, \`ubuntu-24.04-6.8\`, \`debian-11-5.10\`, \`debian-12-6.1\`, \`debian-13-6.12\`
- Fixtures: simple pass, ringbuf modern, perfbuf fallback, CO-RE relocation failure, unsupported attach, unknown non-ELF load failure

## Fixture Results

| Fixture | Summary | Target Pass/Fail | Classification Codes |
|---|---|---|---|
EOF

append_row() {
  local fixture="$1"
  local report="reports/${fixture}-mvp.json"
  local summary
  local pass_count
  local fail_count
  local codes

  summary="$(jq -r '.summary.status' "$report")"
  pass_count="$(jq '[.targets[] | select(.status == "pass")] | length' "$report")"
  fail_count="$(jq '[.targets[] | select(.status == "fail")] | length' "$report")"
  codes="$(jq -r '[.. | objects | (.classification_code? // .code? // empty)] | unique | if length == 0 then "-" else join(", ") end' "$report")"

  echo "| ${fixture} | ${summary} | ${pass_count}/${fail_count} | ${codes} |" >>"$OUTPUT"
}

for fixture in "${fixtures[@]}"; do
  append_row "$fixture"
done

cat >>"$OUTPUT" <<EOF

## Gate Assertions

- \`simple-pass\`: summary is \`pass\`, includes 8 targets, and has no \`infra_error\` targets.
- \`ringbuf-modern\`: includes \`UNSUPPORTED_MAP_TYPE\` and markdown guidance mentions perf fallback.
- \`perfbuf-fallback\`: summary is \`pass\` and markdown references \`perf_event\`.
- \`core-relocation\`: includes both \`MISSING_BTF\` and \`CORE_RELOCATION_FAILURE\` and per-target BTF fields.
- \`unsupported-attach\`: includes \`UNSUPPORTED_ATTACH_TYPE\` or \`UNSUPPORTED_PROG_TYPE\`.
- \`unknown-load-fail\`: includes \`UNKNOWN\` classification for non-ELF load failure.

## Raw Artifact Presence

- \`libbpf.log\` files under \`.bpfcompat/runs/\`: ${libbpf_log_count}
- \`*.json\` files under \`.bpfcompat/runs/\`: ${raw_json_count}

## Referenced Reports

- \`reports/simple-pass-mvp.json\` / \`reports/simple-pass-mvp.md\`
- \`reports/ringbuf-modern-mvp.json\` / \`reports/ringbuf-modern-mvp.md\`
- \`reports/perfbuf-fallback-mvp.json\` / \`reports/perfbuf-fallback-mvp.md\`
- \`reports/core-relocation-mvp.json\` / \`reports/core-relocation-mvp.md\`
- \`reports/unsupported-attach-mvp.json\` / \`reports/unsupported-attach-mvp.md\`
- \`reports/unknown-load-fail-mvp.json\` / \`reports/unknown-load-fail-mvp.md\`
EOF

echo "[evidence] wrote ${OUTPUT}"
