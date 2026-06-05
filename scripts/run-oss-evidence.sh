#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BPFCOMPAT_BIN:-./bin/bpfcompat}"
MATRIX="${BPFCOMPAT_MATRIX:-matrices/mvp.yaml}"
TIMEOUT="${BPFCOMPAT_TIMEOUT:-8m}"

EVIDENCE_ROOT="${BPFCOMPAT_OSS_EVIDENCE_ROOT:-evidence/oss-validation}"
REPORT_DIR="${EVIDENCE_ROOT}/reports"
RAW_DIR="${EVIDENCE_ROOT}/raw-runs"
SUMMARY_DOC="${BPFCOMPAT_OSS_SUMMARY_DOC:-${EVIDENCE_ROOT}/summary.md}"

mkdir -p "$REPORT_DIR" "$RAW_DIR"

if [[ ! -x "$BIN" ]]; then
  echo "[oss-evidence] missing CLI binary at $BIN (run: make build)" >&2
  exit 1
fi

bash scripts/build-oss-examples.sh

copy_raw_run() {
  local run_id="$1"
  local case_name="$2"
  local src=".bpfcompat/runs/${run_id}"
  local dst="${RAW_DIR}/${case_name}/${run_id}"

  if [[ ! -d "$src" ]]; then
    echo "[oss-evidence] missing run directory: ${src}" >&2
    exit 1
  fi

  rm -rf "$dst"
  mkdir -p "$dst/input" "$dst/targets"

  cp "$src/metadata.json" "$dst/metadata.json"
  find "$src/input" -maxdepth 1 -type f \( -name "*.yaml" -o -name "*.yml" -o -name "*.json" \) \
    -exec cp {} "$dst/input/" \;

  local target
  for target in "$src"/targets/*; do
    [[ -d "$target" ]] || continue
    local target_id
    target_id="$(basename "$target")"
    mkdir -p "$dst/targets/$target_id"
    local f
    for f in libbpf.log qemu.log serial.log validator-result.json validator.stderr validator-exit-code; do
      if [[ -f "$target/$f" ]]; then
        cp "$target/$f" "$dst/targets/$target_id/$f"
      fi
    done
  done
}

run_case() {
  local name="$1"
  local artifact="$2"
  local manifest="$3"
  local expected_rc="$4"
  local out_json="${REPORT_DIR}/${name}-mvp.json"
  local out_md="${REPORT_DIR}/${name}-mvp.md"

  echo "[oss-evidence] running ${name} (expected rc=${expected_rc})"
  set +e
  "$BIN" test \
    --artifact "$artifact" \
    --manifest "$manifest" \
    --matrix "$MATRIX" \
    --out "$out_json" \
    --markdown "$out_md" \
    --timeout "$TIMEOUT"
  local rc=$?
  set -e

  if [[ "$rc" -ne "$expected_rc" ]]; then
    echo "[oss-evidence] ${name} expected rc=${expected_rc}, got rc=${rc}" >&2
    exit 1
  fi

  local run_id
  run_id="$(jq -r '.run.id' "$out_json")"
  copy_raw_run "$run_id" "$name"
}

run_case "cilium-tracepoint-in-c" \
  "examples/oss/cilium-tracepoint-in-c/tracepoint.bpf.o" \
  "examples/oss/cilium-tracepoint-in-c/manifest.yaml" \
  0

run_case "bcc-execsnoop" \
  "examples/oss/bcc-execsnoop/execsnoop.bpf.o" \
  "examples/oss/bcc-execsnoop/manifest.yaml" \
  2

generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat >"$SUMMARY_DOC" <<EOF
# OSS Validation Evidence

Generated at: \`$generated_at\` (UTC)

## Scope

- Matrix: \`$MATRIX\`
- Report directory: \`$REPORT_DIR\`
- Raw run directory: \`$RAW_DIR\`
- Artifacts:
  - \`examples/oss/cilium-tracepoint-in-c\` (upstream: \`cilium/ebpf\`)
  - \`examples/oss/bcc-execsnoop\` (upstream: \`iovisor/bcc\`)

## Results

| Artifact | Upstream Project | Run ID | Summary | Target Pass/Fail | Required Failing Profiles | Classification Codes |
|---|---|---|---|---|---|---|
EOF

append_row() {
  local name="$1"
  local project="$2"
  local report="${REPORT_DIR}/${name}-mvp.json"
  local run_id summary pass_count fail_count required_failures codes

  run_id="$(jq -r '.run.id' "$report")"
  summary="$(jq -r '.summary.status' "$report")"
  pass_count="$(jq '[.targets[] | select(.status == "pass")] | length' "$report")"
  fail_count="$(jq '[.targets[] | select(.status == "fail")] | length' "$report")"
  required_failures="$(jq -r '[.targets[] | select(.required == true and .status == "fail") | .profile_id] | if length == 0 then "-" else join(", ") end' "$report")"
  codes="$(jq -r '[.targets[] | .classification_code // empty] | unique | if length == 0 then "-" else join(", ") end' "$report")"

  echo "| ${name} | ${project} | ${run_id} | ${summary} | ${pass_count}/${fail_count} | ${required_failures} | ${codes} |" >>"$SUMMARY_DOC"
}

append_row "cilium-tracepoint-in-c" "cilium/ebpf"
append_row "bcc-execsnoop" "iovisor/bcc"

cat >>"$SUMMARY_DOC" <<EOF

## Referenced Files

- \`${REPORT_DIR}/cilium-tracepoint-in-c-mvp.json\`
- \`${REPORT_DIR}/cilium-tracepoint-in-c-mvp.md\`
- \`${REPORT_DIR}/bcc-execsnoop-mvp.json\`
- \`${REPORT_DIR}/bcc-execsnoop-mvp.md\`
- \`${RAW_DIR}/cilium-tracepoint-in-c/*\`
- \`${RAW_DIR}/bcc-execsnoop/*\`
EOF

echo "[oss-evidence] wrote ${SUMMARY_DOC}"
