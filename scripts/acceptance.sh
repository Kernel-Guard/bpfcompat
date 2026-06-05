#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BPFCOMPAT_BIN:-./bin/bpfcompat}"
MATRIX="${BPFCOMPAT_MATRIX:-matrices/mvp.yaml}"
TIMEOUT="${BPFCOMPAT_TIMEOUT:-8m}"

required_images=(
  "vm/cache/ubuntu-18.04.qcow2"
  "vm/cache/ubuntu-20.04.qcow2"
  "vm/cache/ubuntu-22.04.qcow2"
  "vm/cache/ubuntu-22.04-minimal.qcow2"
  "vm/cache/ubuntu-24.04.qcow2"
  "vm/cache/debian-11.qcow2"
  "vm/cache/debian-12.qcow2"
  "vm/cache/debian-13.qcow2"
)

for image in "${required_images[@]}"; do
  if [[ ! -f "$image" ]]; then
    echo "[acceptance] missing VM image: $image (run: make vm-images)" >&2
    exit 1
  fi
done

if [[ ! -x "$BIN" ]]; then
  echo "[acceptance] missing CLI binary at $BIN (run: make build)" >&2
  exit 1
fi

mkdir -p reports

run_case() {
  local name="$1"
  local artifact="$2"
  local manifest="$3"
  local expected_rc="$4"

  local out="reports/${name}-mvp.json"
  local markdown="reports/${name}-mvp.md"

  echo "[acceptance] running ${name} (expected rc=${expected_rc})"
  set +e
  "$BIN" test \
    --artifact "$artifact" \
    --manifest "$manifest" \
    --matrix "$MATRIX" \
    --out "$out" \
    --markdown "$markdown" \
    --timeout "$TIMEOUT"
  local rc=$?
  set -e

  if [[ "$rc" -ne "$expected_rc" ]]; then
    echo "[acceptance] ${name} expected rc=${expected_rc}, got rc=${rc}" >&2
    exit 1
  fi
}

run_case "simple-pass" \
  "examples/simple-pass/simple_pass.bpf.o" \
  "examples/simple-pass/manifest.yaml" \
  0

run_case "ringbuf-modern" \
  "examples/ringbuf-modern/ringbuf_modern.bpf.o" \
  "examples/ringbuf-modern/manifest.yaml" \
  2

run_case "perfbuf-fallback" \
  "examples/perfbuf-fallback/perfbuf_fallback.bpf.o" \
  "examples/perfbuf-fallback/manifest.yaml" \
  0

run_case "core-relocation" \
  "examples/core-relocation-fail/core_relocation_fail.bpf.o" \
  "examples/core-relocation-fail/manifest.yaml" \
  2

run_case "unsupported-attach" \
  "examples/unsupported-attach/unsupported_attach.bpf.o" \
  "examples/unsupported-attach/manifest.yaml" \
  2

run_case "unknown-load-fail" \
  "examples/unknown-load-fail/invalid_object.bin" \
  "examples/unknown-load-fail/manifest.yaml" \
  2

echo "[acceptance] validating report expectations"
jq -e '.summary.status == "pass"' reports/simple-pass-mvp.json >/dev/null
jq -e '.targets | length == 8' reports/simple-pass-mvp.json >/dev/null
jq -e '[.targets[] | select(.status == "infra_error")] | length == 0' reports/simple-pass-mvp.json >/dev/null
grep -q "Ubuntu 22.04" reports/simple-pass-mvp.md

jq -e '.. | objects | select(.classification_code? == "UNSUPPORTED_MAP_TYPE" or .code? == "UNSUPPORTED_MAP_TYPE")' reports/ringbuf-modern-mvp.json >/dev/null
grep -qi "perf" reports/ringbuf-modern-mvp.md

jq -e '.summary.status == "pass"' reports/perfbuf-fallback-mvp.json >/dev/null
grep -q "perf_event" reports/perfbuf-fallback-mvp.md

jq -e '.. | objects | select(.classification_code? == "MISSING_BTF" or .code? == "MISSING_BTF")' reports/core-relocation-mvp.json >/dev/null
jq -e '.. | objects | select(.classification_code? == "CORE_RELOCATION_FAILURE" or .code? == "CORE_RELOCATION_FAILURE")' reports/core-relocation-mvp.json >/dev/null
jq -e '.targets[] | has("btf")' reports/core-relocation-mvp.json >/dev/null

jq -e '.. | objects | select(.classification_code? == "UNSUPPORTED_ATTACH_TYPE" or .classification_code? == "UNSUPPORTED_PROG_TYPE" or .code? == "UNSUPPORTED_ATTACH_TYPE" or .code? == "UNSUPPORTED_PROG_TYPE")' reports/unsupported-attach-mvp.json >/dev/null

jq -e '.. | objects | select(.classification_code? == "UNKNOWN" or .code? == "UNKNOWN")' reports/unknown-load-fail-mvp.json >/dev/null

required_codes=(
  "UNSUPPORTED_MAP_TYPE"
  "MISSING_BTF"
  "CORE_RELOCATION_FAILURE"
  "UNSUPPORTED_ATTACH_TYPE"
  "UNKNOWN"
)

for code in "${required_codes[@]}"; do
  if ! jq -e --arg code "$code" '.. | objects | select(.classification_code? == $code or .code? == $code)' \
      reports/ringbuf-modern-mvp.json \
      reports/core-relocation-mvp.json \
      reports/unsupported-attach-mvp.json \
      reports/unknown-load-fail-mvp.json >/dev/null; then
    echo "[acceptance] missing required classification code: ${code}" >&2
    exit 1
  fi
done

test -d .bpfcompat/runs
find .bpfcompat/runs -name "libbpf.log" -print -quit | grep -q .
find .bpfcompat/runs -name "*.json" -print -quit | grep -q .

echo "[acceptance] all checks passed"
