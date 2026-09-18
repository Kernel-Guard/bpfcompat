#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:-dist/research-corpus-v1}"
REPORTS="${2:-reports/research-v1}"
MATRIX="research/corpus/v1/execution-matrix.yaml"
PLAN="research/corpus/v1/study-plan.json"

fail() {
  echo "[research-pilot-v1] $*" >&2
  exit 1
}

[[ -x "$BUNDLE/bin/bpfcompat-linux-amd64" ]] || fail "missing materialized BPFCompat CLI"
[[ -x "$BUNDLE/bin/bpfcompat-validator-static-linux-amd64" ]] || fail "missing materialized validator"
[[ -s "$PLAN" && -s "$MATRIX" ]] || fail "missing frozen study plan or matrix"

bash scripts/research/verify-materialization-v1.sh "$BUNDLE"
bash scripts/research/verify-profile-lock-v1.sh

expected_cli="1365337098474dc0a42484271ee6383d46cb1cd20da09d248f9a0063c5147f0e"
actual_cli="$(sha256sum "$BUNDLE/bin/bpfcompat-linux-amd64" | awk '{print $1}')"
[[ "$actual_cli" == "$expected_cli" ]] || fail "BPFCompat CLI identity drift"

export BPFCOMPAT_VALIDATOR_BIN="$PWD/$BUNDLE/bin/bpfcompat-validator-static-linux-amd64"
export BPFCOMPAT_VALIDATOR_SHA256="4ae1d5b838be07e6e7c304d753389a239c19eb92f6ba3bd77657e5c9583b9d04"

BPF="$PWD/$BUNDLE/bin/bpfcompat-linux-amd64"
mkdir -p "$REPORTS/logs" "$REPORTS/normalized"

run_case() {
  local case_id="$1"
  shift

  echo "[research-pilot-v1] === $case_id ==="
  set +e
  "$@" >"$REPORTS/logs/${case_id}.stdout.log" 2>"$REPORTS/logs/${case_id}.stderr.log"
  local rc=$?
  set -e
  printf '%s\n' "$rc" > "$REPORTS/logs/${case_id}.exit-code"

  # Compatibility negatives are observations, not shell failures. A missing
  # report means the case itself did not execute far enough to enter the
  # research dataset and is left for the normalizer to flag.
  if [[ ! -s "$REPORTS/${case_id}.json" ]]; then
    echo "[research-pilot-v1] warning: $case_id exited $rc without a report" >&2
  else
    echo "[research-pilot-v1] $case_id report captured (CLI exit $rc)"
  fi
}

common=(
  --matrix "$MATRIX"
  --concurrency 2
  --timeout 10m
)

run_case simple-pass-libbpf   "$BPF" test   --artifact "$BUNDLE/artifacts/simple_pass.bpf.o"   --manifest research/corpus/v1/manifests/simple-pass.yaml   --validation-mode load_attach   "${common[@]}"   --artifact-name research-simple-pass --artifact-version v1   --workdir .bpfcompat/research-v1/simple-pass-libbpf   --out "$REPORTS/simple-pass-libbpf.json"   --markdown "$REPORTS/simple-pass-libbpf.md"

run_case ringbuf-modern-libbpf   "$BPF" test   --artifact "$BUNDLE/artifacts/ringbuf_modern.bpf.o"   --manifest research/corpus/v1/manifests/ringbuf-modern.yaml   --validation-mode load_attach   "${common[@]}"   --artifact-name research-ringbuf-modern --artifact-version v1   --workdir .bpfcompat/research-v1/ringbuf-modern-libbpf   --out "$REPORTS/ringbuf-modern-libbpf.json"   --markdown "$REPORTS/ringbuf-modern-libbpf.md"

run_case perfbuf-fallback-libbpf   "$BPF" test   --artifact "$BUNDLE/artifacts/perfbuf_fallback.bpf.o"   --manifest research/corpus/v1/manifests/perfbuf-fallback.yaml   --validation-mode load_attach   "${common[@]}"   --artifact-name research-perfbuf-fallback --artifact-version v1   --workdir .bpfcompat/research-v1/perfbuf-fallback-libbpf   --out "$REPORTS/perfbuf-fallback-libbpf.json"   --markdown "$REPORTS/perfbuf-fallback-libbpf.md"

run_case core-relocation-fail-libbpf   "$BPF" test   --artifact "$BUNDLE/artifacts/core_relocation_fail.bpf.o"   --manifest research/corpus/v1/manifests/core-relocation-fail.yaml   --validation-mode load_only   "${common[@]}"   --artifact-name research-core-relocation-calibration --artifact-version v1   --workdir .bpfcompat/research-v1/core-relocation-fail-libbpf   --out "$REPORTS/core-relocation-fail-libbpf.json"   --markdown "$REPORTS/core-relocation-fail-libbpf.md"

run_case cilium-tracepoint-libbpf   "$BPF" test   --artifact "$BUNDLE/artifacts/cilium_tracepoint_in_c.bpf.o"   --manifest research/corpus/v1/manifests/cilium-tracepoint-in-c.yaml   --validation-mode load_attach   "${common[@]}"   --artifact-name research-cilium-tracepoint --artifact-version v1-libbpf   --workdir .bpfcompat/research-v1/cilium-tracepoint-libbpf   --out "$REPORTS/cilium-tracepoint-libbpf.json"   --markdown "$REPORTS/cilium-tracepoint-libbpf.md"

run_case cilium-tracepoint-ebpf-go   "$BPF" test-command   --cmd '$BPFCOMPAT_BIN $BPFCOMPAT_ARTIFACT'   --bin "$BUNDLE/loaders/ebpf-go-loader"   --artifact "$BUNDLE/artifacts/cilium_tracepoint_in_c.bpf.o"   --matrix "$MATRIX"   --concurrency 2   --timeout 10m   --artifact-name research-cilium-tracepoint --artifact-version v1-ebpf-go   --workdir .bpfcompat/research-v1/cilium-tracepoint-ebpf-go   --out "$REPORTS/cilium-tracepoint-ebpf-go.json"   --markdown "$REPORTS/cilium-tracepoint-ebpf-go.md"

run_case falco-modern-bpf-scap-open   "$BPF" test-command   --cmd '$BPFCOMPAT_BIN --modern_bpf --num_events 10'   --bin "$BUNDLE/loaders/scap-open"   --matrix "$MATRIX"   --concurrency 2   --timeout 10m   --artifact-name research-falco-modern-bpf --artifact-version v1   --workdir .bpfcompat/research-v1/falco-modern-bpf-scap-open   --out "$REPORTS/falco-modern-bpf-scap-open.json"   --markdown "$REPORTS/falco-modern-bpf-scap-open.md"

python3 scripts/research/normalize-study-v1.py   --reports-dir "$REPORTS"   --out-dir "$REPORTS/normalized"

echo "[research-pilot-v1] collection normalization complete"
