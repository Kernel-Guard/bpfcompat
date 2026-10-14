#!/usr/bin/env bash
# The release-candidate canaries must run on a pinned runner image.
#
# consumer-canary, release-candidate-canary and external-consumer-canary
# produce the manual/T+24h/T+72h graduation evidence for a release candidate.
# `ubuntu-latest` is a moving label: GitHub migrates it to Ubuntu 26.04
# gradually from 2026-10-19 (GitHub changelog 2026-09-17,
# actions/runner-images#14748). A runner OS change between observations
# would make them test different host stacks (QEMU, KVM, cloud-image-utils)
# and could surface as an infrastructure error mid-window. Every job in these
# workflows therefore names an exact image.
#
# release-candidate-canary dispatches external-consumer-canary at the RC
# *tag*, so that file's runner labels are read from the tagged commit: the pin
# must be on main before the candidate is tagged.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOWS=(
  "$ROOT/.github/workflows/consumer-canary.yml"
  "$ROOT/.github/workflows/release-candidate-canary.yml"
  "$ROOT/.github/workflows/external-consumer-canary.yml"
)
EXPECTED="ubuntu-24.04"

fail=0
for wf in "${WORKFLOWS[@]}"; do
  name="$(basename "$wf")"
  labels="$(python3 - "$wf" <<'PY'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
for name, job in (wf.get("jobs") or {}).items():
    print(f"{name}\t{job.get('runs-on')}")
PY
)"
  if [[ -z "$labels" ]]; then
    echo "FAIL: no jobs found in $name" >&2
    fail=1
    continue
  fi
  while IFS=$'\t' read -r job label; do
    if [[ "$label" == "$EXPECTED" ]]; then
      printf 'ok:   %s/%s runs on %s\n' "$name" "$job" "$label"
    else
      printf 'FAIL: %s/%s runs on %s; release-candidate canaries must pin %s\n' \
        "$name" "$job" "$label" "$EXPECTED" >&2
      fail=1
    fi
  done <<<"$labels"
  # The moving label must not appear outside comments either (a matrix value
  # or an expression would slip past the runs-on comparison above).
  if grep -nE '^[^#]*ubuntu-latest' "$wf" >&2; then
    echo "FAIL: $name references ubuntu-latest outside a comment" >&2
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "canary-runner-pin_test: FAILED" >&2
  exit 1
fi
echo "canary-runner-pin_test: all checks passed"
