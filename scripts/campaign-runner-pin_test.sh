#!/usr/bin/env bash
# The scheduled production campaign must run on a pinned runner image.
#
# Four campaigns, 6-8 days apart, with zero infrastructure errors qualify a
# stable release. `ubuntu-latest` is a moving label: GitHub announced its
# gradual move to Ubuntu 26 from 2026-10-19, in the middle of a qualification
# window. A runner OS change mid-window would make the four campaigns test
# different host stacks (QEMU, KVM, cloud-image-utils) and could turn into an
# infrastructure error that resets the window. Every job in the campaign
# workflow therefore names an exact image.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/latest-kernel-compatibility.yml"

labels="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
for name, job in (wf.get("jobs") or {}).items():
    print(f"{name}\t{job.get('runs-on')}")
PY
)"
[[ -n "$labels" ]] || { echo "FAIL: no jobs found in $WORKFLOW" >&2; exit 1; }

fail=0
while IFS=$'\t' read -r job label; do
  if [[ "$label" == "ubuntu-24.04" ]]; then
    printf 'ok:   %s runs on %s\n' "$job" "$label"
  else
    printf 'FAIL: %s runs on %s; the campaign must pin ubuntu-24.04\n' "$job" "$label" >&2
    fail=1
  fi
done <<<"$labels"

if [[ "$fail" -ne 0 ]]; then
  echo "campaign-runner-pin_test: FAILED" >&2
  exit 1
fi
echo "campaign-runner-pin_test: all checks passed"
