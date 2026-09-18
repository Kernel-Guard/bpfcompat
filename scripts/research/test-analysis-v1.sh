#!/usr/bin/env bash
set -euo pipefail
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
python3 scripts/research/analyze-study-v1.py --out-dir "$tmp/generated"
diff -ru research/analysis/v1/generated "$tmp/generated"
(cd research/data/v1 && sha256sum -c SHA256SUMS)
jq -e '.overall.attempts==70 and .rq1_version_predictiveness.disagreement==1 and .rq2_failure_taxonomy.non_calibration.incompatible==4 and .rq3_loader_pair_observations[0].verdict_disagreements==0' research/analysis/v1/generated/analysis-summary.json >/dev/null
echo "[test-analysis-v1] PASS"
