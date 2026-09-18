#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/reports" "$tmp/out"

base_report="$tmp/base.json"
python3 - "$base_report" <<'PY'
import json
import sys

path = sys.argv[1]
profiles = json.load(open("research/corpus/v1/profile-identities.json"))["profiles"]
targets = []
for p in profiles:
    pid = p["id"]
    targets.append({
        "profile_id": pid,
        "required": False,
        "status": "pass",
        "verdict": "COMPATIBLE",
        "environment": {
            "requested_kernel_family": "5.15",
            "observed_kernel": "5.15.0-fixture",
            "kernel_family_match": True,
            "image_source_url": "https://example.invalid/image",
            "image_sha256": "1" * 64,
        },
        "profile": {
            "distro": "fixture",
            "version": "1",
            "kernel_family": "5.15",
            "arch": "x86_64",
        },
        "host": {"kernel": "5.15.0-fixture", "arch": "x86_64"},
        "notes": [],
    })

doc = {
    "schema_version": "v0.1",
    "run": {"id": "fixture", "started_at": "2026-09-18T00:00:00Z"},
    "artifact": {
        "sha256": "41647d6d49fc72763fe8e2e7ee0a3b74f92d317de2595d8c95a4ca29b6fd0b0f"
    },
    "validator": {
        "sha256": "4ae1d5b838be07e6e7c304d753389a239c19eb92f6ba3bd77657e5c9583b9d04"
    },
    "targets": targets,
}
json.dump(doc, open(path, "w"))
PY

jq '.cases = [.cases[0]] | .expected_profiles = 10'   research/corpus/v1/study-plan.json > "$tmp/plan-one.json"

run_one() {
  local report="$1"
  local out="$2"
  rm -rf "$out"
  mkdir -p "$out" "$tmp/reports"
  cp "$report" "$tmp/reports/simple-pass-libbpf.json"
  python3 scripts/research/normalize-study-v1.py     --reports-dir "$tmp/reports"     --study-plan "$tmp/plan-one.json"     --out-dir "$out"
}

expect_fail() {
  local label="$1"
  shift
  if "$@" >"$tmp/$label.stdout" 2>"$tmp/$label.stderr"; then
    echo "expected failure: $label" >&2
    exit 1
  fi
}

# Baseline: exact ten-profile collection is complete.
run_one "$base_report" "$tmp/out/good"
jq -e '
  .collection_complete == true and
  .fully_evaluable == true and
  .observed_execution_records == 10 and
  .totals.compatible == 10 and
  (.invalid_profile_sets | length) == 0 and
  (.missing_environments | length) == 0 and
  (.environment_drift | length) == 0
' "$tmp/out/good/collection-summary.json" >/dev/null

# Duplicate one profile and omit another while retaining ten rows: incomplete.
jq '.targets[9] = .targets[0]' "$base_report" > "$tmp/duplicate.json"
rm -rf "$tmp/out/duplicate"; mkdir -p "$tmp/out/duplicate"
cp "$tmp/duplicate.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail duplicate-set python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json"   --out-dir "$tmp/out/duplicate"
jq -e '
  .collection_complete == false and
  (.invalid_profile_sets | index("simple-pass-libbpf")) != null and
  (.case_summaries[0].duplicate_profile_ids | length) == 1 and
  (.case_summaries[0].missing_profile_ids | length) == 1
' "$tmp/out/duplicate/collection-summary.json" >/dev/null

# Nine rows cannot satisfy a ten-profile case.
jq '.targets |= .[0:9]' "$base_report" > "$tmp/missing-profile.json"
rm -rf "$tmp/out/missing-profile"; mkdir -p "$tmp/out/missing-profile"
cp "$tmp/missing-profile.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail missing-profile python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json"   --out-dir "$tmp/out/missing-profile"
jq -e '
  .collection_complete == false and
  (.wrong_target_counts | index("simple-pass-libbpf")) != null
' "$tmp/out/missing-profile/collection-summary.json" >/dev/null

# Missing kernel-family evidence can never produce compatibility or exact env.
jq 'del(.targets[0].environment.kernel_family_match)' "$base_report" > "$tmp/missing-match.json"
rm -rf "$tmp/out/missing-match"; mkdir -p "$tmp/out/missing-match"
cp "$tmp/missing-match.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail missing-match python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json"   --out-dir "$tmp/out/missing-match"
jq -e '
  .collection_complete == false and
  .fully_evaluable == false and
  (.missing_environments | length) == 1
' "$tmp/out/missing-match/collection-summary.json" >/dev/null
head -n1 "$tmp/out/missing-match/executions.jsonl" |
  jq -e '.verdict == "inconclusive" and .inconclusive_reason == "evidence_unavailable" and .environment_id == null' >/dev/null

# A genuine requested/observed mismatch is inconclusive, not incompatible.
jq '
  .targets[0].environment.requested_kernel_family = "5.4" |
  .targets[0].profile.kernel_family = "5.4" |
  .targets[0].environment.kernel_family_match = false
' "$base_report" > "$tmp/mismatch.json"
rm -rf "$tmp/out/mismatch"; mkdir -p "$tmp/out/mismatch"
cp "$tmp/mismatch.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail mismatch python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json"   --out-dir "$tmp/out/mismatch"
head -n1 "$tmp/out/mismatch/executions.jsonl" |
  jq -e '.verdict == "inconclusive" and .inconclusive_reason == "environment_unavailable" and .environment_id == null' >/dev/null

# Infrastructure failure is collected but remains inconclusive.
jq '
  .targets[0].status = "infra_error" |
  .targets[0].verdict = "INFRA_ERROR"
' "$base_report" > "$tmp/infra.json"
run_one "$tmp/infra.json" "$tmp/out/infra"
jq -e '.collection_complete == true and .fully_evaluable == false and .totals.inconclusive == 1'   "$tmp/out/infra/collection-summary.json" >/dev/null
head -n1 "$tmp/out/infra/executions.jsonl" |
  jq -e '.verdict == "inconclusive" and .inconclusive_reason == "infrastructure_error"' >/dev/null

# Malformed/tampered evidence is rejected before a dataset is accepted.
jq '.targets[0].environment.image_sha256 = "banana"' "$base_report" > "$tmp/bad-image.json"
cp "$tmp/bad-image.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail bad-image python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/bad-image"
grep -q "malformed SHA-256" "$tmp/bad-image.stderr"

jq '.targets[0].status = "pass" | .targets[0].verdict = "INCOMPATIBLE"'   "$base_report" > "$tmp/contradiction.json"
cp "$tmp/contradiction.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail contradiction python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/contradiction"
grep -q "contradictory status/verdict" "$tmp/contradiction.stderr"

jq '.targets[0].profile_id = "not-frozen"' "$base_report" > "$tmp/unexpected.json"
cp "$tmp/unexpected.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail unexpected python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/unexpected"
grep -q "unexpected profile ids" "$tmp/unexpected.stderr"

jq '.artifact.sha256 = ("2" * 64)' "$base_report" > "$tmp/bad-artifact.json"
cp "$tmp/bad-artifact.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail bad-artifact python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/bad-artifact"
grep -q "artifact digest mismatch" "$tmp/bad-artifact.stderr"

jq '.validator.sha256 = ("3" * 64)' "$base_report" > "$tmp/bad-validator.json"
cp "$tmp/bad-validator.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail bad-validator python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/bad-validator"
grep -q "validator digest mismatch" "$tmp/bad-validator.stderr"

jq '
  .targets[0].environment.requested_kernel_family = "not-a-kernel" |
  .targets[0].profile.kernel_family = "not-a-kernel" |
  .targets[0].environment.kernel_family_match = true
' "$base_report" > "$tmp/unparseable-kernel.json"
cp "$tmp/unparseable-kernel.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail unparseable-kernel python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/unparseable-kernel"
grep -q "kernel series is not derivable" "$tmp/unparseable-kernel.stderr"

# Missing report is an incomplete collection, not silent success.
jq '.cases = [.cases[0], (.cases[0] | .id = "second-case")] | .expected_profiles = 10'   research/corpus/v1/study-plan.json > "$tmp/plan-two.json"
cp "$base_report" "$tmp/reports/simple-pass-libbpf.json"
rm -f "$tmp/reports/second-case.json"
rm -rf "$tmp/out/missing-report"; mkdir -p "$tmp/out/missing-report"
expect_fail missing-report python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-two.json" --out-dir "$tmp/out/missing-report"
jq -e '.collection_complete == false and (.missing_cases | index("second-case")) != null'   "$tmp/out/missing-report/collection-summary.json" >/dev/null

# Same logical profile resolving to different image bytes across cases is drift.
cp "$base_report" "$tmp/reports/simple-pass-libbpf.json"
jq '
  .run.id = "fixture-two" |
  .targets[0].environment.image_sha256 = ("4" * 64)
' "$base_report" > "$tmp/reports/second-case.json"
rm -rf "$tmp/out/drift"; mkdir -p "$tmp/out/drift"
expect_fail environment-drift python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-two.json" --out-dir "$tmp/out/drift"
jq -e '.collection_complete == false and (.environment_drift | length) == 1'   "$tmp/out/drift/collection-summary.json" >/dev/null

echo "[test-normalize-study-v1] PASS"
