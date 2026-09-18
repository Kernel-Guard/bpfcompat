#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/reports" "$tmp/out"

cat > "$tmp/reports/execution-provenance.json" <<'JSON'
{
  "schema_version": "bpfcompat.research.execution-provenance.v1",
  "corpus_version": "v1",
  "workflow_source_commit": "fixture",
  "bpfcompat_cli": {
    "sha256": "sha256:1365337098474dc0a42484271ee6383d46cb1cd20da09d248f9a0063c5147f0e"
  },
  "validator": {
    "sha256": "sha256:4ae1d5b838be07e6e7c304d753389a239c19eb92f6ba3bd77657e5c9583b9d04"
  },
  "loaders": {
    "cilium-ebpf-v022-loader": {
      "path": "loaders/ebpf-go-loader",
      "sha256": "sha256:2e0517a0a068cf169ebf6a562cd2354ff9f18da708de7e54af52027a893598a4"
    },
    "falco-modern-bpf-scap-open": {
      "path": "loaders/scap-open",
      "sha256": "sha256:736c307379603a8320434217440e346ce03260d31a5e7d58326f5526e2c2f2cd"
    }
  },
  "inputs": {}
}
JSON

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
        "profile": {
            "distro": "fixture",
            "version": "1",
            "kernel_family": "5.15",
            "arch": "x86_64"
        },
        "host": {
            "distro": "fixture",
            "version": "1",
            "kernel_family": "5.15",
            "kernel": "5.15.0-fixture",
            "arch": "x86_64"
        },
        "notes": [
            "base image sha256: " + ("1" * 64)
        ]
    })

doc = {
    "schema_version": "v0.1",
    "run": {"id": "fixture", "started_at": "2026-09-18T00:00:00Z"},
    "artifact": {
        "sha256": "41647d6d49fc72763fe8e2e7ee0a3b74f92d317de2595d8c95a4ca29b6fd0b0f"
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
  mkdir -p "$out"
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

# Frozen v0.3.7 ReportV01 has no verdict/environment/validator top-level fields.
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
head -n1 "$tmp/out/good/executions.jsonl" |
  jq -e '
    .target_verdict == "COMPATIBLE" and
    .target_verdict_source == "derived_from_status_v0.3.7" and
    .kernel_family_match == true and
    .kernel_family_match_source == "derived_from_profile_and_host" and
    .environment_id != null
  ' >/dev/null

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

# Wrong requested kernel is still an exactly identified observed environment,
# but it is not a compatibility observation about the requested profile.
jq '
  .targets[0].profile.kernel_family = "5.15" |
  .targets[0].host.kernel = "6.12.0-fixture"
' "$base_report" > "$tmp/mismatch.json"
run_one "$tmp/mismatch.json" "$tmp/out/mismatch"
jq -e '
  .collection_complete == true and
  .fully_evaluable == false and
  .totals.inconclusive == 1 and
  (.missing_environments | length) == 0
' "$tmp/out/mismatch/collection-summary.json" >/dev/null
head -n1 "$tmp/out/mismatch/executions.jsonl" |
  jq -e '
    .verdict == "inconclusive" and
    .inconclusive_reason == "environment_unavailable" and
    .kernel_family_match == false and
    .environment_id != null
  ' >/dev/null

# Unparseable observed kernel cannot support an exact environment identity.
jq '.targets[0].host.kernel = "not-a-kernel"' "$base_report" > "$tmp/unparseable.json"
rm -rf "$tmp/out/unparseable"; mkdir -p "$tmp/out/unparseable"
cp "$tmp/unparseable.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail unparseable python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json"   --out-dir "$tmp/out/unparseable"
jq -e '
  .collection_complete == false and
  .fully_evaluable == false and
  (.missing_environments | length) == 1
' "$tmp/out/unparseable/collection-summary.json" >/dev/null
head -n1 "$tmp/out/unparseable/executions.jsonl" |
  jq -e '.verdict == "inconclusive" and .inconclusive_reason == "evidence_unavailable" and .environment_id == null' >/dev/null

# Infrastructure failure is collected but remains inconclusive.
jq '.targets[0].status = "infra_error"' "$base_report" > "$tmp/infra.json"
run_one "$tmp/infra.json" "$tmp/out/infra"
jq -e '.collection_complete == true and .fully_evaluable == false and .totals.inconclusive == 1'   "$tmp/out/infra/collection-summary.json" >/dev/null
head -n1 "$tmp/out/infra/executions.jsonl" |
  jq -e '.verdict == "inconclusive" and .inconclusive_reason == "infrastructure_error" and .target_verdict == "INFRA_ERROR"' >/dev/null

# If a future/reporting layer adds verdict, contradiction must still hard-fail.
jq '.targets[0].verdict = "INCOMPATIBLE"' "$base_report" > "$tmp/contradiction.json"
cp "$tmp/contradiction.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail contradiction python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/contradiction"
grep -q "contradictory status/verdict" "$tmp/contradiction.stderr"

# Legacy image digest evidence is validated, not merely treated as a note.
jq '.targets[0].notes = ["base image sha256: banana"]' "$base_report" > "$tmp/bad-image.json"
cp "$tmp/bad-image.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail bad-image python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/bad-image"
grep -q "malformed base image SHA-256 note" "$tmp/bad-image.stderr"

jq '.targets[0].profile_id = "not-frozen"' "$base_report" > "$tmp/unexpected.json"
cp "$tmp/unexpected.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail unexpected python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/unexpected"
grep -q "unexpected profile ids" "$tmp/unexpected.stderr"

jq '.artifact.sha256 = "2222222222222222222222222222222222222222222222222222222222222222"'   "$base_report" > "$tmp/bad-artifact.json"
cp "$tmp/bad-artifact.json" "$tmp/reports/simple-pass-libbpf.json"
expect_fail bad-artifact python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/bad-artifact"
grep -q "artifact digest mismatch" "$tmp/bad-artifact.stderr"

# Execution-time validator provenance is mandatory because v0.3.7 does not
# embed the validator binary identity in ReportV01.
cp "$tmp/reports/execution-provenance.json" "$tmp/good-provenance.json"
jq '.validator.sha256 = "sha256:3333333333333333333333333333333333333333333333333333333333333333"'   "$tmp/good-provenance.json" > "$tmp/reports/execution-provenance.json"
cp "$base_report" "$tmp/reports/simple-pass-libbpf.json"
expect_fail bad-validator-provenance python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/bad-validator-provenance"
grep -q "validator identity drift" "$tmp/bad-validator-provenance.stderr"
cp "$tmp/good-provenance.json" "$tmp/reports/execution-provenance.json"

mv "$tmp/reports/execution-provenance.json" "$tmp/reports/execution-provenance.missing"
expect_fail missing-provenance python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-one.json" --out-dir "$tmp/out/missing-provenance"
grep -q "missing execution provenance" "$tmp/missing-provenance.stderr"
mv "$tmp/reports/execution-provenance.missing" "$tmp/reports/execution-provenance.json"

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
  .targets[0].notes = ["base image sha256: 4444444444444444444444444444444444444444444444444444444444444444"]
' "$base_report" > "$tmp/reports/second-case.json"
rm -rf "$tmp/out/drift"; mkdir -p "$tmp/out/drift"
expect_fail environment-drift python3 scripts/research/normalize-study-v1.py   --reports-dir "$tmp/reports" --study-plan "$tmp/plan-two.json" --out-dir "$tmp/out/drift"
jq -e '.collection_complete == false and (.environment_drift | length) == 1'   "$tmp/out/drift/collection-summary.json" >/dev/null

echo "[test-normalize-study-v1] PASS"
