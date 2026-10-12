#!/usr/bin/env bash
# Regression guard for scripts/check-matrix-reports.sh, the gate that decides
# whether the public compatibility page may be (re)published.
#
# The page is now deployed even when a validation step failed, so that an
# honest incomplete report replaces a stale green one. That makes the gate on
# WHAT gets published load-bearing: a report must be (1) present for every
# expected artifact, (2) a v0.1 bpfcompat report, (3) produced by THIS run
# (not a leftover file older than the job), (4) about exactly the profiles the
# matrix requests, and (5) about exactly the artifact bytes built in this run.
# Any violation must refuse publication (exit 1), never publish partially.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/check-matrix-reports.sh"
command -v jq >/dev/null || { echo "SKIP: jq required" >&2; exit 0; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
mkdir -p reports matrices

cat >matrices/m.yaml <<'YAML'
name: m
profiles:
  - id: p1
    required: true
  - id: p2
    required: false
YAML
printf 'object-bytes' >art.o
art_sha="$(sha256sum art.o | awk '{print $1}')"
not_before="$(date -u -d '2026-10-11T10:00:00Z' +%s)"

write_report() { # path started_at schema sha profiles_json
  cat >"$1" <<JSON
{"schema_version":"$3","run":{"id":"r","started_at":"$2"},
 "artifact":{"basename":"art.o","sha256":"$4"},
 "summary":{"status":"pass","verdict":"COMPATIBLE","complete":true},
 "targets":$(jq -c 'map({profile_id:., required:(. != "p2"), status:"pass", verdict:"COMPATIBLE"})' <<<"$5")}
JSON
}

fail=0
expect() { # name want_rc args...
  local name="$1" want="$2"; shift 2
  local rc=0
  bash "$SCRIPT" "$@" >"$work/out.txt" 2>&1 || rc=$?
  if [[ "$rc" -eq "$want" ]]; then
    printf 'ok:   %s (rc=%s)\n' "$name" "$rc"
  else
    printf 'FAIL: %s (rc=%s want %s)\n' "$name" "$rc" "$want" >&2
    cat "$work/out.txt" >&2
    fail=1
  fi
}

good='["p1","p2"]'
args=(reports matrices/m.yaml "$not_before" "quirk-a.json=art.o")

write_report reports/quirk-a.json 2026-10-11T11:00:00Z v0.1 "$art_sha" "$good"
expect "fresh, complete, matching report is publishable" 0 "${args[@]}"

rm -f reports/quirk-a.json
expect "missing expected report refuses publication" 1 "${args[@]}"

write_report reports/quirk-a.json 2026-10-04T11:00:00Z v0.1 "$art_sha" "$good"
expect "report older than this job refuses publication" 1 "${args[@]}"

write_report reports/quirk-a.json 2026-10-11T11:00:00Z v0.2 "$art_sha" "$good"
expect "unknown schema refuses publication" 1 "${args[@]}"

write_report reports/quirk-a.json 2026-10-11T11:00:00Z v0.1 "deadbeef" "$good"
expect "report about different artifact bytes refuses publication" 1 "${args[@]}"

write_report reports/quirk-a.json 2026-10-11T11:00:00Z v0.1 "$art_sha" '["p1"]'
expect "report missing a matrix profile refuses publication" 1 "${args[@]}"

write_report reports/quirk-a.json 2026-10-11T11:00:00Z v0.1 "$art_sha" '["p1","p2","p3"]'
expect "report with an extra profile refuses publication" 1 "${args[@]}"

printf 'not json' >reports/quirk-a.json
expect "unparseable report refuses publication" 1 "${args[@]}"

# An infrastructure-error target is still a publishable, honest report.
cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "summary":{"status":"error","verdict":"INFRA_ERROR","complete":false},
 "targets":[{"profile_id":"p1","required":true,"status":"pass","verdict":"COMPATIBLE"},
            {"profile_id":"p2","required":false,"status":"infra_error","verdict":"INFRA_ERROR","infra_error":"download image: 502"}]}
JSON
expect "honest incomplete report (infra_error target) is publishable" 0 "${args[@]}"

# Results must be real v0.1 results, not just the right profile ids.
cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "targets":[{"profile_id":"p1"},{"profile_id":"p2"}]}
JSON
expect "report without summary or target results refuses publication" 1 "${args[@]}"

cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "summary":{"status":"pass","verdict":"COMPATIBLE","complete":true},
 "targets":[{"profile_id":"p1","required":true,"status":"pass","verdict":"COMPATIBLE"},
            {"profile_id":"p2","required":false,"status":"pass"}]}
JSON
expect "target without a verdict refuses publication" 1 "${args[@]}"

cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "summary":{"status":"pass","verdict":"COMPATIBLE","complete":true},
 "targets":[{"profile_id":"p1","required":true,"status":"pass","verdict":"COMPATIBLE"},
            {"profile_id":"p2","required":false,"status":"pass","verdict":"PROBABLY_FINE"}]}
JSON
expect "unknown verdict value refuses publication" 1 "${args[@]}"

cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "summary":{"status":"pass","complete":true},
 "targets":[{"profile_id":"p1","required":true,"status":"pass","verdict":"COMPATIBLE"},
            {"profile_id":"p2","required":false,"status":"pass","verdict":"COMPATIBLE"}]}
JSON
expect "summary without a verdict refuses publication" 1 "${args[@]}"

# summary.complete is what the page's "incomplete" banner relies on. It must
# be present, and it must be false whenever any target -- required or
# optional -- produced no answer (docs/compatibility-contract.md).
cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "summary":{"status":"pass","verdict":"COMPATIBLE"},
 "targets":[{"profile_id":"p1","required":true,"status":"pass","verdict":"COMPATIBLE"},
            {"profile_id":"p2","required":false,"status":"infra_error","verdict":"INFRA_ERROR","infra_error":"boot timeout"}]}
JSON
expect "optional infra error with summary.complete missing refuses publication" 1 "${args[@]}"

cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "summary":{"status":"pass","verdict":"COMPATIBLE","complete":true},
 "targets":[{"profile_id":"p1","required":true,"status":"pass","verdict":"COMPATIBLE"},
            {"profile_id":"p2","required":false,"status":"infra_error","verdict":"INFRA_ERROR","infra_error":"boot timeout"}]}
JSON
expect "complete:true with an INFRA_ERROR target refuses publication" 1 "${args[@]}"

cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "summary":{"status":"pass","verdict":"COMPATIBLE","complete":true},
 "targets":[{"profile_id":"p1","required":true,"status":"pass","verdict":"COMPATIBLE"},
            {"profile_id":"p2","required":false,"status":"unsupported","verdict":"UNSUPPORTED"}]}
JSON
expect "complete:true with an UNSUPPORTED target refuses publication" 1 "${args[@]}"

cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "summary":{"status":"pass","verdict":"COMPATIBLE","complete":true},
 "targets":[{"profile_id":"p1","required":true,"status":"pass","verdict":"COMPATIBLE",
             "environment":{"kernel_family_match":false}},
            {"profile_id":"p2","required":false,"status":"pass","verdict":"COMPATIBLE"}]}
JSON
expect "complete:true with a kernel-family mismatch refuses publication" 1 "${args[@]}"

cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "summary":{"status":"pass","verdict":"COMPATIBLE","complete":"yes"},
 "targets":[{"profile_id":"p1","required":true,"status":"pass","verdict":"COMPATIBLE"},
            {"profile_id":"p2","required":false,"status":"pass","verdict":"COMPATIBLE"}]}
JSON
expect "non-boolean summary.complete refuses publication" 1 "${args[@]}"

# The page counts required targets separately, so required flags must be
# the matrix's, not the report's.
cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "summary":{"status":"pass","verdict":"COMPATIBLE","complete":true},
 "targets":[{"profile_id":"p1","required":true,"status":"pass","verdict":"COMPATIBLE"},
            {"profile_id":"p2","required":true,"status":"pass","verdict":"COMPATIBLE"}]}
JSON
expect "optional profile reported as required refuses publication" 1 "${args[@]}"

cat >reports/quirk-a.json <<JSON
{"schema_version":"v0.1","run":{"id":"r","started_at":"2026-10-11T11:00:00Z"},
 "artifact":{"basename":"art.o","sha256":"$art_sha"},
 "summary":{"status":"pass","verdict":"COMPATIBLE","complete":true},
 "targets":[{"profile_id":"p1","required":false,"status":"pass","verdict":"COMPATIBLE"},
            {"profile_id":"p2","required":false,"status":"pass","verdict":"COMPATIBLE"}]}
JSON
expect "required profile reported as optional refuses publication" 1 "${args[@]}"

# A matrix entry without `required:` is required (bpfcompat's default).
cat >matrices/m2.yaml <<'YAML'
name: m2
profiles:
  - id: p1
  - id: p2
    required: false
YAML
write_report reports/quirk-a.json 2026-10-11T11:00:00Z v0.1 "$art_sha" "$good"
expect "omitted required defaults to required" 0 reports matrices/m2.yaml "$not_before" "quirk-a.json=art.o"

expect "no expected reports given is a usage error" 2 reports matrices/m.yaml "$not_before"

if [[ "$fail" -ne 0 ]]; then
  echo "check-matrix-reports_test: FAILED" >&2
  exit 1
fi
echo "check-matrix-reports_test: all checks passed"
