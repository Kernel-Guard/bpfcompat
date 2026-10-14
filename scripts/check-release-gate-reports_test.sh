#!/usr/bin/env bash
# Regression cover for scripts/check-release-gate-reports.sh.
#
# The defect it guards against (R1): release-artifacts.yml runs
#   jq -e FILTER reports/release-positive.json reports/release-negative.json
# and `jq -e` takes its exit status from the LAST output only, so a positive
# report with the wrong validator, an infra_error target or no base-image note
# passes whenever the negative report is good. Each "bad positive" case below
# first asserts that the multi-file form really does pass (the defect is real,
# not imagined) and then that the checker fails.
#
# Positive cases use the real, unmodified v0.4.0-rc.4 gate evidence (run
# 38592617383) from scripts/testdata/release-gate/v0.4.0-rc.4; its bytes are
# bound by sha256 to the attested release-candidate-evidence.json beside it.
# shellcheck disable=SC2016 # jq programs read $vars bound by --arg, not by the shell
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="${ROOT_DIR}/scripts/check-release-gate-reports.sh"
data="${ROOT_DIR}/scripts/testdata/release-gate"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# rc.4 values: SHA256SUMS validator entry and the pinned Ubuntu 22.04 image.
V="$(awk '$2 == "bpfcompat-validator-static-linux-amd64" {print $1}' "${data}/v0.4.0-rc.4/SHA256SUMS")"
D=757908b2fd6d5b1431bb45070fc1f56cbf017d4025568d292ece37d9cc75e812
# rc.3's validator: same validator/c-libbpf tree, different bytes.
V_RC3="$(awk '$2 == "bpfcompat-validator-static-linux-amd64" {print $1}' "${data}/v0.4.0-rc.3/SHA256SUMS")"
[[ "$V" == e0e7fcf8bd8384be3f85e4716d7330bdc0d3ae4d5de4070e815fa07c278be03a ]]
[[ "$V_RC3" =~ ^[0-9a-f]{64}$ && "$V_RC3" != "$V" ]]

pos="$tmp/release-positive.json"
neg="$tmp/release-negative.json"
real_reports() {
  cp "${data}/v0.4.0-rc.4/release-positive.json" "$pos"
  cp "${data}/v0.4.0-rc.4/release-negative.json" "$neg"
}
mutate() { # $1 = file, $2 = jq filter
  jq "$2" "$1" >"$1.tmp" && mv "$1.tmp" "$1"
}
fail_test() {
  echo "[release-gate-test] $*" >&2
  exit 1
}
expect_pass() { # $1 = label, rest = checker args
  local label="$1"
  shift
  bash "$checker" "$@" >"$tmp/out.log" 2>&1 || {
    cat "$tmp/out.log" >&2
    fail_test "expected PASS: ${label}"
  }
}
expect_fail() { # $1 = label, $2 = expected message fragment, rest = checker args
  local label="$1" want="$2" rc=0
  shift 2
  bash "$checker" "$@" >"$tmp/out.log" 2>&1 || rc=$?
  [[ "$rc" -ne 0 ]] || fail_test "expected FAIL: ${label}"
  grep -qF -- "$want" "$tmp/out.log" || {
    cat "$tmp/out.log" >&2
    fail_test "FAIL for ${label} did not mention: ${want}"
  }
}
# The frozen workflow's exact multi-file form. Returns jq's exit status.
old_multi_file() { # $1 = jq filter, rest = jq args
  local filter="$1"
  shift
  jq -e "$@" "$filter" "$pos" "$neg" >/dev/null
}
assert_old_pattern_masks() { # $1 = label, rest = old_multi_file args
  local label="$1"
  shift
  old_multi_file "$@" || fail_test "old multi-file pattern unexpectedly caught: ${label}"
}

# --- Real rc.4 evidence -----------------------------------------------------
real_reports
expect_pass "real rc.4 reports" "$pos" "$neg" "$V" "$D"
EV="${data}/v0.4.0-rc.4/release-candidate-evidence.json"
RC4_TAG=v0.4.0-rc.4
RC4_COMMIT=222c3f38a5361fca7c43c33df841290f8bef0021
expect_pass "real rc.4 reports bound to the attested evidence (rc.4 role)" \
  "$pos" "$neg" "$V" "$D" "$EV" "$RC4_TAG" "$RC4_COMMIT"
expect_fail "real rc.4 reports against rc.3's validator sha256" \
  "validator sha256 is the candidate's" "$pos" "$neg" "$V_RC3" "$D"
expect_fail "real rc.4 reports against another base image" \
  "every target notes the pinned base image digest" "$pos" "$neg" "$V" "$(printf '0%.0s' {1..64})"
expect_fail "reports swapped" "positive summary is pass" "$neg" "$pos" "$V" "$D"

# --- R1: bad positive listed first, good negative last ----------------------
real_reports
mutate "$pos" '.validator.sha256 = "0000000000000000000000000000000000000000000000000000000000000000"'
assert_old_pattern_masks "positive validator sha256" \
  '.validator.sha256 == $validator' --arg validator "$V"
expect_fail "positive report validator sha256 differs" \
  "FAIL validator sha256 is the candidate's: ${pos}" "$pos" "$neg" "$V" "$D"

real_reports
mutate "$pos" '.targets += [(.targets[0] | .status = "infra_error" | .profile_id = "rocky-9-5.14")]'
assert_old_pattern_masks "positive infra_error" '.targets | all(.status != "infra_error")'
expect_fail "positive report has an infra_error target" \
  "FAIL no infra_error target: ${pos}" "$pos" "$neg" "$V" "$D"

real_reports
mutate "$pos" '.targets[0].notes |= map(select(startswith("base image sha256:") | not))'
assert_old_pattern_masks "positive digest note" \
  'all(.targets[]; any(.notes[]?; contains($digest)))' --arg digest "$D"
expect_fail "positive report lacks the base image digest note" \
  "FAIL every target notes the pinned base image digest: ${pos}" "$pos" "$neg" "$V" "$D"

real_reports
mutate "$pos" '.targets = []'
assert_old_pattern_masks "positive vacuous targets" '.targets | all(.status != "infra_error")'
expect_fail "positive report has no targets (vacuous all())" \
  "FAIL has at least one target: ${pos}" "$pos" "$neg" "$V" "$D"

# Order dependence: the same defect in the LAST file is caught by the old
# pattern, which is why the rc.2/rc.3/rc.4 runs never exposed it.
real_reports
mutate "$neg" '.validator.sha256 = "0000000000000000000000000000000000000000000000000000000000000000"'
if old_multi_file '.validator.sha256 == $validator' --arg validator "$V"; then
  fail_test "old multi-file pattern should catch a bad LAST report"
fi
expect_fail "negative report validator sha256 differs" \
  "FAIL validator sha256 is the candidate's: ${neg}" "$pos" "$neg" "$V" "$D"

# --- Other per-report conditions --------------------------------------------
real_reports
mutate "$neg" '.targets[0].status = "infra_error"'
expect_fail "negative report has an infra_error target" \
  "FAIL no infra_error target: ${neg}" "$pos" "$neg" "$V" "$D"

real_reports
mutate "$neg" 'del(.targets[0].classification_code)'
expect_fail "negative report is unclassified" "negative is classified UNKNOWN" "$pos" "$neg" "$V" "$D"

real_reports
mutate "$pos" '.summary.status = "fail"'
expect_fail "positive summary is not pass" "FAIL positive summary is pass" "$pos" "$neg" "$V" "$D"

real_reports
mutate "$pos" '.targets[0].status = "fail"'
expect_fail "positive target did not pass" "FAIL every positive target passed" "$pos" "$neg" "$V" "$D"

real_reports
mutate "$neg" '.summary.status = "pass"'
expect_fail "negative summary is not fail" "FAIL negative summary is fail" "$pos" "$neg" "$V" "$D"

# Several failures are all reported, not just the first.
real_reports
mutate "$pos" '.validator.sha256 = "x" | .targets[0].status = "infra_error"'
expect_fail "multiple failures" "gate condition(s) failed" "$pos" "$neg" "$V" "$D"
grep -qF "FAIL validator sha256 is the candidate's: ${pos}" "$tmp/out.log" ||
  fail_test "multiple failures: validator failure not listed"
grep -qF "FAIL no infra_error target: ${pos}" "$tmp/out.log" ||
  fail_test "multiple failures: infra_error failure not listed"

# --- Evidence binding -------------------------------------------------------
real_reports
printf '\n' >>"$pos"
expect_pass "re-serialised report is still structurally fine" "$pos" "$neg" "$V" "$D"
expect_fail "report bytes differ from the attested evidence" \
  "reports are the bytes the candidate evidence names" \
  "$pos" "$neg" "$V" "$D" "$EV" "$RC4_TAG" "$RC4_COMMIT"
real_reports
expect_fail "missing evidence file" "missing, empty or symlinked evidence file" \
  "$pos" "$neg" "$V" "$D" "$tmp/no-such-evidence.json" "$RC4_TAG" "$RC4_COMMIT"

# --- Binding the evidence to the release being promoted ---------------------
# The operator error this guards: the qualified RC's own reports and evidence
# handed over where the stable build's belong pass every byte check, so the
# evidence must also name the expected tag and commit.
real_reports
expect_fail "rc.4 inputs claimed as stable v0.4.0" "FAIL candidate evidence is for tag v0.4.0:" \
  "$pos" "$neg" "$V" "$D" "$EV" v0.4.0 "$RC4_COMMIT"
expect_fail "rc.4 inputs claimed as another commit" \
  "FAIL candidate evidence is for commit 849ed26c352eb4d83921609cb4425a374403d8d3:" \
  "$pos" "$neg" "$V" "$D" "$EV" "$RC4_TAG" 849ed26c352eb4d83921609cb4425a374403d8d3
rc=0
bash "$checker" "$pos" "$neg" "$V" "$D" "$EV" >/dev/null 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || fail_test "evidence without expected tag/commit should be a usage error, got ${rc}"
expect_fail "malformed expected tag" "expected tag must look like" \
  "$pos" "$neg" "$V" "$D" "$EV" latest "$RC4_COMMIT"
expect_fail "abbreviated expected commit" "full 40-character" \
  "$pos" "$neg" "$V" "$D" "$EV" "$RC4_TAG" 222c3f3
expect_fail "empty evidence path with tag/commit" "evidence file path must not be empty" \
  "$pos" "$neg" "$V" "$D" "" "$RC4_TAG" "$RC4_COMMIT"

# --- Malformed inputs -------------------------------------------------------
real_reports
expect_fail "malformed validator sha256" "validator sha256 must be" "$pos" "$neg" notahash "$D"
expect_fail "upper-case validator sha256" "validator sha256 must be" "$pos" "$neg" "${V^^}" "$D"
expect_fail "malformed image sha256" "base image sha256 must be" "$pos" "$neg" "$V" notahash
ln -s "$pos" "$tmp/link.json"
expect_fail "symlinked report" "missing, empty or symlinked report" "$tmp/link.json" "$neg" "$V" "$D"
expect_fail "missing report" "missing, empty or symlinked report" "$tmp/none.json" "$neg" "$V" "$D"
printf 'not json' >"$pos"
expect_fail "positive report is not JSON" "not a JSON object" "$pos" "$neg" "$V" "$D"
rc=0
bash "$checker" "$pos" >/dev/null 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || fail_test "usage error should exit 2, got ${rc}"

echo "[release-gate-test] PASS"
