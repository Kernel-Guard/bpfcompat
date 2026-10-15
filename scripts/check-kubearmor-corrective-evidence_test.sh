#!/usr/bin/env bash
# Regression cover for scripts/check-kubearmor-corrective-evidence.sh, the
# offline acceptance gate for the v0.4.0-rc.4 KubeArmor corrective run.
#
# A synthetic bundle that satisfies the whole evidence contract must be
# VERIFIED; each single violation of the contract must be rejected (exit 1) or,
# for infrastructure errors, reported INCONCLUSIVE (exit 2). The synthetic
# bundle cannot contain the real rc.4 validator binary, so the pass case uses
# the checker's test seam BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256, under which
# an otherwise-accepted bundle exits 3 (never 0); the test also proves that
# without the seam the same bundle is rejected.
#
# Usage: check-kubearmor-corrective-evidence_test.sh
#   CHECKER=/path/to/other-checker.sh runs the cases against another
#   implementation (used to show the cases fail against a stub).
#   HISTORICAL_KUBEARMOR_REPORT=/path/kubearmor.json additionally requires the
#   real run-38609582942 KubeArmor report to be rejected.
#   TEST_VERBOSE=1 prints every checker transcript.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="${CHECKER:-${ROOT_DIR}/scripts/check-kubearmor-corrective-evidence.sh}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

readonly RC4_SHA="e0e7fcf8bd8384be3f85e4716d7330bdc0d3ae4d5de4070e815fa07c278be03a"
readonly V037_SHA="4ae1d5b838be07e6e7c304d753389a239c19eb92f6ba3bd77657e5c9583b9d04"
readonly PIN="f2b2da6466b47285fb2d6ef2464def8ac1219ab1"
readonly OTHER_PIN="28ae2f4745e1992ff5447cba7e0c67bf253aa7b3"
readonly K_UBU="6.8.0-142-generic"
readonly K_ALMA="4.18.0-553.168.1.el8_10.x86_64"
OBJ_SHA="$(printf obj | sha256sum | awk '{print $1}')"
readonly OBJ_SHA

# The fixture "validator" is a small file; the seam makes the checker expect
# its hash instead of the real rc.4 validator's.
printf 'synthetic validator fixture\n' >"$tmp/validator.bin"
FIX_SHA="$(sha256sum "$tmp/validator.bin" | awk '{print $1}')"
export BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256="$FIX_SHA"

pass=0
failures=0
bad() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}
# expect CODE LABEL BUNDLE [CHECKER-ARGS...]
expect() {
  local want="$1" label="$2"
  shift 2
  local got=0
  bash "$CHECKER" "$@" >"$tmp/out.txt" 2>&1 || got=$?
  if [[ -n "${TEST_VERBOSE:-}" ]]; then
    echo "--- case: ${label} (exit ${got}, want ${want})"
    sed 's/^/    /' "$tmp/out.txt"
  fi
  if [[ "$got" == "$want" ]]; then
    pass=$((pass + 1))
  else
    bad "${label}: exit ${got}, want ${want}"
    sed 's/^/    /' "$tmp/out.txt" >&2
  fi
  # Every verdict must come from the checker's own conclusion, never from a
  # crash part-way through: the last line is always a RESULT line.
  if [[ "$want" != 64 ]] && ! tail -n 1 "$tmp/out.txt" | grep -q '^RESULT: '; then
    bad "${label}: checker ended without a RESULT line (crashed?)"
  fi
}
# expect_line LABEL REGEX: the last checker output must contain REGEX.
expect_line() {
  if grep -Eq -- "$2" "$tmp/out.txt"; then pass=$((pass + 1)); else bad "$1: output lacks /$2/"; fi
}

validator_json() { # $1 kernel, $2 = optional jq filter applied last
  jq -n --arg k "$1" '{
    schema_version: "validator.v0.4", status: "pass",
    host: {sysname: "Linux", release: $k, machine: "x86_64"},
    discovery: {program_count: 3, map_count: 4, programs: [
      {name: "kprobe__security_bprm_check", section: "kprobe/security_bprm_check", attach_status: "skipped", attach_error: "", load_status: "pass", load_errno: 0, load_log: ""},
      {name: "syscall__sys_execve", section: "kprobe/sys_execve", attach_status: "skipped", attach_error: "", load_status: "pass", load_errno: 0, load_log: ""},
      {name: "trace_sched_exit", section: "tracepoint/sched/sched_process_exit", attach_status: "skipped", attach_error: "", load_status: "pass", load_errno: 0, load_log: ""}
    ]},
    input: {artifact: "system_monitor.bpf.o", manifest: "", functional_plan: "", attach_mode: "best-effort", probe_features: true},
    load: {status: "pass", error_code: 0, error: ""},
    logs: {libbpf: "libbpf: map '\''kubearmor_visibility'\'': created\nlibbpf: prog loaded\n"}
  }' | jq "${2:-.}"
}

guest_stdout() { # $1 distro line, $2 kernel, $3 validator sha, $4 kubearmor sha, $5 validator json filter
  echo "=== $1 on $2 ==="
  echo "guest-uname-r=$2"
  echo "guest-proc-version=Linux version $2 (mockbuild@example) #1 SMP PREEMPT_DYNAMIC"
  for i in $(seq 1 120); do echo "Setting up synthetic-package-${i} (1.0) ..."; done
  echo "built system_monitor.bpf.o against $2"
  echo "kubearmor-object-sha256-pre=${OBJ_PRE:-$OBJ_SHA}"
  echo "bpfcompat-validator-sha256-pre=${VAL_PRE:-$3}"
  echo "----- BEGIN bpfcompat-validator-json -----"
  validator_json "$2" "${5:-.}"
  echo
  echo "----- END bpfcompat-validator-json -----"
  echo "validator-exit-code=0"
  echo "kubearmor-object-sha256=${OBJ_SHA}"
  echo "libbpf-submodule-sha=67a4b1464349345e483df26ed93f8d388a60cee1"
  echo "guest-uname-r=$2"
  [[ -n "$4" ]] && echo "kubearmor-source-sha=$4"
  echo "bpfcompat-validator-sha256=$3"
}

# make_bundle DIR [VALIDATOR_SHA] [GUEST_KA_SHA] [ALMA_KERNEL] [ALMA_VALIDATOR_JSON_FILTER]
make_bundle() {
  local d="$1" vsha="${2:-$FIX_SHA}" gka="${3-$PIN}" kalma="${4:-$K_ALMA}" vfilter="${5:-.}"
  mkdir -p "$d"/{meta,host,validator,reports,targets/ubuntu-24.04-6.8,targets/almalinux-8-4.18,logs}
  echo "2026-10-16T09:00:00Z" >"$d/meta/started-at.txt"
  echo "2026-10-16T09:12:00Z" >"$d/meta/finished-at.txt"
  echo 0 >"$d/meta/bpfcompat-test.exit-code"
  jq -n '{name: "bpfcompat", version: "v0.4.0-rc.4", commit: "222c3f38a536", go_version: "go1.26.9"}' >"$d/meta/bpfcompat-version.json"
  jq -n --arg c "$PIN" '{schema: "bpfcompat.kubearmor-pin.v1", url: "https://github.com/kubearmor/KubeArmor", commit: $c, libbpf_submodule_commit: "67a4b1464349345e483df26ed93f8d388a60cee1"}' >"$d/meta/kubearmor-pin.json"
  printf 'set -e\nKA_COMMIT=%s\nEXPECTED_VALIDATOR_SHA256=%s\necho synthetic guest command\n' "$PIN" "$FIX_SHA" >"$d/meta/guest-command.sh"
  cp "$tmp/validator.bin" "$d/validator/bpfcompat-validator"
  jq -n --arg s "$FIX_SHA" '{schema: "bpfcompat.consumer-validator-identity.v1", mode: "release", tag: "v0.4.0-rc.4",
    commit: "222c3f38a5361fca7c43c33df841290f8bef0021", sha256: $s,
    provenance: "sha256sums+github-attestation:https://github.com/Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/v0.4.0-rc.4"}' \
    >"$d/validator/validator-identity.json"
  echo "Linux host 6.8.0 x86_64" >"$d/host/host.txt"
  echo "QEMU emulator version 8.2.2" >"$d/host/qemu-version.txt"
  printf 'crw-rw---- 1 root kvm 10, 232 /dev/kvm\nkvm-access=rw\n' >"$d/host/kvm.txt"
  echo "procedure log" >"$d/logs/procedure.log"
  guest_stdout "ubuntu 24.04" "$K_UBU" "$vsha" "$gka" >"$d/targets/ubuntu-24.04-6.8/command.stdout"
  guest_stdout "almalinux 8.10" "$kalma" "$vsha" "$gka" "$vfilter" >"$d/targets/almalinux-8-4.18/command.stdout"
  echo 0 >"$d/targets/ubuntu-24.04-6.8/command-exit-code"
  echo 0 >"$d/targets/almalinux-8-4.18/command-exit-code"
  local inv
  inv="$(printf '%s\0expected-exit=0' "$(cat "$d/meta/guest-command.sh")" | sha256sum | awk '{print $1}')"
  jq -n \
    --arg inv "$inv" --arg vsha "$vsha" \
    --arg ku "$K_UBU" --arg ka "$kalma" \
    '
    def tgt($p; $k; $fam): {
      profile_id: $p, required: true, status: "pass", verdict: "COMPATIBLE",
      environment: {requested_kernel_family: $fam, observed_kernel: $k, kernel_family_match: true, distro_match: true},
      validation: {load_status: "skipped"},
      notes: ["base image sha256: \($p | @base64 | explode | map(. % 16) | map("0123456789abcdef"[.:.+1]) | join("") | (. * 8)[:64])",
              "command executed inside VM (exit code 0)"],
      functional: {status: "pass", tests: [{name: "command", required: true, status: "pass",
        expected_exit_code: 0, exit_code: 0, stdout_tail: ""}]}
    };
    {
      schema_version: "v0.1",
      run: {id: "synthetic", started_at: "2026-10-16T09:01:00Z"},
      artifact: {path: "command://command", basename: "command", sha256: "x", size_bytes: 1},
      command: {invocation_sha256: $inv, expected_exit_code: 0,
                binary: {basename: "bpfcompat-validator", sha256: $vsha, size_bytes: 28}},
      matrix: {name: "consumer-external", profiles: ["ubuntu-24.04-6.8", "almalinux-8-4.18"]},
      targets: [tgt("ubuntu-24.04-6.8"; $ku; "6.8"), tgt("almalinux-8-4.18"; $ka; "4.18")],
      summary: {status: "pass", verdict: "COMPATIBLE", complete: true}
    }' >"$d/reports/kubearmor.json"
  jq -n --arg k "$PIN" '{schema: "bpfcompat.kubearmor-corrective-run.v1", verdict: "VERIFIED", dry_run: false, kubearmor_commit: $k}' >"$d/verdict.json"
  refresh_bundle "$d"
}
# tail_json FILE: the report's stdout_tail for FILE as rc.4 computes it
# (internal/vm readFileTail: last 4096 bytes, surrounding whitespace trimmed),
# JSON-encoded.
tail_json() { tail -c 4096 "$1" | jq -Rs 'sub("\\A\\s+"; "") | sub("\\s+\\z"; "")'; }
# refresh_bundle DIR: re-derive, from each targets/*/command.stdout, the report
# stdout_tail and the extracted validator.json / libbpf.log, as the runner and
# bpfcompat would. Cases that mutate stdout call it so the mutation is the only
# defect.
refresh_bundle() {
  local d="$1" p f
  for p in ubuntu-24.04-6.8 almalinux-8-4.18; do
    f="$d/targets/$p/command.stdout"
    [[ -f "$f" ]] || continue
    awk '/^----- BEGIN bpfcompat-validator-json -----$/ {on=1; next}
         /^----- END bpfcompat-validator-json -----$/ {on=0}
         on' "$f" >"$d/targets/$p/validator.json"
    jq -rj '.logs.libbpf // ""' "$d/targets/$p/validator.json" >"$d/targets/$p/libbpf.log" 2>/dev/null || : >"$d/targets/$p/libbpf.log"
    if [[ -f "$d/reports/kubearmor.json" ]]; then
      jq --arg p "$p" --argjson t "$(tail_json "$f")" \
        '(.targets[]? | select(.profile_id == $p) | .functional.tests[]? | select(.name == "command") | .stdout_tail) = $t' \
        "$d/reports/kubearmor.json" >"$d/reports/kubearmor.json.tmp"
      mv "$d/reports/kubearmor.json.tmp" "$d/reports/kubearmor.json"
    fi
  done
}
seal() {
  (cd "$1" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum --) >"$tmp/sums"
  mv "$tmp/sums" "$1/SHA256SUMS"
}
jq_edit() { # FILE FILTER
  jq "$2" "$1" >"$1.tmp" && mv "$1.tmp" "$1"
}

# --- 1. the fully compliant bundle is VERIFIED (seam marks it) ------------------
make_bundle "$tmp/ok"
seal "$tmp/ok"
expect 3 "compliant bundle (under the seam: distinct non-zero exit)" "$tmp/ok"
expect_line "seam is announced" 'TEST SEAM'
expect_line "seam result is marked not-evidence" '^RESULT: VERIFIED \(TEST SEAM'

# Without the seam the expected validator is the real rc.4 one, so the same
# synthetic bundle is rejected.
BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256="" expect 1 "synthetic bundle without the seam" "$tmp/ok"
BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256="" expect_line "names the rc.4 validator" "$RC4_SHA"

# --- 2. wrong validator (the v0.3.7 one actually run by 38609582942) ----------
make_bundle "$tmp/v037" "$V037_SHA"
seal "$tmp/v037"
expect 1 "v0.3.7 validator in the guests" "$tmp/v037"
expect_line "v0.3.7 rejected via command.binary" "R2 command.binary.sha256 is ${V037_SHA}"
expect_line "v0.3.7 rejected via guest marker" "B6 almalinux-8-4.18: in-guest bpfcompat-validator-sha256-pre '${V037_SHA}'"

# --- 3. a required kernel is missing ---------------------------------------------
make_bundle "$tmp/nokernel"
jq_edit "$tmp/nokernel/reports/kubearmor.json" '.targets |= map(select(.profile_id != "almalinux-8-4.18"))'
rm -rf "$tmp/nokernel/targets/almalinux-8-4.18"
seal "$tmp/nokernel"
expect 1 "missing almalinux-8-4.18 kernel" "$tmp/nokernel"
expect_line "missing kernel named" 'R6 almalinux-8-4.18: expected exactly one target, found 0'

make_bundle "$tmp/nobase"
jq_edit "$tmp/nobase/reports/kubearmor.json" '(.targets[] | select(.profile_id == "ubuntu-24.04-6.8") | .notes) |= map(select(startswith("base image") | not))'
seal "$tmp/nobase"
expect 1 "guest base image digest not recorded" "$tmp/nobase"

# --- 4. kernel family mismatch (a 5.14 kernel under the 4.18 profile) ------------
make_bundle "$tmp/family" "" "$PIN" "5.14.0-570.el9.x86_64"
seal "$tmp/family"
expect 1 "kernel family mismatch" "$tmp/family"

# --- 5. guest kernel string disagrees with the report ----------------------------
make_bundle "$tmp/uname"
sed -i "0,/^guest-uname-r=.*/s//guest-uname-r=6.8.0-999-generic/" "$tmp/uname/targets/ubuntu-24.04-6.8/command.stdout"
seal "$tmp/uname"
expect 1 "guest uname -r != report kernel" "$tmp/uname"

# --- 6. missing KubeArmor commit marker ------------------------------------------
make_bundle "$tmp/noka" "" ""
seal "$tmp/noka"
expect 1 "missing kubearmor-source-sha" "$tmp/noka"
expect_line "missing kubearmor sha named" 'kubearmor-source-sha is .<missing>'

# --- 7. KubeArmor built from a commit other than the pin --------------------------
make_bundle "$tmp/otherka" "" "$OTHER_PIN"
seal "$tmp/otherka"
expect 1 "kubearmor commit != pin" "$tmp/otherka"

# --- 8. a program failed to load (verifier rejection) ------------------------------
make_bundle "$tmp/progfail" "" "$PIN" "" \
  '.discovery.programs[1].load_status = "fail" | .discovery.programs[1].load_errno = -13 | .discovery.programs[1].load_log = "R1 invalid mem access"'
seal "$tmp/progfail"
expect 1 "one program failed to load" "$tmp/progfail"
expect_line "failed program named" 'syscall__sys_execve'

# --- 9. per-program results missing / truncated -----------------------------------
make_bundle "$tmp/noprog" "" "$PIN" "" '.discovery.programs |= map(del(.load_status))'
seal "$tmp/noprog"
expect 1 "per-program load results missing" "$tmp/noprog"
make_bundle "$tmp/trunc" "" "$PIN" "" '.discovery.program_count = 70'
seal "$tmp/trunc"
expect 1 "per-program list truncated" "$tmp/trunc"

# --- 10. whole-object load failed -----------------------------------------------------
make_bundle "$tmp/loadfail" "" "$PIN" "" '.status = "fail" | .load.status = "fail" | .load.error_code = -22'
seal "$tmp/loadfail"
expect 1 "object load failed" "$tmp/loadfail"

# --- 11. tampering after sealing ---------------------------------------------------------
make_bundle "$tmp/tamper"
seal "$tmp/tamper"
sed -i 's/"load_status": "pass"/"load_status": "pass" /' "$tmp/tamper/targets/almalinux-8-4.18/command.stdout"
expect 1 "file modified after SHA256SUMS" "$tmp/tamper"
expect_line "tamper named" 'B1 checksum mismatch \(tampered\?\): targets/almalinux-8-4.18/command.stdout'
make_bundle "$tmp/extra"
seal "$tmp/extra"
echo "late" >"$tmp/extra/logs/unlisted.log"
expect 1 "file not covered by SHA256SUMS" "$tmp/extra"
make_bundle "$tmp/nosums"
expect 1 "no SHA256SUMS" "$tmp/nosums"

# --- 12. infrastructure error -> INCONCLUSIVE, never VERIFIED ---------------------------
make_bundle "$tmp/infra"
jq_edit "$tmp/infra/reports/kubearmor.json" \
  '.summary.verdict = "INFRA_ERROR" | .summary.status = "fail" | .summary.complete = false
   | (.targets[] | select(.profile_id == "almalinux-8-4.18")) |= (.status = "error" | .verdict = "INFRA_ERROR")'
seal "$tmp/infra"
expect 2 "INFRA_ERROR report" "$tmp/infra"
expect_line "infra classified" '^RESULT: INCONCLUSIVE'
make_bundle "$tmp/noreport"
rm "$tmp/noreport/reports/kubearmor.json"
seal "$tmp/noreport"
expect 2 "no report at all" "$tmp/noreport"

# --- 13. the runner's own record must be a non-dry VERIFIED --------------------------
make_bundle "$tmp/dry"
jq_edit "$tmp/dry/verdict.json" '.verdict = "DRY_RUN_OK" | .dry_run = true'
seal "$tmp/dry"
expect 1 "dry-run bundle" "$tmp/dry"

# --- 14. a different guest command than the recorded one ---------------------------------
make_bundle "$tmp/cmd"
echo "V=v0.3.7; curl -fsSLO https://github.com/Kernel-Guard/bpfcompat/releases/download/\$V/x" >>"$tmp/cmd/meta/guest-command.sh"
seal "$tmp/cmd"
expect 1 "guest command differs from the report invocation" "$tmp/cmd"

# --- 15. wrong CLI -------------------------------------------------------------------------
make_bundle "$tmp/cli"
jq_edit "$tmp/cli/meta/bpfcompat-version.json" '.version = "v0.3.7" | .commit = "0123456789ab"'
seal "$tmp/cli"
expect 1 "CLI is not rc.4" "$tmp/cli"

# --- 16. reviewer adversarial cases (ADV1-ADV4, ADV8) and pre-exec binding ------
# ADV1: the validator block holds two JSON documents, a failing one first.
make_bundle "$tmp/adv1"
f="$tmp/adv1/targets/almalinux-8-4.18/command.stdout"
failjson="$(validator_json "$K_ALMA" '.status = "fail" | .load.status = "fail" | .load.error_code = -13 | .discovery.programs[1].load_status = "fail"' | jq -c .)"
FJ="$failjson" awk '{print} /^----- BEGIN bpfcompat-validator-json -----$/ {print ENVIRON["FJ"]}' "$f" >"$f.new"
mv "$f.new" "$f"
refresh_bundle "$tmp/adv1"
seal "$tmp/adv1"
expect 1 "ADV1 two JSON documents in the validator block" "$tmp/adv1"
expect_line "ADV1 named" 'exactly one JSON document'
# ADV10 variant: END marker missing.
make_bundle "$tmp/noend"
sed -i '/^----- END bpfcompat-validator-json -----$/d' "$tmp/noend/targets/ubuntu-24.04-6.8/command.stdout"
refresh_bundle "$tmp/noend"
seal "$tmp/noend"
expect 1 "END marker missing" "$tmp/noend"
expect_line "END marker named" 'found 1 BEGIN / 0 END'

# ADV2: full stdout no longer matches the report's stdout_tail.
make_bundle "$tmp/adv2"
sed -i 's/^kubearmor-object-sha256=.*/kubearmor-object-sha256=0000000000000000000000000000000000000000000000000000000000000000/' \
  "$tmp/adv2/targets/ubuntu-24.04-6.8/command.stdout"
seal "$tmp/adv2"
expect 1 "ADV2 command.stdout diverges from the report stdout_tail" "$tmp/adv2"
expect_line "ADV2 named" 'B9 ubuntu-24.04-6.8: report stdout_tail is not the tail of targets/ubuntu-24.04-6.8/command.stdout'

# ADV3: validator JSON describes another artifact; object hash not stable.
make_bundle "$tmp/adv3" "" "$PIN" "" '.input.artifact = "/tmp/not-kubearmor.bpf.o"'
seal "$tmp/adv3"
expect 1 "ADV3 validator input.artifact is not system_monitor.bpf.o" "$tmp/adv3"
make_bundle "$tmp/probeoff" "" "$PIN" "" '.input.probe_features = false'
seal "$tmp/probeoff"
expect 1 "validator ran without per-program probing" "$tmp/probeoff"
OBJ_PRE="1111111111111111111111111111111111111111111111111111111111111111" make_bundle "$tmp/objswap"
seal "$tmp/objswap"
expect 1 "object hash changed between build and validator run" "$tmp/objswap"

# Pre-exec binding: the guest hashed a different binary before running it.
VAL_PRE="$V037_SHA" make_bundle "$tmp/preexec"
seal "$tmp/preexec"
expect 1 "pre-exec validator sha256 != rc.4" "$tmp/preexec"
expect_line "pre-exec named" 'bpfcompat-validator-sha256-pre'

# Derived files must be exactly what command.stdout contains.
make_bundle "$tmp/derived"
echo '{"forged": true}' >"$tmp/derived/targets/almalinux-8-4.18/validator.json"
seal "$tmp/derived"
expect 1 "extracted validator.json differs from command.stdout" "$tmp/derived"

# ADV4: the seam leaking into an acceptance run never yields exit 0.
expect 3 "ADV4 seam set during acceptance" "$tmp/ok"
BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256="" expect 1 "ADV4 same bundle without the seam" "$tmp/ok"

# ADV8: a definite validator mismatch is FAILED even when INFRA_ERROR is present.
make_bundle "$tmp/adv8" "$V037_SHA"
jq_edit "$tmp/adv8/reports/kubearmor.json" '(.targets[] | select(.profile_id == "almalinux-8-4.18")) |= (.verdict = "INFRA_ERROR")'
seal "$tmp/adv8"
expect 1 "ADV8 v0.3.7 validator plus INFRA_ERROR" "$tmp/adv8"
expect_line "ADV8 classified FAILED" '^RESULT: FAILED'

# --- 17. historical-shaped report (no binary identity, no markers) --------------------------
make_bundle "$tmp/hist"
jq '.command |= del(.binary) | .targets[].functional.tests[].stdout_tail |= "bpfcompat-validator-static-linux-amd64: OK\n"' \
  "$tmp/hist/reports/kubearmor.json" >"$tmp/hist-report.json"
expect 1 "historical-shaped report (report-only)" --report-only "$tmp/hist-report.json"
if [[ -n "${HISTORICAL_KUBEARMOR_REPORT:-}" ]]; then
  BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256="" expect 1 "real run 38609582942 KubeArmor report" --report-only "$HISTORICAL_KUBEARMOR_REPORT"
  BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256="" expect_line "real historical report: no binary identity" 'R2 command.binary.sha256 is <missing>'
fi

echo "check-kubearmor-corrective-evidence_test: ${pass} passed, ${failures} failed"
[[ "$failures" -eq 0 ]]
