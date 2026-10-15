#!/usr/bin/env bash
# Offline verifier for the v0.4.0-rc.4 KubeArmor corrective-run evidence
# bundle written by scripts/kubearmor-corrective-run.sh. It implements the
# evidence contract in docs/kubearmor-rc4-corrective-run.md and trusts nothing
# the runner concluded: every acceptance condition is recomputed from the raw
# files.
#
# Usage:
#   check-kubearmor-corrective-evidence.sh BUNDLE_DIR
#       full contract on a sealed bundle (the acceptance gate)
#   check-kubearmor-corrective-evidence.sh --pre-seal BUNDLE_DIR
#       used by the runner before it writes verdict.json / finished-at.txt
#   check-kubearmor-corrective-evidence.sh --report-only REPORT_JSON
#       only the report-level clauses, for a bare bpfcompat report (e.g. the
#       historical run 38609582942 KubeArmor report, which must be rejected)
#
# Exit: 0 accepted (VERIFIED), 1 rejected (FAILED), 2 inconclusive
# (INFRA_ERROR or no report, and no definite mismatch), 3 would-be-accepted
# under the test seam (never acceptance), 64 usage. Every violated clause is
# printed. Acceptance requires exit 0 and the final line exactly
# "RESULT: VERIFIED". A definite identity mismatch (wrong validator, CLI or
# KubeArmor commit) or broken integrity is FAILED even if INFRA_ERROR is also
# present.
#
# Test seam (never set for acceptance): BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256
# replaces the expected validator sha256 so synthetic fixtures can be checked;
# it is announced, and a bundle that would otherwise pass exits 3, not 0.
set -euo pipefail

readonly EXPECTED_TAG="v0.4.0-rc.4"
readonly EXPECTED_COMMIT="222c3f38a5361fca7c43c33df841290f8bef0021"
EXPECTED_VALIDATOR_SHA256="e0e7fcf8bd8384be3f85e4716d7330bdc0d3ae4d5de4070e815fa07c278be03a"
TEST_SEAM=false
if [[ -n "${BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256:-}" ]]; then
  [[ "$BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256" >&2
    exit 64
  }
  EXPECTED_VALIDATOR_SHA256="$BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256"
  TEST_SEAM=true
  echo "WARNING: TEST SEAM ACTIVE: expected validator sha256 overridden to ${EXPECTED_VALIDATOR_SHA256}; this result is NOT acceptance evidence"
fi
readonly EXPECTED_VALIDATOR_SHA256 TEST_SEAM
readonly MATRIX_NAME="consumer-external"
readonly -a PROFILES=("ubuntu-24.04-6.8" "almalinux-8-4.18")
readonly MAX_PROGRAMS=64 # validator MAX_ITEMS: a longer object is reported truncated

kernel_regex() {
  case "$1" in
    ubuntu-24.04-6.8) echo '^6\.8\.[0-9]+-[0-9]+-generic$' ;;
    almalinux-8-4.18) echo '^4\.18\.0-[0-9][0-9.]*\.el8(_[0-9]+)?\.x86_64$' ;;
    *) echo '^$' ;;
  esac
}

usage() {
  sed -n '/^# Usage:/,/^# Exit:/p' "${BASH_SOURCE[0]}" >&2
  exit 64
}

mode=full
case "${1:-}" in
  --pre-seal) mode="pre-seal"; shift ;;
  --report-only) mode="report-only"; shift ;;
  -h | --help | "") usage ;;
esac
[[ $# -eq 1 ]] || usage
target_path="$1"
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 64; }

rejects=0
integrity=0
definite=0
infra=0
reject() {
  echo "REJECT: $*"
  rejects=$((rejects + 1))
}
reject_integrity() {
  reject "$@"
  integrity=$((integrity + 1))
}
# reject_definite: a value is present and provably wrong (identity mismatch).
reject_definite() {
  reject "$@"
  definite=$((definite + 1))
}
inconclusive() {
  echo "INCONCLUSIVE: $*"
  infra=$((infra + 1))
}
okline() { echo "ok: $*"; }

finish() {
  if ((integrity > 0)); then
    echo "RESULT: FAILED (${rejects} violated clause(s), bundle integrity broken)"
    exit 1
  fi
  if ((definite > 0)); then
    echo "RESULT: FAILED (${rejects} violated clause(s), ${definite} definite identity mismatch(es))"
    exit 1
  fi
  if ((infra > 0)); then
    echo "RESULT: INCONCLUSIVE (${infra} infrastructure condition(s); ${rejects} other violation(s))"
    exit 2
  fi
  if ((rejects > 0)); then
    echo "RESULT: FAILED (${rejects} violated clause(s))"
    exit 1
  fi
  if [[ "$TEST_SEAM" == true ]]; then
    echo "RESULT: VERIFIED (TEST SEAM: expected validator overridden; not acceptance evidence)"
    exit 3
  fi
  echo "RESULT: VERIFIED"
  exit 0
}

# marker_values FILE PREFIX: every line starting with PREFIX, prefix stripped.
marker_values() { grep -a -- "^$2" "$1" | sed "s/^$2//" || true; }
# tail_json FILE: what bpfcompat v0.4.0-rc.4 stores as stdout_tail for FILE
# (internal/vm/result.go readFileTail: last 4096 bytes, then
# strings.TrimSpace), JSON-encoded for an exact comparison.
tail_json() { tail -c 4096 "$1" | jq -Rs 'sub("\\A\\s+"; "") | sub("\\s+\\z"; "")'; }
readonly BEGIN_MARK='----- BEGIN bpfcompat-validator-json -----'
readonly END_MARK='----- END bpfcompat-validator-json -----'
# extract_validator_json STDOUT: the lines strictly between the markers.
extract_validator_json() {
  awk -v b="$BEGIN_MARK" -v e="$END_MARK" '$0 == b {on=1; next} $0 == e {on=0} on' "$1"
}

# ---- report-level clauses (R*) ------------------------------------------------
# check_report REPORT -> sets REPORT_KA_SHA (the guest-observed KubeArmor commit
# from the stdout tails, when consistent).
REPORT_KA_SHA=""
declare -A OBSERVED_KERNEL=()
check_report() {
  local report="$1"
  if [[ ! -s "$report" ]] || ! jq -e 'type == "object"' "$report" >/dev/null 2>&1; then
    inconclusive "R0 report ${report} is missing or not JSON"
    return
  fi
  if jq -e '.summary.verdict == "INFRA_ERROR" or any(.targets[]?; .verdict == "INFRA_ERROR")' "$report" >/dev/null; then
    inconclusive "R0 report carries INFRA_ERROR (summary or a target)"
  fi
  jq -e '.schema_version == "v0.1"' "$report" >/dev/null || reject "R1 schema_version is not v0.1"

  local bin_sha
  bin_sha="$(jq -r '.command.binary.sha256 // empty' "$report")"
  if [[ "$bin_sha" == "$EXPECTED_VALIDATOR_SHA256" ]]; then
    okline "R2 command.binary.sha256 == rc.4 validator"
  elif [[ -n "$bin_sha" ]]; then
    reject_definite "R2 command.binary.sha256 is ${bin_sha}, want ${EXPECTED_VALIDATOR_SHA256} (the validator shipped to the guests is not the rc.4 validator)"
  else
    reject "R2 command.binary.sha256 is ${bin_sha:-<missing>}, want ${EXPECTED_VALIDATOR_SHA256} (the validator shipped to the guests is not the rc.4 validator)"
  fi
  jq -e '.command.expected_exit_code == 0' "$report" >/dev/null || reject "R3 command.expected_exit_code is not 0"

  jq -e --arg n "$MATRIX_NAME" --arg a "${PROFILES[0]}" --arg b "${PROFILES[1]}" '
    .matrix.name == $n and ((.matrix.profiles // []) | sort) == ([$a, $b] | sort)
  ' "$report" >/dev/null || reject "R4 matrix is not ${MATRIX_NAME} with exactly ${PROFILES[*]}"

  jq -e '.summary.verdict == "COMPATIBLE" and .summary.status == "pass" and .summary.complete == true' "$report" >/dev/null ||
    reject "R5 summary is not COMPATIBLE/pass/complete: $(jq -c '.summary | {status, verdict, complete}' "$report")"

  local p n kernel rx tail_sha ka_values=""
  for p in "${PROFILES[@]}"; do
    n="$(jq --arg p "$p" '[.targets[]? | select(.profile_id == $p)] | length' "$report")"
    if [[ "$n" != 1 ]]; then
      reject "R6 ${p}: expected exactly one target, found ${n}"
      continue
    fi
    jq -e --arg p "$p" '
      .targets[] | select(.profile_id == $p)
      | .required == true and .status == "pass" and .verdict == "COMPATIBLE"
        and .environment.kernel_family_match == true and .environment.distro_match == true
        and ([.functional.tests[]? | select(.name == "command")] | length == 1
             and all(.[]; .status == "pass" and .exit_code == 0))
    ' "$report" >/dev/null ||
      reject "R6 ${p}: target is not required/pass/COMPATIBLE with matching kernel family+distro and a passing command"
    kernel="$(jq -r --arg p "$p" '.targets[] | select(.profile_id == $p) | .environment.observed_kernel // empty' "$report")"
    rx="$(kernel_regex "$p")"
    if [[ -n "$kernel" && "$kernel" =~ $rx ]]; then
      OBSERVED_KERNEL[$p]="$kernel"
      okline "R6 ${p}: booted kernel ${kernel}"
    else
      reject "R6 ${p}: observed kernel '${kernel:-<missing>}' does not match the profile family (${rx})"
    fi
    local base
    base="$(jq -r --arg p "$p" '.targets[] | select(.profile_id == $p) | (.notes // [])[] | select(startswith("base image sha256: ")) | ltrimstr("base image sha256: ")' "$report" | sort -u)"
    if [[ "$base" =~ ^[0-9a-f]{64}$ ]]; then
      okline "R6 ${p}: base image sha256 ${base}"
    else
      reject "R6 ${p}: report does not record exactly one 'base image sha256:' for the guest image"
    fi
    # R7: guest-observed identity in the report's stdout tail.
    local tailf
    tailf="$(mktemp)"
    jq -r --arg p "$p" '.targets[] | select(.profile_id == $p) | [.functional.tests[]? | select(.name == "command") | (.stdout_tail // "")] | join("\n")' "$report" >"$tailf"
    tail_sha="$(marker_values "$tailf" 'bpfcompat-validator-sha256=' | sort -u)"
    if [[ "$tail_sha" == "$EXPECTED_VALIDATOR_SHA256" ]]; then
      okline "R7 ${p}: guest-observed validator sha256 == rc.4 validator"
    elif [[ -n "$tail_sha" ]]; then
      reject_definite "R7 ${p}: guest-observed validator sha256 is '${tail_sha//$'\n'/,}', want ${EXPECTED_VALIDATOR_SHA256}"
    else
      reject "R7 ${p}: guest-observed validator sha256 is '${tail_sha:-<missing>}', want ${EXPECTED_VALIDATOR_SHA256}"
    fi
    local ka
    ka="$(marker_values "$tailf" 'kubearmor-source-sha=' | sort -u)"
    if [[ "$ka" =~ ^[0-9a-f]{40}$ ]]; then
      ka_values+="${ka}"$'\n'
    else
      reject "R7 ${p}: guest-observed kubearmor-source-sha is '${ka:-<missing>}' (want exactly one 40-hex commit)"
    fi
    rm -f "$tailf"
  done
  ka_values="$(printf '%s' "$ka_values" | sed '/^$/d' | sort -u)"
  if [[ "$ka_values" =~ ^[0-9a-f]{40}$ ]]; then
    REPORT_KA_SHA="$ka_values"
  elif [[ -n "$ka_values" ]]; then
    reject "R7 kubearmor-source-sha differs between kernels: ${ka_values//$'\n'/ }"
  fi
}

if [[ "$mode" == report-only ]]; then
  echo "== report-only contract check: ${target_path}"
  check_report "$target_path"
  finish
fi

# ---- bundle-level clauses (B*) ---------------------------------------------------
B="$target_path"
[[ -d "$B" ]] || { echo "INCONCLUSIVE: bundle ${B} is not a directory"; echo "RESULT: INCONCLUSIVE"; exit 2; }
B="$(cd "$B" && pwd)"
echo "== ${mode} contract check: ${B}"

# B1 integrity: every listed file verifies, every file is listed, paths stay inside.
excluded=()
[[ "$mode" == pre-seal ]] && excluded=(logs/procedure.log logs/contract-check.log)
if [[ ! -f "$B/SHA256SUMS" ]]; then
  reject_integrity "B1 SHA256SUMS is missing"
else
  declare -A listed=()
  while IFS= read -r line; do
    if [[ ! "$line" =~ ^([0-9a-f]{64})\ \ (.+)$ ]]; then
      reject_integrity "B1 malformed SHA256SUMS line: ${line}"
      continue
    fi
    sum="${BASH_REMATCH[1]}"
    f="${BASH_REMATCH[2]}"
    if [[ "$f" == /* || "$f" == *..* || "$f" == ./* ]]; then
      reject_integrity "B1 unsafe path in SHA256SUMS: ${f}"
      continue
    fi
    [[ -z "${listed[$f]:-}" ]] || reject_integrity "B1 duplicate SHA256SUMS entry: ${f}"
    listed[$f]=1
    if [[ ! -f "$B/$f" || -L "$B/$f" ]]; then
      reject_integrity "B1 listed file missing (or a symlink): ${f}"
    elif [[ "$(sha256sum -- "$B/$f" | awk '{print $1}')" != "$sum" ]]; then
      reject_integrity "B1 checksum mismatch (tampered?): ${f}"
    fi
  done <"$B/SHA256SUMS"
  while IFS= read -r f; do
    [[ "$f" == SHA256SUMS ]] && continue
    skip=false
    for x in "${excluded[@]}"; do [[ "$f" == "$x" ]] && skip=true; done
    [[ "$skip" == true ]] && continue
    [[ -n "${listed[$f]:-}" ]] || reject_integrity "B1 file not covered by SHA256SUMS: ${f}"
  done < <(cd "$B" && find . \( -type f -o -type l \) -printf '%P\n' | LC_ALL=C sort)
  ((integrity == 0)) && okline "B1 SHA256SUMS covers and verifies every file (${#listed[@]} entries)"
fi

need() { [[ -f "$B/$1" ]] || reject "B0 required file missing: $1"; }
for f in meta/started-at.txt meta/bpfcompat-version.json meta/bpfcompat-test.exit-code meta/kubearmor-pin.json \
  meta/guest-command.sh validator/validator-identity.json validator/bpfcompat-validator \
  reports/kubearmor.json host/host.txt host/qemu-version.txt host/kvm.txt; do
  need "$f"
done
if [[ "$mode" == full ]]; then
  need meta/finished-at.txt
  need verdict.json
fi

# B2 CLI identity.
if [[ -f "$B/meta/bpfcompat-version.json" ]]; then
  if jq -e --arg v "$EXPECTED_TAG" --arg c "$EXPECTED_COMMIT" '
      .version == $v and (.commit | type == "string" and length >= 12) and (.commit as $short | $c | startswith($short))
    ' "$B/meta/bpfcompat-version.json" >/dev/null 2>&1; then
    okline "B2 bpfcompat CLI is ${EXPECTED_TAG} at ${EXPECTED_COMMIT:0:12}"
  else
    reject_definite "B2 bpfcompat version is not ${EXPECTED_TAG}/${EXPECTED_COMMIT:0:12}: $(jq -c '{version, commit}' "$B/meta/bpfcompat-version.json" 2>/dev/null || echo unreadable)"
  fi
fi

# B3 validator identity (resolved release asset) and the shipped file.
if [[ -f "$B/validator/validator-identity.json" ]]; then
  jq -e --arg s "$EXPECTED_VALIDATOR_SHA256" --arg t "$EXPECTED_TAG" --arg c "$EXPECTED_COMMIT" '
    .schema == "bpfcompat.consumer-validator-identity.v1" and .mode == "release"
    and .tag == $t and .commit == $c and .sha256 == $s
    and (.provenance | startswith("sha256sums+github-attestation:"))
  ' "$B/validator/validator-identity.json" >/dev/null 2>&1 ||
    reject_definite "B3 validator-identity.json is not the attested ${EXPECTED_TAG} release validator ${EXPECTED_VALIDATOR_SHA256}"
fi
if [[ -f "$B/validator/bpfcompat-validator" ]]; then
  if [[ "$(sha256sum "$B/validator/bpfcompat-validator" | awk '{print $1}')" == "$EXPECTED_VALIDATOR_SHA256" ]]; then
    okline "B3 bundled validator hashes to ${EXPECTED_VALIDATOR_SHA256}"
  else
    reject_definite "B3 bundled validator does not hash to ${EXPECTED_VALIDATOR_SHA256}"
  fi
fi

# Report-level clauses.
check_report "$B/reports/kubearmor.json"

# B4 the report ran exactly the recorded guest command.
pin=""
if [[ -f "$B/meta/kubearmor-pin.json" ]]; then
  pin="$(jq -r '.commit // empty' "$B/meta/kubearmor-pin.json" 2>/dev/null || true)"
  [[ "$pin" =~ ^[0-9a-f]{40}$ ]] || { reject "B5 kubearmor-pin.json commit '${pin}' is not 40-hex"; pin=""; }
fi
if [[ -f "$B/meta/guest-command.sh" && -f "$B/reports/kubearmor.json" ]]; then
  inv="$(printf '%s\0expected-exit=0' "$(cat "$B/meta/guest-command.sh")" | sha256sum | awk '{print $1}')"
  if [[ "$(jq -r '.command.invocation_sha256 // empty' "$B/reports/kubearmor.json")" == "$inv" ]]; then
    okline "B4 report invocation_sha256 matches meta/guest-command.sh"
  else
    reject "B4 report invocation_sha256 does not match meta/guest-command.sh (a different guest command ran)"
  fi
  if [[ -n "$pin" ]] && ! grep -qx "KA_COMMIT=${pin}" "$B/meta/guest-command.sh"; then
    reject "B4 guest command does not pin KubeArmor to ${pin}"
  fi
  grep -qx "EXPECTED_VALIDATOR_SHA256=${EXPECTED_VALIDATOR_SHA256}" "$B/meta/guest-command.sh" ||
    reject "B4 guest command does not embed the expected validator sha256 for its pre-exec check"
  grep -q 'bpfcompat/releases/download' "$B/meta/guest-command.sh" &&
    reject "B4 guest command downloads a validator itself (must use \$BPFCOMPAT_BIN)"
fi

# B5 KubeArmor commit consistency (pin == every guest-observed value).
if [[ -n "$pin" ]]; then
  if [[ -n "$REPORT_KA_SHA" && "$REPORT_KA_SHA" != "$pin" ]]; then
    reject_definite "B5 guest-observed kubearmor-source-sha ${REPORT_KA_SHA} != pinned ${pin}"
  fi
fi

# B6 per-kernel full guest output: booted kernel, validator identity, and the
# validator's own per-program load + verifier outcome.
for p in "${PROFILES[@]}"; do
  out="$B/targets/${p}/command.stdout"
  if [[ ! -f "$out" ]]; then
    reject "B6 ${p}: full guest stdout targets/${p}/command.stdout is missing"
    continue
  fi
  kernel="${OBSERVED_KERNEL[$p]:-}"
  vals="$(marker_values "$out" 'guest-uname-r=' | sort -u)"
  if [[ -n "$kernel" && "$vals" == "$kernel" ]]; then
    okline "B6 ${p}: guest uname -r == ${kernel}"
  else
    reject "B6 ${p}: guest-uname-r '${vals//$'\n'/,}' missing or != report kernel '${kernel}'"
  fi
  pv="$(marker_values "$out" 'guest-proc-version=')"
  if [[ -n "$kernel" && "$(wc -l <<<"$pv")" -eq 1 && "$pv" == "Linux version ${kernel} "* ]]; then
    okline "B6 ${p}: /proc/version recorded"
  else
    reject "B6 ${p}: guest-proc-version missing or not 'Linux version ${kernel:-?} ...'"
  fi
  # The guest hashes $BPFCOMPAT_BIN before executing it (-pre, the guest
  # aborts with 93 on mismatch) and again afterwards; both must be rc.4.
  for marker in bpfcompat-validator-sha256-pre= bpfcompat-validator-sha256=; do
    vs="$(marker_values "$out" "$marker" | sort -u)"
    if [[ "$vs" == "$EXPECTED_VALIDATOR_SHA256" ]]; then
      okline "B6 ${p}: in-guest ${marker%=} == rc.4 validator"
    elif [[ -n "$vs" ]]; then
      reject_definite "B6 ${p}: in-guest ${marker%=} '${vs//$'\n'/,}' != ${EXPECTED_VALIDATOR_SHA256}"
    else
      reject "B6 ${p}: in-guest ${marker%=} line is missing"
    fi
  done
  ka="$(marker_values "$out" 'kubearmor-source-sha=' | sort -u)"
  if [[ -z "$ka" || -z "$pin" ]]; then
    reject "B6 ${p}: in-guest kubearmor-source-sha '${ka:-<missing>}' != pinned '${pin:-<none>}'"
  elif [[ "$ka" != "$pin" ]]; then
    reject_definite "B6 ${p}: in-guest kubearmor-source-sha '${ka//$'\n'/,}' != pinned '${pin}'"
  fi
  # The object the validator loaded is the one that was built: hashed after
  # the build (-pre) and again after the validator ran.
  op="$(marker_values "$out" 'kubearmor-object-sha256-pre=' | sort -u)"
  oa="$(marker_values "$out" 'kubearmor-object-sha256=' | sort -u)"
  if [[ "$op" =~ ^[0-9a-f]{64}$ && "$op" == "$oa" ]]; then
    okline "B6 ${p}: KubeArmor object sha256 ${op}"
  else
    reject "B6 ${p}: kubearmor-object-sha256-pre '${op//$'\n'/,}' and kubearmor-object-sha256 '${oa//$'\n'/,}' are not one equal 64-hex value"
  fi
  # B9 the full stdout is the one bpfcompat captured: its rc.4 tail must be
  # exactly the report's stdout_tail for this target.
  if [[ -f "$B/reports/kubearmor.json" ]] &&
    [[ "$(jq -c --arg p "$p" '[.targets[]? | select(.profile_id == $p) | .functional.tests[]? | select(.name == "command") | .stdout_tail] | if length == 1 then .[0] else null end' "$B/reports/kubearmor.json")" == "$(tail_json "$out" | jq -c .)" ]]; then
    okline "B9 ${p}: report stdout_tail == tail of command.stdout"
  else
    reject "B9 ${p}: report stdout_tail is not the tail of targets/${p}/command.stdout (stdout not bound to the report)"
  fi
  ve="$(marker_values "$out" 'validator-exit-code=' | sort -u)"
  [[ "$ve" == 0 ]] || reject "B6 ${p}: validator-exit-code is '${ve:-<missing>}', want 0"
  if [[ -f "$B/targets/${p}/command-exit-code" ]]; then
    [[ "$(tr -d '[:space:]' <"$B/targets/${p}/command-exit-code")" == 0 ]] ||
      reject "B6 ${p}: guest command exit code is not 0"
  fi
  nb="$(grep -cx -- "$BEGIN_MARK" "$out" || true)"
  ne="$(grep -cx -- "$END_MARK" "$out" || true)"
  lb="$(grep -nx -- "$BEGIN_MARK" "$out" | head -1 | cut -d: -f1 || true)"
  le="$(grep -nx -- "$END_MARK" "$out" | head -1 | cut -d: -f1 || true)"
  if [[ "$nb" != 1 || "$ne" != 1 || -z "$lb" || -z "$le" || "$lb" -ge "$le" ]]; then
    reject "B6 ${p}: expected exactly one BEGIN and one later END validator-json marker, found ${nb} BEGIN / ${ne} END"
    continue
  fi
  vj="$(mktemp)"
  extract_validator_json "$out" >"$vj"
  if ! jq -s -e 'length == 1 and (.[0] | type == "object")' "$vj" >/dev/null 2>&1; then
    reject "B6 ${p}: validator block must hold exactly one JSON document (object); found $(jq -s 'length' "$vj" 2>/dev/null || echo 'unparseable')"
    rm -f "$vj"
    continue
  fi
  # B10 the bundle's extracted copies are exactly what the guest printed.
  if [[ -f "$B/targets/${p}/validator.json" ]] && cmp -s "$vj" "$B/targets/${p}/validator.json"; then
    okline "B10 ${p}: targets/${p}/validator.json == block in command.stdout"
  else
    reject "B10 ${p}: targets/${p}/validator.json is missing or differs from the block in command.stdout"
  fi
  if [[ -f "$B/targets/${p}/libbpf.log" ]] && cmp -s <(jq -rj '.logs.libbpf // ""' "$vj") "$B/targets/${p}/libbpf.log"; then
    okline "B10 ${p}: targets/${p}/libbpf.log == validator .logs.libbpf"
  else
    reject "B10 ${p}: targets/${p}/libbpf.log is missing or differs from the validator's .logs.libbpf"
  fi
  jq -e '.input.artifact == "system_monitor.bpf.o" and .input.probe_features == true' "$vj" >/dev/null ||
    reject "B6 ${p}: validator input is not system_monitor.bpf.o with probe_features=true: $(jq -c '.input | {artifact, probe_features}' "$vj")"
  jq -e --arg k "$kernel" '.host.release == $k' "$vj" >/dev/null ||
    reject "B6 ${p}: validator host.release $(jq -c '.host.release' "$vj") != booted kernel '${kernel}'"
  jq -e '.status == "pass" and .load.status == "pass"' "$vj" >/dev/null ||
    reject "B6 ${p}: validator status/load is not pass: $(jq -c '{status, load}' "$vj")"
  if jq -e --argjson max "$MAX_PROGRAMS" '
      (.discovery.programs | type == "array" and length > 0)
      and .discovery.program_count == (.discovery.programs | length)
      and .discovery.program_count <= $max
      and all(.discovery.programs[]; (.name | type == "string" and length > 0)
                                     and (.load_status | IN("pass", "fail", "skipped")))
    ' "$vj" >/dev/null; then
    counts="$(jq -r '[.discovery.programs[].load_status] | "pass=\(map(select(. == "pass")) | length) fail=\(map(select(. == "fail")) | length) skipped=\(map(select(. == "skipped")) | length) total=\(length)"' "$vj")"
    if jq -e '([.discovery.programs[] | select(.load_status == "fail")] | length == 0)
              and ([.discovery.programs[] | select(.load_status == "pass")] | length > 0)' "$vj" >/dev/null; then
      okline "B6 ${p}: per-program loads ${counts}"
    else
      reject "B6 ${p}: per-program loads not clean (${counts}); failed: $(jq -c '[.discovery.programs[] | select(.load_status == "fail") | {name, load_errno}]' "$vj")"
    fi
  else
    reject "B6 ${p}: per-program load results missing, truncated or malformed (program_count vs programs[], max ${MAX_PROGRAMS})"
  fi
  rm -f "$vj"
done

# B7 run timing and outcome records.
iso='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
st="$(cat "$B/meta/started-at.txt" 2>/dev/null || true)"
[[ "$st" =~ $iso ]] || reject "B7 meta/started-at.txt is not a UTC timestamp"
if [[ "$mode" == full ]]; then
  fi_="$(cat "$B/meta/finished-at.txt" 2>/dev/null || true)"
  if [[ "$fi_" =~ $iso && "$st" =~ $iso ]]; then
    [[ ! "$fi_" < "$st" ]] || reject "B7 finished-at ${fi_} precedes started-at ${st}"
  else
    reject "B7 meta/finished-at.txt is not a UTC timestamp"
  fi
fi
if [[ -f "$B/meta/bpfcompat-test.exit-code" ]]; then
  [[ "$(tr -d '[:space:]' <"$B/meta/bpfcompat-test.exit-code")" == 0 ]] || reject "B7 bpfcompat test exit code is not 0"
fi
grep -qx 'kvm-access=rw' "$B/host/kvm.txt" 2>/dev/null || reject "B7 host/kvm.txt does not record read-write /dev/kvm"

# B8 the runner's own record must agree (it cannot upgrade a rejection).
if [[ "$mode" == full && -f "$B/verdict.json" ]]; then
  jq -e --arg k "$pin" '.verdict == "VERIFIED" and .dry_run == false and .kubearmor_commit == $k' "$B/verdict.json" >/dev/null 2>&1 ||
    reject "B8 verdict.json is not a non-dry-run VERIFIED record for KubeArmor ${pin:-<none>}: $(jq -c '{verdict, dry_run, reason}' "$B/verdict.json" 2>/dev/null)"
fi

finish
