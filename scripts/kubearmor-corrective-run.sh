#!/usr/bin/env bash
# Controlled, operator-approved corrective KubeArmor compatibility run for
# v0.4.0-rc.4.
#
# Why this exists: external-consumer-canary run 38609582942 (attempt 1, job
# 116009175474) recorded KubeArmor as passing for the rc.4 candidate, but its
# guest command downloaded and ran the v0.3.7 validator (hard-coded V=v0.3.7),
# not the rc.4 validator. That run is NOT rc.4 KubeArmor evidence. This script
# produces the replacement evidence under a fixed contract
# (docs/kubearmor-rc4-corrective-run.md) and never touches historical evidence.
#
# What it does, in order (every step is fatal; nothing falls back):
#   1. asserts the rc.4 checkout is exactly 222c3f38... with a clean tree,
#      builds the CLI there, and asserts `bpfcompat version --json` reports
#      v0.4.0-rc.4 at that commit;
#   2. resolves the validator with scripts/consumer-validator-identity.sh
#      (release asset of tag v0.4.0-rc.4: SHA256SUMS + GitHub build
#      attestation bound to the tag and commit) and aborts unless its sha256 is
#      the qualified e0e7fcf8...;
#   3. pins KubeArmor to the explicit 40-hex commit given on the command line
#      (no floating HEAD), proves it is fetchable, and records it;
#   4. (skipped by --dry-run) runs `bpfcompat test` in command mode over
#      matrices/consumer-external.yaml with the pinned guest command, shipping
#      the resolved validator as --command-binary;
#   5. (skipped by --dry-run) runs verify-report and the offline contract
#      checker scripts/check-kubearmor-corrective-evidence.sh;
#   6. always writes the evidence bundle (raw reports, logs, identity, CLI
#      version, host info, start/end `date -u`, verdict.json) and a
#      SHA256SUMS over every file in it.
#
# Verdicts (verdict.json .verdict): VERIFIED only when the guest run passed,
# verify-report passed AND the offline checker accepted the bundle;
# INCONCLUSIVE for infrastructure problems (missing host prerequisites, no
# report, INFRA_ERROR); FAILED for every mismatch or failed load. A dry run
# ends in DRY_RUN_OK or DRY_RUN_BLOCKED and is never evidence of compatibility.
#
# Usage:
#   kubearmor-corrective-run.sh --checkout DIR --kubearmor-commit SHA40
#       --out-dir DIR [--work-dir DIR] [--dry-run]
#   (gh >= 2.50 with `gh attestation`, authenticated, must be on PATH.)
set -euo pipefail

readonly EXPECTED_TAG="v0.4.0-rc.4"
readonly EXPECTED_COMMIT="222c3f38a5361fca7c43c33df841290f8bef0021"
readonly EXPECTED_VALIDATOR_SHA256="e0e7fcf8bd8384be3f85e4716d7330bdc0d3ae4d5de4070e815fa07c278be03a"
readonly REPO="Kernel-Guard/bpfcompat"
readonly KUBEARMOR_URL="https://github.com/kubearmor/KubeArmor"
readonly MATRIX_REL="matrices/consumer-external.yaml"
readonly TEST_TIMEOUT="25m"
readonly TEST_CONCURRENCY="2"
readonly DISK_RESIZE="4"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IDENTITY_SCRIPT="${SCRIPT_DIR}/consumer-validator-identity.sh"
CHECKER="${SCRIPT_DIR}/check-kubearmor-corrective-evidence.sh"

checkout="" ka_commit="" out_dir="" work_dir="" dry_run=false

usage() {
  sed -n '/^# Usage:/,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --checkout) checkout="${2:-}"; shift 2 ;;
    --kubearmor-commit) ka_commit="${2:-}"; shift 2 ;;
    --out-dir) out_dir="${2:-}"; shift 2 ;;
    --work-dir) work_dir="${2:-}"; shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    -h | --help) usage ;;
    *) usage ;;
  esac
done
[[ -n "$checkout" && -n "$ka_commit" && -n "$out_dir" ]] || usage

# The bundle is write-once: refuse to reuse a directory so no earlier
# evidence can ever be overwritten.
[[ ! -e "$out_dir" ]] || { echo "refusing to reuse existing --out-dir ${out_dir}" >&2; exit 2; }
mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"
work_dir="${work_dir:-${out_dir}.work}"
[[ ! -e "$work_dir" ]] || { echo "refusing to reuse existing --work-dir ${work_dir}" >&2; exit 2; }
mkdir -p "$out_dir"/{meta,host,validator,reports,targets,logs}

# Every procedure line goes to the terminal and to logs/procedure.log; each
# step's tool output goes to its own file under logs/.
LOG="${out_dir}/logs/procedure.log"

VERDICT="INCONCLUSIVE"
REASON="procedure did not complete"
STEP="init"
declare -A STEP_STATUS=()

log() {
  local line
  line="[kubearmor-corrective $(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
  echo "$line" >>"$LOG"
  echo "$line" >&2
}
# fail VERDICT REASON: record the outcome and stop (the EXIT trap seals the bundle).
fail() {
  VERDICT="$1"
  REASON="$2"
  STEP_STATUS[$STEP]="$1"
  log "ABORT (${VERDICT}) at step ${STEP}: ${REASON}"
  exit 1
}
step() {
  STEP="$1"
  log "== step: $1"
}
done_step() { STEP_STATUS[$STEP]="ok"; }

# write_sums [EXCLUDED-RELATIVE-PATH...]: SHA256SUMS over every file in the
# bundle except SHA256SUMS itself and the named paths.
write_sums() {
  local sums f x skip
  sums="$(mktemp)"
  while IFS= read -r f; do
    skip=false
    for x in SHA256SUMS "$@"; do [[ "$f" == "$x" ]] && skip=true; done
    [[ "$skip" == true ]] || (cd "$out_dir" && sha256sum -- "$f")
  done < <(cd "$out_dir" && find . -type f -printf '%P\n' | LC_ALL=C sort) >"$sums"
  mv "$sums" "${out_dir}/SHA256SUMS"
  chmod 0644 "${out_dir}/SHA256SUMS"
}

seal() {
  local rc=$?
  set +e
  date -u +%Y-%m-%dT%H:%M:%SZ >"${out_dir}/meta/finished-at.txt"
  local steps_json="{}"
  local k
  for k in "${!STEP_STATUS[@]}"; do
    steps_json="$(jq -c --arg k "$k" --arg v "${STEP_STATUS[$k]}" '. + {($k): $v}' <<<"$steps_json")"
  done
  jq -n \
    --arg verdict "$VERDICT" \
    --arg reason "$REASON" \
    --arg last_step "$STEP" \
    --argjson dry_run "$dry_run" \
    --arg tag "$EXPECTED_TAG" \
    --arg commit "$EXPECTED_COMMIT" \
    --arg validator "$EXPECTED_VALIDATOR_SHA256" \
    --arg kubearmor "$ka_commit" \
    --argjson steps "$steps_json" \
    '{
      schema: "bpfcompat.kubearmor-corrective-run.v1",
      verdict: $verdict,
      reason: $reason,
      last_step: $last_step,
      dry_run: $dry_run,
      expected: {tag: $tag, commit: $commit, validator_sha256: $validator},
      kubearmor_commit: $kubearmor,
      steps: $steps,
      note: "Supersedes nothing by itself: external-consumer-canary run 38609582942 (job 116009175474) ran the v0.3.7 validator and is not rc.4 KubeArmor evidence."
    }' >"${out_dir}/verdict.json"
  log "verdict: ${VERDICT} (${REASON})"
  # SHA256SUMS covers every file in the bundle except itself; nothing is
  # written into the bundle after it.
  write_sums
  echo "[kubearmor-corrective] bundle sealed: ${out_dir} (verdict ${VERDICT})" >&2
  if [[ "$VERDICT" == VERIFIED || "$VERDICT" == DRY_RUN_OK ]]; then exit 0; fi
  [[ $rc -ne 0 ]] && exit "$rc"
  exit 1
}
trap seal EXIT

date -u +%Y-%m-%dT%H:%M:%SZ >"${out_dir}/meta/started-at.txt"
log "started; dry_run=${dry_run} out=${out_dir} work=${work_dir}"

step arguments
[[ "$ka_commit" =~ ^[0-9a-f]{40}$ ]] || fail FAILED "--kubearmor-commit must be a full 40-hex commit id (got '${ka_commit}'); floating refs are refused"
done_step

# --- 0. host information and prerequisites -----------------------------------
step host-info
{
  echo "uname -a: $(uname -a)"
  echo "date -u: $(date -u)"
  [[ -r /etc/os-release ]] && sed 's/^/os-release: /' /etc/os-release
  echo "nproc: $(nproc)"
  free -b | sed 's/^/free: /'
  df -B1 --output=source,size,avail,target "$(dirname "$out_dir")" | sed 's/^/df: /'
} >"${out_dir}/host/host.txt" 2>&1
(qemu-system-x86_64 --version || echo "qemu-system-x86_64: MISSING") >"${out_dir}/host/qemu-version.txt" 2>&1
(qemu-img --version || echo "qemu-img: MISSING") >>"${out_dir}/host/qemu-version.txt" 2>&1
{
  ls -l /dev/kvm 2>&1 || true
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then echo "kvm-access=rw"; else echo "kvm-access=none"; fi
} >"${out_dir}/host/kvm.txt"
{
  for t in git go jq curl make sha256sum cloud-localds genisoimage gh; do
    if command -v "$t" >/dev/null 2>&1; then echo "${t}=$(command -v "$t")"; else echo "${t}=MISSING"; fi
  done
  echo "gh-version=$(gh --version 2>/dev/null | head -1)"
  echo "go-version=$(go version 2>/dev/null)"
  echo "jq-version=$(jq --version 2>/dev/null)"
} >"${out_dir}/host/tools.txt"

missing=()
for t in git go jq curl make sha256sum gh; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
gh attestation --help >/dev/null 2>&1 || missing+=("gh-attestation(gh>=2.50)")
boot_missing=()
command -v qemu-system-x86_64 >/dev/null 2>&1 || boot_missing+=("qemu-system-x86_64")
command -v qemu-img >/dev/null 2>&1 || boot_missing+=("qemu-img")
command -v cloud-localds >/dev/null 2>&1 || boot_missing+=("cloud-localds(cloud-image-utils; needed for almalinux-8 seed)")
[[ -r /dev/kvm && -w /dev/kvm ]] || boot_missing+=("/dev/kvm read-write")
printf '%s\n' "missing_pre_boot=${missing[*]:-none}" "missing_boot=${boot_missing[*]:-none}" >"${out_dir}/host/prerequisites.txt"
[[ ${#missing[@]} -eq 0 ]] || fail INCONCLUSIVE "missing host prerequisites: ${missing[*]}"
done_step

# --- 1. checkout + CLI identity ------------------------------------------------
step checkout
checkout="$(cd "$checkout" && pwd)"
head="$(git -C "$checkout" rev-parse --verify 'HEAD^{commit}')" || fail FAILED "cannot read checkout HEAD"
[[ "$head" == "$EXPECTED_COMMIT" ]] || fail FAILED "checkout HEAD ${head} != ${EXPECTED_COMMIT}"
dirty="$(git -C "$checkout" status --porcelain --untracked-files=all)"
[[ -z "$dirty" ]] || fail FAILED "checkout tree is not clean: ${dirty//$'\n'/; }"
head_tags="$(git -C "$checkout" tag --points-at HEAD)"
grep -qx -- "$EXPECTED_TAG" <<<"$head_tags" ||
  fail FAILED "tag ${EXPECTED_TAG} does not point at checkout HEAD"
{
  echo "head=${head}"
  echo "tags_at_head=${head_tags//$'\n'/ }"
  echo "remote=$(git -C "$checkout" remote get-url origin 2>/dev/null || echo none)"
} >"${out_dir}/meta/checkout.txt"
done_step

step build-cli
make -C "$checkout" build >"${out_dir}/logs/make-build.log" 2>&1 || fail FAILED "make build failed (logs/make-build.log)"
dirty="$(git -C "$checkout" status --porcelain --untracked-files=all)"
[[ -z "$dirty" ]] || fail FAILED "build dirtied the checkout: ${dirty//$'\n'/; }"
CLI="${checkout}/bin/bpfcompat"
"$CLI" version --json >"${out_dir}/meta/bpfcompat-version.json" || fail FAILED "bpfcompat version --json failed"
sha256sum "$CLI" | awk '{print $1}' >"${out_dir}/meta/bpfcompat-cli.sha256"
jq -e --arg v "$EXPECTED_TAG" --arg c "$EXPECTED_COMMIT" '
  .version == $v and (.commit | type == "string" and length >= 12) and (.commit as $short | $c | startswith($short))
' "${out_dir}/meta/bpfcompat-version.json" >/dev/null ||
  fail FAILED "bpfcompat version does not report ${EXPECTED_TAG} at ${EXPECTED_COMMIT}: $(jq -c . "${out_dir}/meta/bpfcompat-version.json")"
log "CLI: $(jq -c '{version, commit, go_version}' "${out_dir}/meta/bpfcompat-version.json")"
done_step

# --- 2. validator identity -------------------------------------------------------
step resolve-validator
bash "$IDENTITY_SCRIPT" resolve --out-dir "${out_dir}/validator" --tag "$EXPECTED_TAG" \
  --repo "$REPO" --root "$checkout" >"${out_dir}/logs/resolve-validator.log" 2>&1 ||
  fail FAILED "validator resolve/verification failed (logs/resolve-validator.log)"
IDENTITY="${out_dir}/validator/validator-identity.json"
VALIDATOR="${out_dir}/validator/bpfcompat-validator"
jq -e --arg sha "$EXPECTED_VALIDATOR_SHA256" --arg tag "$EXPECTED_TAG" --arg c "$EXPECTED_COMMIT" '
  .mode == "release" and .tag == $tag and .commit == $c and .sha256 == $sha
' "$IDENTITY" >/dev/null ||
  fail FAILED "resolved validator is not the qualified rc.4 validator: $(jq -c '{mode, tag, commit, sha256}' "$IDENTITY")"
[[ "$(sha256sum "$VALIDATOR" | awk '{print $1}')" == "$EXPECTED_VALIDATOR_SHA256" ]] ||
  fail FAILED "validator file on disk does not hash to ${EXPECTED_VALIDATOR_SHA256}"
log "validator: $(jq -c '{mode, tag, sha256, provenance}' "$IDENTITY")"
done_step

# --- 3. KubeArmor pin -------------------------------------------------------------
step pin-kubearmor
[[ "$ka_commit" =~ ^[0-9a-f]{40}$ ]] || fail FAILED "--kubearmor-commit must be a full 40-hex commit id (got '${ka_commit}')"
ka_probe="${work_dir}/kubearmor-pin-probe"
mkdir -p "$ka_probe"
{
  git -C "$ka_probe" init -q &&
    git -C "$ka_probe" fetch -q --depth 1 "$KUBEARMOR_URL" "$ka_commit" &&
    [[ "$(git -C "$ka_probe" rev-parse 'FETCH_HEAD^{commit}')" == "$ka_commit" ]]
} >"${out_dir}/logs/kubearmor-pin.log" 2>&1 ||
  fail FAILED "KubeArmor commit ${ka_commit} is not fetchable from ${KUBEARMOR_URL}"
libbpf_gitlink="$(git -C "$ka_probe" ls-tree "$ka_commit" KubeArmor/BPF/libbpf | awk '$2 == "commit" {print $3}')"
[[ "$libbpf_gitlink" =~ ^[0-9a-f]{40}$ ]] || fail FAILED "cannot read the libbpf submodule pin at ${ka_commit}"
jq -n \
  --arg url "$KUBEARMOR_URL" \
  --arg commit "$ka_commit" \
  --arg tree "$(git -C "$ka_probe" rev-parse "${ka_commit}^{tree}")" \
  --arg date "$(git -C "$ka_probe" show -s --format=%cI "$ka_commit")" \
  --arg subject "$(git -C "$ka_probe" show -s --format=%s "$ka_commit")" \
  --arg libbpf "$libbpf_gitlink" \
  '{schema: "bpfcompat.kubearmor-pin.v1", url: $url, commit: $commit, tree: $tree,
    committer_date: $date, subject: $subject, libbpf_submodule_commit: $libbpf}' \
  >"${out_dir}/meta/kubearmor-pin.json"
rm -rf "$ka_probe"
log "KubeArmor pin: $(jq -c . "${out_dir}/meta/kubearmor-pin.json")"
done_step

# --- 4. guest command ------------------------------------------------------------
# PR #249's KubeArmor guest command, with three changes: KubeArmor is fetched
# at the pinned commit instead of the floating default branch; the booted
# kernel identity is printed; the validator's exit code is captured so its
# full JSON is always printed (between markers) before the command exits with
# that code. The identity markers stay at the very end so they also land in
# the report's 4 KiB stdout_tail that verify-report reads.
step guest-command
GUEST_CMD_FILE="${out_dir}/meta/guest-command.sh"
cat >"$GUEST_CMD_FILE" <<'GUEST'
set -e
. /etc/os-release
echo "=== $ID $VERSION_ID on $(uname -r) ==="
echo "guest-uname-r=$(uname -r)"
echo "guest-proc-version=$(cat /proc/version)"
case "$ID" in
  ubuntu)
    export DEBIAN_FRONTEND=noninteractive; apt-get update -qq
    apt-get install -y -qq --no-install-recommends clang llvm libelf-dev make git ca-certificates curl linux-tools-$(uname -r) \
      || apt-get install -y -qq --no-install-recommends clang llvm libelf-dev make git ca-certificates curl linux-tools-generic
    apt-get clean; rm -rf /var/lib/apt/lists/* ;;
  almalinux|rocky|centos|rhel|ol|amzn)
    dnf install -y -q clang llvm bpftool elfutils-libelf-devel zlib-devel make git curl ;;
  *) echo "unsupported distro: $ID"; exit 91 ;;
esac
command -v bpftool >/dev/null || { echo "no bpftool on PATH"; exit 90; }
KA_COMMIT=@@KUBEARMOR_COMMIT@@
mkdir -p /root/KubeArmor
cd /root/KubeArmor
git init -q
git fetch -q --depth 1 https://github.com/kubearmor/KubeArmor "$KA_COMMIT"
git checkout -q --detach FETCH_HEAD
test "$(git rev-parse HEAD)" = "$KA_COMMIT" || { echo "kubearmor commit mismatch: $(git rev-parse HEAD)"; exit 92; }
cd KubeArmor/BPF
git submodule update --init --depth 1 libbpf
make kernel_headers >/dev/null
make system_monitor.bpf.o >/dev/null 2>&1
echo "built system_monitor.bpf.o against $(uname -r)"
set +e
"$BPFCOMPAT_BIN" \
  --artifact system_monitor.bpf.o \
  --set-map-inner-map kubearmor_visibility=hash:4:4:64 \
  --out /tmp/kubearmor-load.json
validator_rc=$?
set -e
echo "----- BEGIN bpfcompat-validator-json -----"
cat /tmp/kubearmor-load.json
echo
echo "----- END bpfcompat-validator-json -----"
echo "validator-exit-code=$validator_rc"
echo "kubearmor-object-sha256=$(sha256sum system_monitor.bpf.o | cut -d' ' -f1)"
echo "libbpf-submodule-sha=$(git -C libbpf rev-parse HEAD)"
echo "guest-uname-r=$(uname -r)"
echo "kubearmor-source-sha=$(git rev-parse HEAD)"
echo "bpfcompat-validator-sha256=$(sha256sum "$BPFCOMPAT_BIN" | cut -d' ' -f1)"
exit "$validator_rc"
GUEST
sed -i "s/@@KUBEARMOR_COMMIT@@/${ka_commit}/" "$GUEST_CMD_FILE"
grep -q '@@' "$GUEST_CMD_FILE" && fail FAILED "unsubstituted placeholder in guest command"
GUEST_CMD="$(cat "$GUEST_CMD_FILE")"
printf '%s\0expected-exit=0' "$GUEST_CMD" | sha256sum | awk '{print $1}' >"${out_dir}/meta/guest-command.invocation-sha256"
done_step

TEST_ARGV=(
  "$CLI" test
  --matrix "${checkout}/${MATRIX_REL}"
  --out "${out_dir}/reports/kubearmor.json"
  --markdown "${out_dir}/reports/kubearmor.md"
  --timeout "$TEST_TIMEOUT"
  --workdir "${work_dir}/bpfcompat"
  --concurrency "$TEST_CONCURRENCY"
  --command "$GUEST_CMD"
  --command-binary "$VALIDATOR"
  --disk-resize "$DISK_RESIZE"
)
{
  printf '%q ' "${TEST_ARGV[@]:0:14}"
  printf -- "--command \"\$(cat meta/guest-command.sh)\" "
  printf '%q ' "${TEST_ARGV[@]:16}"
  echo
} >"${out_dir}/meta/test-command.txt"

if [[ "$dry_run" == true ]]; then
  step dry-run-stop
  log "dry run: would run (cwd ${checkout}): $(cat "${out_dir}/meta/test-command.txt")"
  if [[ ${#boot_missing[@]} -gt 0 ]]; then
    VERDICT="DRY_RUN_BLOCKED"
    REASON="pre-boot steps passed; guest boot would be blocked by: ${boot_missing[*]}"
  else
    VERDICT="DRY_RUN_OK"
    REASON="pre-boot steps passed (checkout, CLI identity, validator identity, KubeArmor pin); guest boot skipped by --dry-run; NOT compatibility evidence"
  fi
  STEP_STATUS[$STEP]="$VERDICT"
  exit 0
fi

[[ ${#boot_missing[@]} -eq 0 ]] || { STEP=boot-prerequisites; fail INCONCLUSIVE "cannot boot guests: ${boot_missing[*]}"; }

# --- 5. guest run --------------------------------------------------------------------
step guest-run
set +e
(cd "$checkout" && "${TEST_ARGV[@]}") >"${out_dir}/logs/bpfcompat-test.log" 2>&1
test_rc=$?
set -e
echo "$test_rc" >"${out_dir}/meta/bpfcompat-test.exit-code"
log "bpfcompat test exit code: ${test_rc}"
shopt -s nullglob
for tdir in "${work_dir}"/bpfcompat/runs/*/targets/*/; do
  profile="$(basename "$tdir")"
  mkdir -p "${out_dir}/targets/${profile}"
  for f in command.stdout command.stderr command-exit-code serial.log; do
    [[ -f "${tdir}${f}" ]] && cp "${tdir}${f}" "${out_dir}/targets/${profile}/${f}"
  done
done
shopt -u nullglob
dirty="$(git -C "$checkout" status --porcelain --untracked-files=all)"
[[ -z "$dirty" ]] || log "WARNING: the run left untracked/modified files in the checkout: ${dirty//$'\n'/; }"
[[ -f "${out_dir}/reports/kubearmor.json" ]] || fail INCONCLUSIVE "bpfcompat test produced no report (exit ${test_rc})"
if jq -e '.summary.verdict == "INFRA_ERROR" or any(.targets[]?; .verdict == "INFRA_ERROR")' \
  "${out_dir}/reports/kubearmor.json" >/dev/null; then
  fail INCONCLUSIVE "report carries INFRA_ERROR (exit ${test_rc})"
fi
[[ "$test_rc" -eq 0 ]] || fail FAILED "bpfcompat test exited ${test_rc}"
done_step

# --- 6. report binding + offline contract -------------------------------------------
step verify-report
bash "$IDENTITY_SCRIPT" verify-report --identity "$IDENTITY" \
  --report "${out_dir}/reports/kubearmor.json" --mode command \
  >"${out_dir}/logs/verify-report.log" 2>&1 ||
  fail FAILED "verify-report rejected the report (logs/verify-report.log)"
done_step

step contract-check
# Seal a provisional SHA256SUMS so the checker sees exactly what is on disk.
write_sums logs/procedure.log
set +e
env -u BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256 \
  bash "$CHECKER" --pre-seal "$out_dir" >"${out_dir}/logs/contract-check.log" 2>&1
check_rc=$?
set -e
cat "${out_dir}/logs/contract-check.log" >&2
case "$check_rc" in
  0) ;;
  2) fail INCONCLUSIVE "offline contract checker: inconclusive (logs/contract-check.log)" ;;
  *) fail FAILED "offline contract checker rejected the bundle (logs/contract-check.log)" ;;
esac
[[ "$(tail -n 1 "${out_dir}/logs/contract-check.log")" == "RESULT: VERIFIED" ]] ||
  fail FAILED "offline contract checker did not end in an unqualified 'RESULT: VERIFIED'"
done_step

VERDICT="VERIFIED"
REASON="rc.4 validator ${EXPECTED_VALIDATOR_SHA256} loaded KubeArmor ${ka_commit} on every required kernel"
