#!/usr/bin/env bash
# Regression cover for validator identity in external-consumer-canary.yml.
#
# release-candidate-canary dispatches external-consumer-canary at the exact RC
# tag and records the result as the candidate's "external_consumers: pass".
# Through v0.4.0-rc.4 the KubeArmor lane nevertheless downloaded a hard-coded
# older validator inside each guest (V=v0.3.5 -> v0.3.6 -> v0.3.7), so the RC
# evidence for that consumer never exercised the RC's validator. This test
# pins three things:
#   1. the workflow carries no hard-coded release download and every lane
#      that runs the validator uses the one resolved by
#      scripts/consumer-validator-identity.sh and verifies its report;
#   2. the resolver binds release mode to the tag at HEAD, verifies checksum
#      and attestation, and never falls back to another version or a build;
#   3. verify-report rejects a report produced by any other validator.
#
# Usage: consumer-validator-identity_test.sh [WORKFLOW]
#   WORKFLOW defaults to this checkout's external-consumer-canary.yml; pass an
#   older copy to demonstrate that the guard fails on it.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/consumer-validator-identity.sh"
WORKFLOW="${1:-${ROOT_DIR}/.github/workflows/external-consumer-canary.yml}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
failures=0
ok() { pass=$((pass + 1)); }
bad() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}
check() { # $1 = label, rest = command that must succeed
  local label="$1"
  shift
  if "$@" >/dev/null; then ok; else bad "$label"; fi
}

# --- 1. workflow guard --------------------------------------------------------
if python3 - "$WORKFLOW" <<'PY'
import re, sys, yaml

wf = yaml.safe_load(open(sys.argv[1]))
errors = []
RES = "${{ steps.validator.outputs.path }}"
SHA = "${{ steps.validator.outputs.sha256 }}"
forbidden = [
    (re.compile(r"bpfcompat/releases/download/"), "hard-coded bpfcompat release download"),
    (re.compile(r"\bV=v[0-9]"), "hard-coded release version"),
    (re.compile(r"bpfcompat-validator-static-linux-amd64"), "validator asset fetched outside the resolver"),
]

for job_name, job in (wf.get("jobs") or {}).items():
    steps = job.get("steps") or []
    texts = []
    for st in steps:
        texts.append(st.get("run") or "")
        texts.append(((st.get("with") or {}).get("command")) or "")
    for text in texts:
        for rx, why in forbidden:
            if rx.search(text):
                errors.append(f"{job_name}: {why}: {rx.pattern}")

    local = [st for st in steps if st.get("uses") == "./"]
    for st in local:
        w = st.get("with") or {}
        env = st.get("env") or {}
        cmd = w.get("command") or ""
        runs_validator = bool(w.get("artifact")) or "--artifact" in cmd
        if not runs_validator:
            continue
        has_resolve = any(
            s.get("id") == "validator"
            and "consumer-validator-identity.sh" in (s.get("run") or "")
            and "resolve" in (s.get("run") or "")
            for s in steps
        )
        if not has_resolve:
            errors.append(f"{job_name}: no 'validator' step running consumer-validator-identity.sh resolve")
        if w.get("artifact"):
            mode = "artifact"
            if env.get("BPFCOMPAT_VALIDATOR_BIN") != RES:
                errors.append(f"{job_name}: BPFCOMPAT_VALIDATOR_BIN is not the resolved validator")
            if env.get("BPFCOMPAT_VALIDATOR_SHA256") != SHA:
                errors.append(f"{job_name}: BPFCOMPAT_VALIDATOR_SHA256 is not the resolved sha256")
        else:
            mode = "command"
            if w.get("command-binary") != RES:
                errors.append(f"{job_name}: command-binary is not the resolved validator")
            if '"$BPFCOMPAT_BIN"' not in cmd:
                errors.append(f"{job_name}: command does not run \"$BPFCOMPAT_BIN\"")
            if 'echo "bpfcompat-validator-sha256=$(sha256sum "$BPFCOMPAT_BIN"' not in cmd:
                errors.append(f"{job_name}: command does not print the guest-observed validator sha256")
        verified = any(
            "consumer-validator-identity.sh verify-report" in (s.get("run") or "")
            and f"--mode {mode}" in (s.get("run") or "")
            for s in steps
        )
        if not verified:
            errors.append(f"{job_name}: report is not checked with verify-report --mode {mode}")

if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
PY
then ok; else bad "workflow guard: ${WORKFLOW} does not bind every validator lane to the resolved identity"; fi

# --- shared fixtures ------------------------------------------------------------
ASSET=bpfcompat-validator-static-linux-amd64
REPO=Kernel-Guard/bpfcompat
mkdir -p "$tmp/bin" "$tmp/rel/v9.9.9-rc.1" "$tmp/rel/v9.9.8"

cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "attestation" && "${2:-}" == "--help" ]]; then exit 0; fi
if [[ "${1:-}" == "attestation" && "${2:-}" == "verify" ]]; then
  [[ "$*" == *"--repo Kernel-Guard/bpfcompat"* ]]
  # Real gh rejects --signer-workflow together with --cert-identity.
  [[ "$*" != *"--signer-workflow"* ]]
  [[ "$*" == *"--cert-identity https://github.com/Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/${BPFCOMPAT_TEST_TAG}"* ]]
  [[ "${BPFCOMPAT_TEST_ATTESTATION:-ok}" == "ok" ]]
  printf '[{"verificationResult":{"signature":{"certificate":{"sourceRepositoryDigest":"%s","sourceRepositoryRef":"%s"}}}}]\n' \
    "$BPFCOMPAT_TEST_DIGEST" "${BPFCOMPAT_TEST_REF:-refs/tags/${BPFCOMPAT_TEST_TAG}}"
  exit 0
fi
exit 1
EOF
chmod 0755 "$tmp/bin/gh"

seed_release() { # $1 tag, $2 content
  local d="$tmp/rel/$1"
  mkdir -p "$d"
  printf '%s\n' "$2" >"$d/$ASSET"
  (cd "$d" && sha256sum "$ASSET" >SHA256SUMS && printf '%s  bpfcompat-linux-amd64\n' "$(printf cli | sha256sum | cut -d' ' -f1)" >>SHA256SUMS)
}
seed_release v9.9.9-rc.1 "rc-validator"
seed_release v9.9.8 "old-validator"

repo_dir="$tmp/checkout"
git init -q "$repo_dir"
git -C "$repo_dir" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m base
mkdir -p "$repo_dir/validator/c-libbpf/bin"
COMMIT="$(git -C "$repo_dir" rev-parse HEAD)"

marker="$tmp/source-build-ran"
resolve() { # rest = extra args; env: BPFCOMPAT_TEST_TAG etc.
  rm -rf "$marker" "$tmp/out"
  PATH="$tmp/bin:$PATH" \
    BPFCOMPAT_RELEASE_BASE_URL="file://$tmp/rel" \
    BPFCOMPAT_SOURCE_BUILD_CMD="touch '$marker'; printf source-validator > validator/c-libbpf/bin/bpfcompat-validator" \
    BPFCOMPAT_TEST_DIGEST="${BPFCOMPAT_TEST_DIGEST:-$COMMIT}" \
    GITHUB_OUTPUT="" \
    bash "$SCRIPT" resolve --root "$repo_dir" --repo "$REPO" --out-dir "$tmp/out" "$@" \
    >"$tmp/log" 2>&1
}
expect_resolve_pass() {
  local label="$1"; shift
  if resolve "$@"; then ok; else bad "resolve expected PASS: ${label}"; cat "$tmp/log" >&2; fi
}
expect_resolve_fail() {
  local label="$1"; shift
  if resolve "$@"; then bad "resolve expected FAIL: ${label}"; cat "$tmp/log" >&2; return; fi
  if [[ -e "$marker" ]]; then bad "resolve fell back to a source build: ${label}"; return; fi
  if [[ -e "$tmp/out/bpfcompat-validator" ]]; then bad "resolve left a validator behind: ${label}"; return; fi
  ok
}

# --- 2. resolver ----------------------------------------------------------------
# No tag at HEAD: weekly run on main builds this checkout.
BPFCOMPAT_TEST_TAG=none expect_resolve_pass "source mode without tag"
check "source mode not recorded" jq -e '.mode == "source" and .tag == null and .asset == null' "$tmp/out/validator-identity.json"
check "source mode did not build" test -e "$marker"

# A requested tag that is not at HEAD is refused (the v0.3.7-in-RC-evidence case).
BPFCOMPAT_TEST_TAG=v9.9.8 expect_resolve_fail "requested tag not at HEAD" --tag v9.9.8

git -C "$repo_dir" tag v9.9.9-rc.1
export BPFCOMPAT_TEST_TAG=v9.9.9-rc.1
expect_resolve_pass "release mode from the tag at HEAD"
id="$tmp/out/validator-identity.json"
want_sha="$(sha256sum "$tmp/rel/v9.9.9-rc.1/$ASSET" | cut -d' ' -f1)"
# shellcheck disable=SC2016 # jq program, not shell
check "release identity record is wrong" jq -e --arg sha "$want_sha" --arg commit "$COMMIT" \
  '.mode == "release" and .tag == "v9.9.9-rc.1" and .sha256 == $sha and .commit == $commit
   and .asset == "bpfcompat-validator-static-linux-amd64" and (.sha256sums_sha256 | test("^[0-9a-f]{64}$"))' \
  "$id"
check "release mode also ran a source build" test ! -e "$marker"

expect_resolve_pass "explicit tag equal to HEAD tag" --tag v9.9.9-rc.1
expect_resolve_fail "explicit older tag while HEAD is the RC" --tag v9.9.8
expect_resolve_fail "malformed tag" --tag 'v1;rm'

cp "$tmp/rel/v9.9.9-rc.1/$ASSET" "$tmp/good"
printf 'tampered\n' >"$tmp/rel/v9.9.9-rc.1/$ASSET"
expect_resolve_fail "asset does not match SHA256SUMS"
cp "$tmp/good" "$tmp/rel/v9.9.9-rc.1/$ASSET"

cp "$tmp/rel/v9.9.9-rc.1/SHA256SUMS" "$tmp/sums"
cat "$tmp/sums" "$tmp/sums" >"$tmp/rel/v9.9.9-rc.1/SHA256SUMS"
expect_resolve_fail "duplicate SHA256SUMS entry"
grep -v "$ASSET" "$tmp/sums" >"$tmp/rel/v9.9.9-rc.1/SHA256SUMS"
expect_resolve_fail "missing SHA256SUMS entry"
cp "$tmp/sums" "$tmp/rel/v9.9.9-rc.1/SHA256SUMS"

BPFCOMPAT_TEST_ATTESTATION=fail expect_resolve_fail "attestation rejected"
BPFCOMPAT_TEST_DIGEST=0000000000000000000000000000000000000000 expect_resolve_fail "attestation from another commit"
BPFCOMPAT_TEST_REF=refs/heads/main expect_resolve_fail "attestation from a branch build"

mv "$tmp/rel/v9.9.9-rc.1" "$tmp/rel-hidden"
expect_resolve_fail "release asset missing (no fallback)"
mv "$tmp/rel-hidden" "$tmp/rel/v9.9.9-rc.1"

git -C "$repo_dir" tag v9.9.10
expect_resolve_fail "ambiguous tags at HEAD without --tag"
expect_resolve_pass "ambiguous tags resolved by --tag" --tag v9.9.9-rc.1
git -C "$repo_dir" tag -d v9.9.10 >/dev/null

# --- 3. verify-report -----------------------------------------------------------
expect_resolve_pass "re-resolve for report checks"
old_sha="$(sha256sum "$tmp/rel/v9.9.8/$ASSET" | cut -d' ' -f1)"

command_report() { # $1 = command.binary.sha256, $2 = guest marker sha (per target)
  jq -n --arg bin "$1" --arg m "bpfcompat-validator-sha256=$2" '{
    command: {binary: {sha256: $bin}},
    targets: [
      {profile_id: "a", functional: {tests: [{name: "command", stdout_tail: ("built\n" + $m)}]}},
      {profile_id: "b", functional: {tests: [{name: "command", stdout_tail: ("built\n" + $m)}]}}
    ]}'
}
verify() { # $1 mode, $2 report file
  bash "$SCRIPT" verify-report --identity "$id" --report "$2" --mode "$1" >"$tmp/log" 2>&1
}
expect_verify() { # $1 PASS|FAIL, $2 label, $3 mode, $4 report
  local got=FAIL
  if verify "$3" "$4"; then got=PASS; fi
  if [[ "$got" == "$1" ]]; then
    ok
  else
    bad "verify-report expected $1 got ${got}: $2"
    cat "$tmp/log" >&2
  fi
}

command_report "$want_sha" "$want_sha" >"$tmp/r-good.json"
expect_verify PASS "command mode bound to resolved validator" command "$tmp/r-good.json"

# The rc.4 shape: binary under test is an older release validator.
command_report "$old_sha" "$old_sha" >"$tmp/r-drift.json"
expect_verify FAIL "command mode ran an older release validator" command "$tmp/r-drift.json"

command_report "$want_sha" "$old_sha" >"$tmp/r-guest.json"
expect_verify FAIL "guest observed a different validator" command "$tmp/r-guest.json"

# Exactly what run 38609582942 produced for KubeArmor: no command binary at all.
jq 'del(.command.binary)' "$tmp/r-good.json" >"$tmp/r-nobin.json"
expect_verify FAIL "command mode without a shipped binary" command "$tmp/r-nobin.json"

jq '.targets[1].functional.tests[0].stdout_tail = "built"' "$tmp/r-good.json" >"$tmp/r-nomarker.json"
expect_verify FAIL "one target without the guest marker" command "$tmp/r-nomarker.json"

artifact_report() { # $1 = validator sha256
  jq -n --arg s "$1" '{
    validator: {sha256: $s},
    targets: [
      {profile_id: "a", required: true, status: "pass", validation: {load_status: "pass"}},
      {profile_id: "b", required: true, status: "pass", validation: {load_status: "pass"}}
    ]}'
}
artifact_report "$want_sha" >"$tmp/a-good.json"
expect_verify PASS "artifact mode bound to resolved validator" artifact "$tmp/a-good.json"
artifact_report "$old_sha" >"$tmp/a-drift.json"
expect_verify FAIL "artifact mode ran another validator" artifact "$tmp/a-drift.json"
jq 'del(.validator)' "$tmp/a-good.json" >"$tmp/a-missing.json"
expect_verify FAIL "artifact mode report without validator identity" artifact "$tmp/a-missing.json"
# A matching sha256 alone is not evidence: the validator must have run and
# loaded the artifact on every target.
jq '.targets = []' "$tmp/a-good.json" >"$tmp/a-empty.json"
expect_verify FAIL "artifact mode report with no targets" artifact "$tmp/a-empty.json"
jq 'del(.targets)' "$tmp/a-good.json" >"$tmp/a-notargets.json"
expect_verify FAIL "artifact mode report without a targets array" artifact "$tmp/a-notargets.json"
jq '.targets[1].validation.load_status = "fail"' "$tmp/a-good.json" >"$tmp/a-loadfail.json"
expect_verify FAIL "artifact mode target whose validator load failed" artifact "$tmp/a-loadfail.json"
jq '.targets[1].validation.load_status = "skipped"' "$tmp/a-good.json" >"$tmp/a-loadskip.json"
expect_verify FAIL "artifact mode target whose validator load was skipped" artifact "$tmp/a-loadskip.json"
jq 'del(.targets[0].validation)' "$tmp/a-good.json" >"$tmp/a-noload.json"
expect_verify FAIL "artifact mode target without a load status" artifact "$tmp/a-noload.json"
jq '.targets[0].status = "infra_error"' "$tmp/a-good.json" >"$tmp/a-infra.json"
expect_verify FAIL "artifact mode target that did not pass" artifact "$tmp/a-infra.json"

echo "[consumer-validator-identity-test] passed=${pass} failed=${failures}"
[[ "$failures" -eq 0 ]]
