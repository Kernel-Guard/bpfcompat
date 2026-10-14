#!/usr/bin/env bash
# Regression cover for scripts/check-validator-equivalence.sh.
#
# The defect it guards against (R3): a stable tag cut from a later commit than
# its qualified RC rebuilds the static validator. v0.4.0-rc.3 and v0.4.0-rc.4
# share the validator/c-libbpf tree but ship different validator bytes (runner
# toolchain drift), so "the source did not change" is not enough. Only a
# byte-identical SHA256SUMS entry plus an unchanged tree counts as qualified.
#
# The SHA256SUMS files under scripts/testdata/release-gate are the real
# published v0.4.0-rc.3 and v0.4.0-rc.4 assets. Refs are exercised in a
# throwaway git repository so the test also runs in a shallow CI checkout.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="${ROOT_DIR}/scripts/check-validator-equivalence.sh"
data="${ROOT_DIR}/scripts/testdata/release-gate"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

Q=e0e7fcf8bd8384be3f85e4716d7330bdc0d3ae4d5de4070e815fa07c278be03a # qualified rc.4 validator
RC4_SUMS="${data}/v0.4.0-rc.4/SHA256SUMS"
RC3_SUMS="${data}/v0.4.0-rc.3/SHA256SUMS"

fail_test() {
  echo "[validator-equivalence-test] $*" >&2
  exit 1
}
run() { # checker args; output in $tmp/out.log, exit status in $rc
  rc=0
  BPFCOMPAT_REPO_DIR="$repo" bash "$checker" "$@" >"$tmp/out.log" 2>&1 || rc=$?
}
expect_pass() { # $1 = label, rest = checker args
  local label="$1"
  shift
  run "$@"
  [[ "$rc" -eq 0 ]] || {
    cat "$tmp/out.log" >&2
    fail_test "expected PASS: ${label}"
  }
}
expect_fail() { # $1 = label, $2 = expected message fragment, rest = checker args
  local label="$1" want="$2"
  shift 2
  run "$@"
  [[ "$rc" -eq 1 ]] || {
    cat "$tmp/out.log" >&2
    fail_test "expected exit 1 for ${label}, got ${rc}"
  }
  grep -qF -- "$want" "$tmp/out.log" || {
    cat "$tmp/out.log" >&2
    fail_test "FAIL for ${label} did not mention: ${want}"
  }
}

# Throwaway history: rc.4 -> docs-only stable 0.4.0 -> validator-changing 0.4.1.
repo="$tmp/repo"
g() { git -C "$repo" -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false "$@"; }
mkdir -p "$repo/validator/c-libbpf/src" "$repo/docs"
git init -q "$repo"
printf 'int main(void) { return 0; }\n' >"$repo/validator/c-libbpf/src/main.c"
printf 'v1\n' >"$repo/docs/notes.md"
g add -A
g commit -q -m rc4
g tag v0.4.0-rc.4
printf 'v2\n' >"$repo/docs/notes.md"
g commit -q -am docs-only
g tag v0.4.0
printf 'int main(void) { return 1; }\n' >"$repo/validator/c-libbpf/src/main.c"
g commit -q -am validator-change
g tag v0.4.1

# --- Real published SHA256SUMS ----------------------------------------------
grep -q " bpfcompat-validator-static-linux-amd64$" "$RC4_SUMS"
expect_pass "rc.4 SHA256SUMS with an unchanged tree" "$RC4_SUMS" "$Q" v0.4.0-rc.4 v0.4.0
grep -qF "PASS: bpfcompat-validator-static-linux-amd64 ${Q}" "$tmp/out.log" ||
  fail_test "PASS line does not name the qualified sha256"

# rc.3's validator was built from the SAME validator/c-libbpf tree as rc.4's
# and still differs: tree equality alone must not pass.
expect_fail "rc.3 bytes, unchanged tree (toolchain drift)" "rc.5 required" \
  "$RC3_SUMS" "$Q" v0.4.0-rc.4 v0.4.0
grep -qF "is not the qualified ${Q}" "$tmp/out.log" || fail_test "sha mismatch reason missing"
if grep -qF "changed:" "$tmp/out.log"; then fail_test "tree reported changed when it is not"; fi

# --- Source drift -----------------------------------------------------------
expect_fail "identical bytes, changed validator tree" "validator/c-libbpf changed" \
  "$RC4_SUMS" "$Q" v0.4.0-rc.4 v0.4.1
grep -qF "rc.5 required" "$tmp/out.log" || fail_test "rc.5 message missing"

expect_fail "both bytes and tree differ, both reasons listed" "is not the qualified" \
  "$RC3_SUMS" "$Q" v0.4.0-rc.4 v0.4.1
grep -qF "validator/c-libbpf changed" "$tmp/out.log" || fail_test "tree reason missing"

# Next-RC wording follows the qualified RC; non-RC refs get a generic message.
g tag v0.5.0-rc.9 v0.4.0-rc.4
expect_fail "rc.9 qualifies -> rc.10" "rc.10 required" "$RC3_SUMS" "$Q" v0.5.0-rc.9 v0.4.0
expect_fail "untagged qualified ref" "a new release candidate required" \
  "$RC3_SUMS" "$Q" "$(g rev-parse v0.4.0-rc.4)" v0.4.0

# --- Malformed SHA256SUMS ---------------------------------------------------
grep -v ' bpfcompat-validator-static-linux-amd64$' "$RC4_SUMS" >"$tmp/missing.sums"
expect_fail "validator entry missing" "exactly once (found 0)" "$tmp/missing.sums" "$Q" v0.4.0-rc.4 v0.4.0
cat "$RC4_SUMS" "$RC4_SUMS" >"$tmp/dup.sums"
expect_fail "validator entry duplicated" "exactly once (found 2)" "$tmp/dup.sums" "$Q" v0.4.0-rc.4 v0.4.0
printf 'XYZ  bpfcompat-validator-static-linux-amd64\n' >"$tmp/bad.sums"
expect_fail "validator entry malformed" "malformed" "$tmp/bad.sums" "$Q" v0.4.0-rc.4 v0.4.0
printf '%s *bpfcompat-validator-static-linux-amd64\n' "$Q" >"$tmp/binary-mode.sums"
expect_pass "binary-mode sha256sum entry" "$tmp/binary-mode.sums" "$Q" v0.4.0-rc.4 v0.4.0
printf '%s  bpfcompat-validator-static-linux-amd64.sig\n' "$Q" >"$tmp/suffix.sums"
expect_fail "only a look-alike asset name" "exactly once (found 0)" "$tmp/suffix.sums" "$Q" v0.4.0-rc.4 v0.4.0
expect_fail "missing SHA256SUMS" "missing, empty or symlinked" "$tmp/none.sums" "$Q" v0.4.0-rc.4 v0.4.0
ln -s "$RC4_SUMS" "$tmp/link.sums"
expect_fail "symlinked SHA256SUMS" "missing, empty or symlinked" "$tmp/link.sums" "$Q" v0.4.0-rc.4 v0.4.0

# --- Bad arguments ----------------------------------------------------------
expect_fail "malformed qualified sha256" "64 lowercase hex" "$RC4_SUMS" notahash v0.4.0-rc.4 v0.4.0
expect_fail "upper-case qualified sha256" "64 lowercase hex" "$RC4_SUMS" "${Q^^}" v0.4.0-rc.4 v0.4.0
expect_fail "unknown RC ref" "cannot resolve v9.9.9-rc.1" "$RC4_SUMS" "$Q" v9.9.9-rc.1 v0.4.0
expect_fail "unknown stable ref" "cannot resolve v9.9.9" "$RC4_SUMS" "$Q" v0.4.0-rc.4 v9.9.9
run "$RC4_SUMS" "$Q" v0.4.0-rc.4
[[ "$rc" -eq 2 ]] || fail_test "usage error should exit 2, got ${rc}"

# --- Real repository history, when this checkout has it ---------------------
if git -C "$ROOT_DIR" rev-parse --verify --quiet 'v0.4.0-rc.3^{commit}' >/dev/null 2>&1 &&
  git -C "$ROOT_DIR" rev-parse --verify --quiet 'v0.4.0-rc.4^{commit}' >/dev/null 2>&1; then
  repo="$ROOT_DIR"
  expect_pass "real rc.4 tag against itself" "$RC4_SUMS" "$Q" v0.4.0-rc.4 v0.4.0-rc.4
  expect_fail "real rc.3 build vs qualified rc.4" "rc.5 required" "$RC3_SUMS" "$Q" v0.4.0-rc.4 v0.4.0-rc.3
else
  echo "[validator-equivalence-test] note: v0.4.0-rc.3/rc.4 tags not in this checkout; real-history cases skipped"
fi

echo "[validator-equivalence-test] PASS"
