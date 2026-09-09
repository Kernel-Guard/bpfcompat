#!/usr/bin/env bash
# Regression cover for scripts/verify-release-assets.sh, the step the GitHub
# Action runs before it trusts a downloaded release binary.
#
# The case that matters most is "extra checksum entries": v0.3.6 began
# publishing bpfcompat-linux-arm64, so the release SHA256SUMS listed three
# artifacts while the action downloads only the two amd64 ones. A bare
# `sha256sum -c SHA256SUMS` then failed on a file that was deliberately never
# fetched and, because verification is a hard error rather than a fallback,
# took the action down on every amd64 runner before a VM had booted. Verifying
# exactly the downloaded assets fixed it -- without loosening anything else,
# which is what the remaining cases pin down.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
verifier="${ROOT_DIR}/scripts/verify-release-assets.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

CLI=bpfcompat-linux-amd64
VALIDATOR=bpfcompat-validator-static-linux-amd64
ARM64=bpfcompat-linux-arm64

mkdir -p "$tmp/bin"

# A stub gh that accepts, but only for the exact repo and signer workflow the
# real verification demands -- so a call that drops either argument fails here.
cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "attestation" && "${2:-}" == "--help" ]]; then
  exit 0
fi
if [[ "${1:-}" == "attestation" && "${2:-}" == "verify" ]]; then
  [[ "$*" == *"--repo Kernel-Guard/bpfcompat"* ]]
  [[ "$*" == *"--signer-workflow Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml"* ]]
  [[ "${BPFCOMPAT_TEST_ATTESTATION:-ok}" == "ok" ]]
  exit 0
fi
exit 1
EOF
chmod 0700 "$tmp/bin/gh"

# A release directory holding only the assets the action actually downloads.
seed() { # $1 = directory
  local dir="$1"
  rm -rf "$dir"
  mkdir -p "$dir"
  printf 'cli\n' >"$dir/$CLI"
  printf 'validator\n' >"$dir/$VALIDATOR"
  (cd "$dir" && sha256sum "$CLI" "$VALIDATOR" >SHA256SUMS)
}

verify() { # $1 = directory, rest = asset basenames
  local dir="$1"
  shift
  PATH="$tmp/bin:$PATH" bash "$verifier" "$dir" Kernel-Guard/bpfcompat "$@" \
    >"$tmp/out.log" 2>&1
}

expect_pass() { # $1 = label, $2 = dir, rest = assets
  local label="$1"
  shift
  if ! verify "$@"; then
    echo "[release-assets-test] expected PASS but verification failed: ${label}" >&2
    cat "$tmp/out.log" >&2
    exit 1
  fi
}

expect_fail() { # $1 = label, $2 = dir, rest = assets
  local label="$1"
  shift
  if verify "$@"; then
    echo "[release-assets-test] expected FAIL but verification passed: ${label}" >&2
    cat "$tmp/out.log" >&2
    exit 1
  fi
}

d="$tmp/assets"

# 1. Downloaded assets match their entries.
seed "$d"
expect_pass "intact assets" "$d" "$CLI" "$VALIDATOR"

# 2. The v0.3.6 failure: SHA256SUMS covers an architecture this runner never
#    downloads. Entries for assets that are not on disk must be ignored, not
#    fatal.
seed "$d"
printf '%s  %s\n' "$(printf '%064d' 7)" "$ARM64" >>"$d/SHA256SUMS"
expect_pass "extra checksum entry for an asset that was not downloaded" \
  "$d" "$CLI" "$VALIDATOR"
test ! -e "$d/$ARM64"

# 3. A modified binary must never be installed.
seed "$d"
printf 'tampered\n' >"$d/$CLI"
expect_fail "tampered asset" "$d" "$CLI" "$VALIDATOR"

# 4. No entry for a downloaded asset means it was never checked -- fail, do
#    not skip.
seed "$d"
grep -v "  ${VALIDATOR}\$" "$d/SHA256SUMS" >"$d/SHA256SUMS.tmp"
mv "$d/SHA256SUMS.tmp" "$d/SHA256SUMS"
expect_fail "missing checksum entry" "$d" "$CLI" "$VALIDATOR"

# 5. Two entries for one asset: which one is authoritative is undefined, and a
#    forged second line must not be able to satisfy the check.
seed "$d"
grep "  ${CLI}\$" "$d/SHA256SUMS" >"$tmp/dup.line"
cat "$tmp/dup.line" >>"$d/SHA256SUMS"
expect_fail "duplicate checksum entry" "$d" "$CLI" "$VALIDATOR"

# 6. A malformed digest is not a digest.
seed "$d"
sed -i "s|^[0-9a-f]\{64\}\(  ${CLI}\)\$|notahash\1|" "$d/SHA256SUMS"
expect_fail "malformed checksum entry" "$d" "$CLI" "$VALIDATOR"

# 7. An asset the caller claims to have downloaded but did not.
seed "$d"
rm "$d/$VALIDATOR"
expect_fail "downloaded asset missing from disk" "$d" "$CLI" "$VALIDATOR"

# 8. No manifest at all.
seed "$d"
rm "$d/SHA256SUMS"
expect_fail "missing SHA256SUMS" "$d" "$CLI" "$VALIDATOR"

# 9. An asset name that escapes the release directory.
seed "$d"
expect_fail "path-traversal asset name" "$d" "../etc/passwd"

# 10. Checksums alone are not enough: assets must also carry a release-workflow
#     attestation. A failing attestation is fatal even when every digest
#     matches.
seed "$d"
if BPFCOMPAT_TEST_ATTESTATION=broken \
  PATH="$tmp/bin:$PATH" bash "$verifier" "$d" Kernel-Guard/bpfcompat \
  "$CLI" "$VALIDATOR" >"$tmp/out.log" 2>&1; then
  echo "[release-assets-test] expected FAIL but verification passed: failed attestation" >&2
  exit 1
fi

# 11. A runner with no usable gh must not fall through to "verified". The PATH
#     has to be genuinely empty -- keeping /usr/bin on it leaves the real gh
#     discoverable, and the case then "passes" on a later attestation error
#     while proving nothing about the missing-gh branch. Assert the diagnostic
#     so it cannot pass for the wrong reason again.
seed "$d"
mkdir -p "$tmp/emptybin"
if PATH="$tmp/emptybin" "$BASH" "$verifier" "$d" Kernel-Guard/bpfcompat \
  "$CLI" "$VALIDATOR" >"$tmp/out.log" 2>&1; then
  echo "[release-assets-test] expected FAIL but verification passed: no gh on PATH" >&2
  exit 1
fi
grep -Fq "GitHub CLI is required for attestation verification" "$tmp/out.log" || {
  echo "[release-assets-test] missing-gh case failed for the wrong reason:" >&2
  cat "$tmp/out.log" >&2
  exit 1
}

echo "[release-assets-test] PASS"
