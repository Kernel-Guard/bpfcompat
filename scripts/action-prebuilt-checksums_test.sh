#!/usr/bin/env bash
# Regression guard for the composite action's prebuilt-binary verification.
#
# v0.3.6 published the first linux/arm64 CLI, so its release SHA256SUMS listed
# three artifacts. The action only downloads the two amd64 assets it needs, then
# ran a bare `sha256sum -c SHA256SUMS`, which failed on the arm64 binary that was
# deliberately never fetched ("FAILED open or read"). Because verification is a
# hard error rather than a fallback, the action aborted on every amd64 runner and
# the "Run bpfcompat" step never executed -- observed across all 108 jobs of
# Inspektor Gadget lane rehearsal run 32901309056.
#
# The fix verifies exactly the downloaded assets, and stays fail-closed: an entry
# that is missing, duplicated, or malformed is an error, never a skipped check.
#
# This test EXTRACTS verify_prebuilt_checksums() straight out of action.yml (the
# single source of truth -- no duplicated logic to drift) and drives it against
# real files on disk, so the bug cannot silently return.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="$ROOT/action.yml"

fn="$(awk '
  /^        verify_prebuilt_checksums\(\) \{/ {f=1}
  f {print}
  f && /^        \}/ {exit}
' "$ACTION")"

if [[ -z "$fn" ]]; then
  echo "FAIL: could not extract verify_prebuilt_checksums() from $ACTION" >&2
  exit 1
fi
# shellcheck disable=SC2086
eval "$fn"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
case_no=0

# Builds a release directory: $1=case name, remaining args are the asset
# basenames to actually download. SHA256SUMS always covers amd64, arm64 and the
# validator, mirroring a real v0.3.6+ release.
setup_case() {
  local name="$1"
  shift
  case_no=$((case_no + 1))
  dir="$WORK/${case_no}-${name}"
  mkdir -p "$dir"
  local staging="$WORK/.staging-${case_no}"
  mkdir -p "$staging"
  printf 'amd64 cli\n' >"$staging/bpfcompat-linux-amd64"
  printf 'arm64 cli\n' >"$staging/bpfcompat-linux-arm64"
  printf 'static validator\n' >"$staging/bpfcompat-validator-static-linux-amd64"
  (
    cd "$staging"
    sha256sum bpfcompat-linux-amd64 bpfcompat-linux-arm64 \
      bpfcompat-validator-static-linux-amd64
  ) >"$dir/SHA256SUMS"
  local asset
  for asset in "$@"; do
    cp "$staging/$asset" "$dir/$asset"
  done
}

assert() { # $1=label  $2=PASS|FAIL
  local label="$1" want="$2" got
  if verify_prebuilt_checksums "$dir" \
    bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 \
    >/dev/null 2>&1; then
    got=PASS
  else
    got=FAIL
  fi
  if [[ "$got" != "$want" ]]; then
    printf 'FAIL: %-52s -> %s (want %s)\n' "$label" "$got" "$want" >&2
    fail=1
  else
    printf 'ok:   %-52s -> %s\n' "$label" "$got"
  fi
  # Whatever the verdict, the temporary checklist must never be left behind.
  local leftovers
  leftovers="$(find "$dir" -maxdepth 1 -name '.bpfcompat-checksums.*' | wc -l)"
  if [[ "$leftovers" -ne 0 ]]; then
    printf 'FAIL: %-52s left %s checklist file(s) behind\n' "$label" "$leftovers" >&2
    fail=1
  fi
}

# The exact v0.3.6 regression: SHA256SUMS covers arm64, which is never fetched.
setup_case arm64-listed-not-downloaded \
  bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64
assert "arm64 listed but not downloaded" PASS

# A downloaded asset whose bytes do not match the published checksum.
setup_case corrupted-amd64 \
  bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64
printf 'tampered\n' >"$dir/bpfcompat-linux-amd64"
assert "corrupted amd64 binary" FAIL

# A downloaded asset with no entry at all in SHA256SUMS.
setup_case entry-missing \
  bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64
grep -v ' bpfcompat-linux-amd64$' "$dir/SHA256SUMS" >"$dir/SHA256SUMS.tmp"
mv "$dir/SHA256SUMS.tmp" "$dir/SHA256SUMS"
assert "no SHA256SUMS entry for amd64" FAIL

# Two entries for one asset: ambiguous, so refuse rather than pick one.
setup_case entry-duplicated \
  bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64
dup_line="$(grep ' bpfcompat-linux-amd64$' "$dir/SHA256SUMS")"
printf '%s\n' "$dup_line" >>"$dir/SHA256SUMS"
assert "duplicate SHA256SUMS entry for amd64" FAIL

# A checksum field that is not a 64-hex digest.
setup_case entry-malformed \
  bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64
sed -i 's/^[0-9a-f]\{64\}\( \+bpfcompat-linux-amd64\)$/not-a-digest\1/' \
  "$dir/SHA256SUMS"
assert "malformed digest for amd64" FAIL

# The checksum file itself absent.
setup_case checksums-absent \
  bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64
rm -f "$dir/SHA256SUMS"
assert "SHA256SUMS absent" FAIL

# An asset the caller claims to have downloaded but did not.
setup_case asset-absent bpfcompat-linux-amd64
assert "validator asset never downloaded" FAIL

if [[ "$fail" -ne 0 ]]; then
  echo "prebuilt checksum verification regression test FAILED" >&2
  exit 1
fi
echo "all prebuilt checksum verification cases passed"
