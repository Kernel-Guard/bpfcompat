#!/usr/bin/env bash
# Offline regression guard for scripts/rollback-drill.sh (P4 backport).
#
# docker and cosign are replaced by stateful mocks: the registry is a
# directory of tag -> digest files, signatures are a digest -> identity map.
# Nothing here contacts GHCR. Covered: malformed input, unexpected ref and
# operator, wrong image identity, digest mismatch, version mismatch,
# restoration failure (loud, exit 3, manual recovery pointer), idempotent
# restore, and evidence verification.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${ROOT_DIR}/scripts/rollback-drill.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

image=ghcr.io/kernel-guard/bpfcompat
repo=Kernel-Guard/bpfcompat
before="sha256:$(printf 'b%.0s' {1..64})"
candidate="sha256:$(printf 'c%.0s' {1..64})"
operator="$(awk -F': ' '$1 == "release_operator" {print $2; exit}' "$ROOT_DIR/release.yaml")"
identity() { echo "https://github.com/${repo}/.github/workflows/release-artifacts.yml@refs/tags/$1"; }
legacy_identity() { echo "https://github.com/${repo}/.github/workflows/ghcr-image.yml@refs/tags/$1"; }

mkdir -p "$tmp/bin"
cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
# Mock registry: $MOCK_REG/<tag-with-slashes-replaced> holds a digest.
set -euo pipefail
key() { printf '%s' "$1" | tr '/:' '__'; }
if [[ -n "${MOCK_SEED_ALIAS:-}" && ! -f "$MOCK_REG/seeded" ]]; then
  # A drill alias stranded on another digest by an earlier, interrupted run.
  printf '%s' "$MOCK_SEED_ALIAS" >"$MOCK_REG/$(key ghcr.io/kernel-guard/bpfcompat:rollback-drill-v0.3.8-rc.1)"
  touch "$MOCK_REG/seeded"
fi
echo "docker $*" >>"$MOCK_REG/calls"
if [[ "$1 $2 $3" == "buildx imagetools inspect" ]]; then
  f="$MOCK_REG/$(key "$4")"
  if [[ -n "${MOCK_INSPECT_ERROR:-}" && "$4" == *rollback-drill-* ]]; then
    echo "ERROR: unexpected status from HEAD request to https://ghcr.io/v2/: 401 Unauthorized" >&2
    exit 1
  fi
  [[ -f "$f" ]] || { echo "ERROR: $4: not found" >&2; exit 1; }
  digest="$(cat "$f")"
  if [[ -n "${MOCK_INSPECT_LIES:-}" && "$4" == *rollback-drill-* && "$digest" == "$MOCK_INSPECT_LIES_FOR" ]]; then
    digest="sha256:$(printf '0%.0s' {1..64})"
  fi
  jq -n --arg d "$digest" '{digest: $d}'
  exit 0
fi
if [[ "$1 $2 $3" == "buildx imagetools create" ]]; then
  [[ "$4" == --tag ]]
  n="$(cat "$MOCK_REG/creates" 2>/dev/null || echo 0)"; n=$((n + 1)); echo "$n" >"$MOCK_REG/creates"
  if [[ -n "${MOCK_CREATE_FAIL_FROM:-}" && "$n" -ge "$MOCK_CREATE_FAIL_FROM" ]]; then exit 1; fi
  printf '%s' "${6##*@}" >"$MOCK_REG/$(key "$5")"
  exit 0
fi
if [[ "$1 $2" == "run --rm" ]]; then
  digest="${3##*@}"
  version="$(cat "$MOCK_REG/version-$digest" 2>/dev/null)" || exit 1
  jq -n --arg v "$version" '{version: $v}'
  exit 0
fi
exit 2
EOF
cat >"$tmp/bin/cosign" <<'EOF'
#!/usr/bin/env bash
# Mock signatures: $MOCK_REG/identity-<digest> is the only identity that verifies.
set -euo pipefail
identity="" ; ref="${*: -1}"
while [[ $# -gt 0 ]]; do
  [[ "$1" == --certificate-identity ]] && identity="$2"
  shift
done
[[ "$(cat "$MOCK_REG/identity-${ref##*@}" 2>/dev/null)" == "$identity" ]]
EOF
chmod 0700 "$tmp/bin/docker" "$tmp/bin/cosign"

reset_registry() {
  reg="$1"
  rm -rf "$reg"; mkdir -p "$reg"
  printf '%s' "$before" >"$reg/$(printf '%s' "$image:latest" | tr '/:' '__')"
  echo v0.3.7 >"$reg/version-$before"
  echo v0.3.8-rc.1 >"$reg/version-$candidate"
  if [[ -n "${MOCK_LEGACY_BEFORE:-}" ]]; then legacy_identity v0.3.7 >"$reg/identity-$before"; else identity v0.3.7 >"$reg/identity-$before"; fi
  identity v0.3.8-rc.1 >"$reg/identity-$candidate"
}
alias_digest() { cat "$1/$(printf '%s' "$image:rollback-drill-v0.3.8-rc.1" | tr '/:' '__')" 2>/dev/null || echo none; }

failures=0
# drill NAME WANT_RC SUBCOMMANDS [VAR=value...]
drill() {
  local name="$1" want="$2" subcommands="$3"
  shift 3
  local dir="$tmp/case-$RANDOM$RANDOM"
  mkdir -p "$dir"
  MOCK_LEGACY_BEFORE=""
  local arg
  for arg in "$@"; do [[ "$arg" == MOCK_LEGACY_BEFORE=1 ]] && MOCK_LEGACY_BEFORE=1; done
  reset_registry "$dir/reg"
  local rc=0 sub
  for sub in $subcommands; do
    env PATH="$tmp/bin:$PATH" MOCK_REG="$dir/reg" \
      IMAGE="$image" GITHUB_REPOSITORY="$repo" GITHUB_ACTOR="$operator" GITHUB_RUN_ID=77 \
      GITHUB_REF=refs/heads/release/v0.3.8-centos-hotfix \
      DRILL_ALLOWED_REF=refs/heads/release/v0.3.8-centos-hotfix \
      DRILL_ALIAS=rollback-drill-v0.3.8-rc.1 \
      BEFORE_DIGEST="$before" CANDIDATE_DIGEST="$candidate" \
      BEFORE_VERSION=v0.3.7 CANDIDATE_VERSION=v0.3.8-rc.1 \
      BEFORE_IDENTITY="$(identity v0.3.7)" CANDIDATE_IDENTITY="$(identity v0.3.8-rc.1)" \
      CONFIRMATION="rollback drill rollback-drill-v0.3.8-rc.1" \
      EVIDENCE_DIR="$dir/evidence" \
      "$@" bash "$script" "$sub" >>"$dir/log" 2>&1 || { rc=$?; break; }
  done
  last="$dir"
  if [[ "$rc" -eq "$want" ]]; then
    printf 'ok:   %s (rc=%s)\n' "$name" "$rc"
  else
    printf 'FAIL: %s (rc=%s want %s)\n' "$name" "$rc" "$want" >&2
    cat "$dir/log" >&2
    failures=$((failures + 1))
  fi
}
expect() { # description condition...
  local description="$1"; shift
  if "$@"; then printf 'ok:   %s\n' "$description"; else printf 'FAIL: %s\n' "$description" >&2; failures=$((failures + 1)); fi
}
latest_unchanged() { [[ "$(cat "$last/reg/$(printf '%s' "$image:latest" | tr '/:' '__')")" == "$before" ]]; }
no_mutation() { ! grep -q 'imagetools create' "$last/reg/calls" 2>/dev/null; }

full="validate verify drill verify-evidence"

drill "full drill restores the known-good digest" 0 "$full"
expect "  alias ends on the known-good digest" test "$(alias_digest "$last/reg")" = "$before"
expect "  latest is never written" latest_unchanged
expect "  only the drill alias is ever written" bash -c "! grep 'imagetools create' '$last/reg/calls' | grep -v ':rollback-drill-v0.3.8-rc.1 '"
expect "  evidence carries the completion marker" grep -Fq '[bpfcompat-rollback-drill:v1]' "$last/evidence/evidence.md"

# v0.3.7 predates the hardened release graph: its image is signed by
# ghcr-image.yml at the v0.3.7 tag. That exact legacy identity is accepted
# for the known-good endpoint only, and only for v0.3.7.
drill "legacy v0.3.7 known-good identity is accepted" 0 "validate" BEFORE_IDENTITY="$(legacy_identity v0.3.7)"
drill "full drill with the legacy v0.3.7 baseline restores it" 0 "$full" BEFORE_IDENTITY="$(legacy_identity v0.3.7)" \
  MOCK_LEGACY_BEFORE=1
expect "  alias ends on the known-good digest" test "$(alias_digest "$last/reg")" = "$before"
drill "legacy identity for the candidate is rejected" 2 "$full" \
  CANDIDATE_IDENTITY="$(legacy_identity v0.3.8-rc.1)"
drill "legacy identity for any other baseline version is rejected" 2 "$full" \
  BEFORE_VERSION=v0.3.6 BEFORE_IDENTITY="$(legacy_identity v0.3.6)"
drill "legacy workflow at another tag is rejected" 2 "$full" BEFORE_IDENTITY="$(legacy_identity v0.3.8-rc.1)"
drill "legacy workflow on a branch ref is rejected" 2 "$full" \
  BEFORE_IDENTITY="https://github.com/${repo}/.github/workflows/ghcr-image.yml@refs/heads/main"

# Malformed input: nothing may be written to the registry.
for bad in latest stable v0.3.7 rollback-drill-latest 'rollback-drill-v0.3.8-rc.1 ' 'rollback-drill-v0.3.8-rc.1;true' ROLLBACK-DRILL-v0.3.8-rc.1; do
  drill "malformed alias '$bad' is rejected" 2 "$full" DRILL_ALIAS="$bad" CONFIRMATION="rollback drill $bad"
  expect "  no registry write for '$bad'" no_mutation
done
drill "short digest is rejected" 2 "$full" CANDIDATE_DIGEST="sha256:abc"
drill "uppercase digest is rejected" 2 "$full" BEFORE_DIGEST="sha256:$(printf 'B%.0s' {1..64})"
drill "tag instead of digest is rejected" 2 "$full" CANDIDATE_DIGEST="$image:latest"
drill "identical endpoints are rejected" 2 "$full" CANDIDATE_DIGEST="$before"
drill "malformed version is rejected" 2 "$full" CANDIDATE_VERSION="0.3.8-rc.1"
drill "missing confirmation is rejected" 2 "$full" CONFIRMATION=""
drill "confirmation for another alias is rejected" 2 "$full" CONFIRMATION="rollback drill rollback-drill-v0.3.8-rc.2"

# Unexpected ref / operator.
drill "dispatch from main is rejected on the hotfix line" 2 "$full" GITHUB_REF=refs/heads/main
drill "dispatch from a tag is rejected" 2 "$full" GITHUB_REF=refs/tags/v0.3.8-rc.1
drill "dispatch from a lookalike branch is rejected" 2 "$full" GITHUB_REF=refs/heads/release/v0.3.8-centos-hotfix-x
drill "missing allowed ref fails closed" 2 "$full" DRILL_ALLOWED_REF=
drill "non-operator actor is rejected" 2 "$full" GITHUB_ACTOR=someone-else

# Wrong image identity.
drill "identity from another workflow is rejected" 2 "$full" \
  CANDIDATE_IDENTITY="https://github.com/${repo}/.github/workflows/ghcr-image.yml@refs/tags/v0.3.8-rc.1"
drill "identity for another tag is rejected" 2 "$full" CANDIDATE_IDENTITY="$(identity v0.3.8-rc.2)"
drill "identity from another repository is rejected" 2 "$full" \
  BEFORE_IDENTITY="https://github.com/evil/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/v0.3.7"
drill "image outside the product repository is rejected" 2 "$full" IMAGE=ghcr.io/evil/bpfcompat
drill "signature that does not verify is rejected before any write" 1 "$full" \
  CANDIDATE_VERSION=v0.3.8-rc.2 CANDIDATE_IDENTITY="$(identity v0.3.8-rc.2)" \
  CONFIRMATION="rollback drill rollback-drill-v0.3.8-rc.1"
expect "  no registry write after failed verification" no_mutation

# Digest and version mismatch.
drill "latest not on the known-good digest is refused before any write" 1 "$full" BEFORE_DIGEST="$candidate" \
  CANDIDATE_DIGEST="$before" BEFORE_VERSION=v0.3.8-rc.1 CANDIDATE_VERSION=v0.3.7 \
  BEFORE_IDENTITY="$(identity v0.3.8-rc.1)" CANDIDATE_IDENTITY="$(identity v0.3.7)"
expect "  no registry write when latest mismatches" no_mutation
drill "alias resolving to an unexpected digest after promotion is restored" 1 "$full" \
  MOCK_INSPECT_LIES=1 MOCK_INSPECT_LIES_FOR="$candidate"
expect "  alias was restored to the known-good digest" test "$(alias_digest "$last/reg")" = "$before"
expect "  latest untouched after mismatch" latest_unchanged

# Restoration failure must be loud and point at manual recovery.
drill "restoration failure exits 3" 3 "$full" MOCK_CREATE_FAIL_FROM=3
expect "  restoration failure names the manual recovery runbook" \
  grep -Fq 'docs/runbooks/rollback-drill-recovery.md' "$last/log"
expect "  restoration failure is not reported as a drill" bash -c "! test -e '$last/evidence/evidence.json'"

# Idempotent restore step (runs on failure/cancel in the workflow).
drill "restore is a no-op when the alias is already known-good" 0 "validate drill restore"
expect "  no-op restore does not write" test "$(grep -c 'imagetools create' "$last/reg/calls")" = 3
drill "restore with nothing to restore succeeds" 0 "validate restore"
drill "restore that cannot read the alias exits 3" 3 "validate restore" MOCK_INSPECT_ERROR=1
expect "  unreadable alias names the manual recovery runbook" \
  grep -Fq 'docs/runbooks/rollback-drill-recovery.md' "$last/log"
drill "restore returns a stranded alias to the known-good digest" 0 "validate restore" MOCK_SEED_ALIAS="$candidate"
expect "  stranded alias restored" test "$(alias_digest "$last/reg")" = "$before"
drill "restore that cannot write exits 3" 3 "validate restore" MOCK_SEED_ALIAS="$candidate" MOCK_CREATE_FAIL_FROM=1
expect "  failed restore names the manual recovery runbook" \
  grep -Fq 'docs/runbooks/rollback-drill-recovery.md' "$last/log"

# Evidence verification.
drill "evidence check rejects missing evidence" 2 "validate verify-evidence"
dir="$tmp/tamper"; mkdir -p "$dir"
drill "baseline drill for tamper checks" 0 "$full"
jq '.final_digest = .candidate_digest' "$last/evidence/evidence.json" >"$dir/e.json" && mv "$dir/e.json" "$last/evidence/evidence.json"
if env IMAGE="$image" DRILL_ALIAS=rollback-drill-v0.3.8-rc.1 BEFORE_DIGEST="$before" CANDIDATE_DIGEST="$candidate" \
  EVIDENCE_DIR="$last/evidence" GITHUB_RUN_ID=77 bash "$script" verify-evidence >/dev/null 2>&1; then
  echo 'FAIL: tampered evidence (final != known-good) was accepted' >&2; failures=$((failures + 1))
else
  echo 'ok:   tampered evidence (final != known-good) is rejected'
fi

if [[ "$failures" -ne 0 ]]; then
  echo "[rollback-drill-test] FAILED ($failures)" >&2
  exit 1
fi
echo "[rollback-drill-test] PASS"
