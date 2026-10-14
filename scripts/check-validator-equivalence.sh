#!/usr/bin/env bash
# Decide whether a stable build ships the validator its release candidate was
# qualified with. Run before promoting a stable tag.
#
# The static validator carries no version stamp: its bytes are a function of
# validator/c-libbpf AND the build runner's toolchain (gcc, static glibc,
# libbpf-dev, libelf, zlib, zstd). v0.4.0-rc.3 and v0.4.0-rc.4 were built from
# the same validator/c-libbpf tree yet ship different validator bytes, so an
# unchanged tree alone proves nothing. A stable build is qualified-equivalent
# only when BOTH hold:
#   1. its SHA256SUMS entry for bpfcompat-validator-static-linux-amd64 is
#      byte-identical (sha256) to the qualified RC's validator, and
#   2. validator/c-libbpf at the stable ref is the same tree as at the RC ref.
# Anything else means the stable validator was never qualified: cut a new RC.
#
# usage: check-validator-equivalence.sh <stable-SHA256SUMS>
#          <stable-release-candidate-evidence.json> <qualified-validator-sha256>
#          <qualified-rc-ref> <stable-tag>
#
# The inputs are bound to the stable release first: the evidence must name
# <stable-tag> and its checksums_sha256 must be the sha256 of the SHA256SUMS
# given, so the RC's own SHA256SUMS/evidence cannot stand in for the stable's.
#
# Refs are resolved in BPFCOMPAT_REPO_DIR (default: this checkout), which must
# contain both commits (fetch tags first; a shallow CI checkout will not).
#
# Exit status: 0 qualified-equivalent, 1 not equivalent (every reason listed),
# 2 usage error.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo="${BPFCOMPAT_REPO_DIR:-$ROOT_DIR}"
asset="bpfcompat-validator-static-linux-amd64"
tree_path="validator/c-libbpf"

usage() {
  echo "usage: $0 <stable-SHA256SUMS> <stable-release-candidate-evidence.json> <qualified-validator-sha256> <qualified-rc-ref> <stable-tag>" >&2
  exit 2
}
die() {
  echo "[validator-equivalence] FAIL: $*" >&2
  exit 1
}

[[ "$#" -eq 5 ]] || usage
sums="$1"
evidence="$2"
qualified="$3"
rc_ref="$4"
stable_ref="$5"

[[ "$qualified" =~ ^[0-9a-f]{64}$ ]] || die "qualified validator sha256 must be 64 lowercase hex characters"
[[ -f "$sums" && ! -L "$sums" && -s "$sums" ]] || die "missing, empty or symlinked SHA256SUMS: ${sums}"
[[ -f "$evidence" && ! -L "$evidence" && -s "$evidence" ]] || die "missing, empty or symlinked evidence: ${evidence}"

# Bind the inputs to the stable release before judging them.
evidence_tag="$(jq -r 'if type == "object" and (.tag | type) == "string" then .tag else "" end' "$evidence" 2>/dev/null)" ||
  die "evidence is not JSON: ${evidence}"
evidence_sums="$(jq -r 'if type == "object" and (.checksums_sha256 | type) == "string" then .checksums_sha256 else "" end' "$evidence")"
[[ "$evidence_tag" == "$stable_ref" ]] ||
  die "evidence ${evidence} is for tag '${evidence_tag}', not the stable tag ${stable_ref}; inputs are not the stable release's"
sums_sha="$(sha256sum "$sums" | awk '{print $1}')"
[[ "$evidence_sums" == "$sums_sha" ]] ||
  die "sha256(${sums}) ${sums_sha} is not the evidence checksums_sha256 '${evidence_sums}'; SHA256SUMS is not the one ${stable_ref} attested"

entries="$(awk -v a="$asset" '$2 == a || $2 == "*" a {print $1}' "$sums")"
count="$(printf '%s' "$entries" | grep -c . || true)"
[[ "$count" -eq 1 ]] || die "${sums} must list ${asset} exactly once (found ${count})"
stable_sha="$entries"
[[ "$stable_sha" =~ ^[0-9a-f]{64}$ ]] || die "${sums} has a malformed ${asset} digest"

tree_of() { # $1 = ref
  git -C "$repo" rev-parse --verify --quiet "${1}^{commit}:${tree_path}" 2>/dev/null
}
rc_tree="$(tree_of "$rc_ref")" || die "cannot resolve ${rc_ref}:${tree_path} in ${repo} (fetch tags/history first)"
stable_tree="$(tree_of "$stable_ref")" || die "cannot resolve ${stable_ref}:${tree_path} in ${repo} (fetch tags/history first)"

reasons=()
if [[ "$stable_sha" != "$qualified" ]]; then
  reasons+=("stable ${asset} sha256 ${stable_sha} is not the qualified ${qualified}")
fi
if [[ "$stable_tree" != "$rc_tree" ]]; then
  reasons+=("${tree_path} changed: ${rc_ref} has tree ${rc_tree}, ${stable_ref} has ${stable_tree}")
fi

if ((${#reasons[@]} > 0)); then
  for reason in "${reasons[@]}"; do
    echo "[validator-equivalence] ${reason}" >&2
  done
  next="a new release candidate"
  if [[ "$rc_ref" =~ -rc\.([0-9]+)$ ]]; then
    next="rc.$((BASH_REMATCH[1] + 1))"
  fi
  die "the stable validator was not qualified by ${rc_ref}; do not promote: ${next} required"
fi
echo "[validator-equivalence] PASS: ${asset} ${stable_sha} and ${tree_path} tree ${stable_tree} match the qualified ${rc_ref}"
