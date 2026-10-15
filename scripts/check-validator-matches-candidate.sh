#!/usr/bin/env bash
# A stable release must ship the validator its release candidate qualified.
#
#   check-validator-matches-candidate.sh <built-validator> \
#     <candidate-SHA256SUMS> <candidate release-candidate-evidence.json> \
#     <expected-candidate-evidence-sha256>
#
# The stable tag rebuilds every asset. The CLI legitimately differs from the RC
# (version, commit and build date are linked in), but the validator has no
# embedded metadata: the same validator/ sources and build inputs give the same
# bytes. The four qualification campaigns ran the candidate validator, so a
# stable validator with other bytes is unqualified, whatever its source tree.
#
# Trust chain, all offline:
#   expected evidence sha256 (from the attested readiness / campaign binding)
#     -> sha256(release-candidate-evidence.json)
#     -> .checksums_sha256 == sha256(candidate SHA256SUMS)
#     -> the single bpfcompat-validator-static-linux-amd64 entry
#     == sha256(<built-validator>)
#
# Exit 0: identical. Exit 1: mismatch or broken chain (do not promote; cut a
# new release candidate). Exit 2: usage.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 <built-validator> <candidate-SHA256SUMS> <candidate-evidence.json> <expected-evidence-sha256>" >&2
  exit 2
fi
built="$1"
sums="$2"
evidence="$3"
expected_evidence="$4"
asset="bpfcompat-validator-static-linux-amd64"

[[ "$expected_evidence" =~ ^[0-9a-f]{64}$ ]] ||
  { echo "check-validator-matches-candidate: expected evidence sha256 must be 64 hex chars" >&2; exit 2; }
command -v jq >/dev/null || { echo "check-validator-matches-candidate: jq is required" >&2; exit 2; }

refuse() {
  echo "::error::$*"
  echo "check-validator-matches-candidate: do not promote; the stable validator is not the qualified one. Cut a new release candidate." >&2
  exit 1
}

for f in "$built" "$sums" "$evidence"; do
  [[ -s "$f" ]] || refuse "$f is missing or empty"
done

actual_evidence="$(sha256sum "$evidence" | awk '{print $1}')"
[[ "$actual_evidence" == "$expected_evidence" ]] ||
  refuse "candidate evidence sha256 $actual_evidence is not the bound $expected_evidence"

declared_sums="$(jq -r '.checksums_sha256 // empty' "$evidence")"
actual_sums="$(sha256sum "$sums" | awk '{print $1}')"
[[ -n "$declared_sums" && "$declared_sums" == "$actual_sums" ]] ||
  refuse "candidate SHA256SUMS sha256 $actual_sums is not the evidence's checksums_sha256 '${declared_sums}'"

entries="$(awk -v a="$asset" '($2 == a || $2 == "*" a) { print $1 }' "$sums")"
[[ "$(grep -c . <<<"$entries" || true)" -eq 1 ]] ||
  refuse "candidate SHA256SUMS must list $asset exactly once"
[[ "$entries" =~ ^[0-9a-f]{64}$ ]] || refuse "candidate $asset entry is not a sha256"

built_sha="$(sha256sum "$built" | awk '{print $1}')"
tag="$(jq -r '.tag // "unknown"' "$evidence")"
if [[ "$built_sha" != "$entries" ]]; then
  refuse "built validator $built_sha differs from candidate $tag validator $entries"
fi
echo "validator matches candidate $tag: $built_sha"
