#!/usr/bin/env bash
# Bind a scheduled latest-kernel campaign to the designated, immutable release
# candidate before anything is tested.
#
#   campaign-candidate-bind.sh <pin.json> <candidate-source-dir> <out-dir>
#
# Scheduled workflows always run on the default branch, so GITHUB_SHA says
# which *workflow source* ran, never which *candidate* was tested. This script
# establishes the second identity independently and fails closed:
#
#   1. the pin (.github/campaign-candidate.json, changed only by reviewed PR)
#      names an RC tag, its commit, its SHA256SUMS digest and its
#      release-candidate-evidence digest;
#   2. the tag peels to exactly that commit on the repository remote;
#   3. the tag's release is a published (non-draft) prerelease;
#   4. SHA256SUMS and release-candidate-evidence.json downloaded from it are
#      byte-identical to the pin, and the evidence names the same tag/commit;
#   5. the release CLI and static validator match their single SHA256SUMS
#      entries, and every executable plus the evidence carries a
#      release-artifacts.yml attestation for exactly that commit and tag;
#   6. the CLI reports that tag and commit itself (`version --json`);
#   7. the candidate source checkout is exactly that commit, unmodified.
#
# Output (in <out-dir>): candidate-binding.json, the verified executables, and
# candidate.env (lines for $GITHUB_ENV). Without a pin the campaign is
# explicitly unbound ({"bound": false}); readiness never accepts that.
#
# Overridable for offline tests only: BPFCOMPAT_REPOSITORY,
# BPFCOMPAT_CAMPAIGN_REMOTE (git remote used to peel the tag).
set -euo pipefail

[[ "$#" -eq 3 ]] || { echo "usage: $0 <pin.json> <candidate-source-dir> <out-dir>" >&2; exit 2; }
pin="$1"; src="$2"; out="$3"
repo="${BPFCOMPAT_REPOSITORY:-Kernel-Guard/bpfcompat}"
remote="${BPFCOMPAT_CAMPAIGN_REMOTE:-https://github.com/${repo}.git}"
readonly CLI_ASSET=bpfcompat-linux-amd64
readonly VALIDATOR_ASSET=bpfcompat-validator-static-linux-amd64
readonly EVIDENCE_ASSET=release-candidate-evidence.json

fail() {
  echo "::error title=campaign candidate binding::$*" >&2
  exit 1
}
sha() { sha256sum -- "$1" | awk '{print $1}'; }

mkdir -p -- "$out"
out="$(realpath -- "$out")"
rm -f -- "$out/candidate-binding.json" "$out/candidate.env"

if [[ ! -e "$pin" ]]; then
  jq -n '{schema_version: "v0.2", bound: false}' >"$out/candidate-binding.json"
  echo "campaign candidate: none designated; this campaign is unbound and cannot qualify a release"
  exit 0
fi

jq -e '
  (keys | sort) == ["candidate_evidence_sha256", "checksums_sha256", "commit_sha", "schema_version", "tag"] and
  .schema_version == "v0.1" and
  (.tag | test("^v[0-9]+\\.[0-9]+\\.[0-9]+-rc\\.[1-9][0-9]*$")) and
  (.commit_sha | test("^[0-9a-f]{40}$")) and
  (.checksums_sha256 | test("^[0-9a-f]{64}$")) and
  (.candidate_evidence_sha256 | test("^[0-9a-f]{64}$"))
' "$pin" >/dev/null 2>&1 || fail "candidate pin $pin is malformed"
tag="$(jq -r .tag "$pin")"
commit="$(jq -r .commit_sha "$pin")"
sums_sha="$(jq -r .checksums_sha256 "$pin")"
evidence_sha="$(jq -r .candidate_evidence_sha256 "$pin")"

# 2. The tag must peel to the pinned commit (annotated: ^{}; lightweight: ref).
refs="$(git ls-remote -- "$remote" "refs/tags/${tag}" "refs/tags/${tag}^{}")" ||
  fail "cannot list tag ${tag} on ${remote}"
peeled="$(awk -v r="refs/tags/${tag}^{}" '$2 == r {print $1}' <<<"$refs")"
[[ -n "$peeled" ]] || peeled="$(awk -v r="refs/tags/${tag}" '$2 == r {print $1}' <<<"$refs")"
[[ -n "$peeled" ]] || fail "tag ${tag} does not exist on ${remote}"
[[ "$peeled" == "$commit" ]] || fail "tag ${tag} peels to ${peeled}, not the pinned ${commit}"

# 3. A published prerelease, not a draft and not a stable release.
state="$(gh release view "$tag" --repo "$repo" --json isDraft,isPrerelease \
  --jq '"\(.isDraft) \(.isPrerelease)"')" || fail "cannot read release ${tag}"
[[ "$state" == "false true" ]] || fail "release ${tag} is not a published prerelease (isDraft isPrerelease = ${state})"

# 4. Download exactly the assets the campaign needs into a fresh directory.
assets="$out/candidate-assets"
rm -rf -- "$assets"; mkdir -p -- "$assets"
for asset in SHA256SUMS "$EVIDENCE_ASSET" "$CLI_ASSET" "$VALIDATOR_ASSET"; do
  gh release download "$tag" --repo "$repo" --dir "$assets" --pattern "$asset" ||
    fail "cannot download ${asset} from ${tag}"
  [[ -f "$assets/$asset" && ! -L "$assets/$asset" ]] || fail "release ${tag} has no ${asset}"
done
[[ "$(sha "$assets/SHA256SUMS")" == "$sums_sha" ]] ||
  fail "SHA256SUMS of ${tag} does not match the pinned digest"
[[ "$(sha "$assets/$EVIDENCE_ASSET")" == "$evidence_sha" ]] ||
  fail "${EVIDENCE_ASSET} of ${tag} does not match the pinned digest"
jq -e --arg repo "$repo" --arg tag "$tag" --arg commit "$commit" --arg sums "$sums_sha" '
  .repository == $repo and .channel == "prerelease" and
  .tag == $tag and .commit_sha == $commit and .checksums_sha256 == $sums
' "$assets/$EVIDENCE_ASSET" >/dev/null 2>&1 ||
  fail "${EVIDENCE_ASSET} does not describe ${tag} at ${commit} with the pinned SHA256SUMS"

# 5. Executables: exactly one SHA256SUMS entry each, matching bytes.
entry() {
  awk -v f="$1" '$2 == f && $1 ~ /^[0-9a-f]{64}$/ {n++; h = $1} END {if (n == 1) print h; else exit 1}' \
    "$assets/SHA256SUMS" || fail "SHA256SUMS must list $1 exactly once"
}
cli_sha="$(entry "$CLI_ASSET")"
validator_sha="$(entry "$VALIDATOR_ASSET")"
[[ "$(sha "$assets/$CLI_ASSET")" == "$cli_sha" ]] || fail "${CLI_ASSET} does not match SHA256SUMS"
[[ "$(sha "$assets/$VALIDATOR_ASSET")" == "$validator_sha" ]] || fail "${VALIDATOR_ASSET} does not match SHA256SUMS"
for asset in "$EVIDENCE_ASSET" "$CLI_ASSET" "$VALIDATOR_ASSET"; do
  gh attestation verify "$assets/$asset" --repo "$repo" \
    --signer-workflow "${repo}/.github/workflows/release-artifacts.yml" \
    --source-digest "$commit" --source-ref "refs/tags/${tag}" >/dev/null ||
    fail "${asset} has no release-artifacts.yml attestation for ${tag} at ${commit}"
done

# 6. The CLI must say it is this build. Release builds embed
#    `git rev-parse --short=12`, so the embedded commit must be a prefix of the
#    pinned commit of at least 12 hex characters. (The bytes themselves are
#    bound to the full commit by the attestation above.)
chmod 0755 -- "$assets/$CLI_ASSET" "$assets/$VALIDATOR_ASSET"
version_json="$("$assets/$CLI_ASSET" version --json)" || fail "${CLI_ASSET} cannot report its version"
jq -e --arg tag "$tag" --arg commit "$commit" '
  .version == $tag and (.commit | type == "string") and
  (.commit | test("^[0-9a-f]{12,40}$")) and (.commit as $embedded | $commit | startswith($embedded))
' \
  <<<"$version_json" >/dev/null 2>&1 ||
  fail "${CLI_ASSET} reports $(jq -c '{version, commit}' <<<"$version_json" 2>/dev/null || echo unknown), not ${tag} at ${commit}"

# 7. The source tree that supplies the action, matrix and fixtures.
head="$(git -C "$src" rev-parse HEAD 2>/dev/null)" || fail "candidate source ${src} is not a git checkout"
[[ "$head" == "$commit" ]] || fail "candidate source is at ${head}, not ${commit}"
[[ -z "$(git -C "$src" status --porcelain --untracked-files=no)" ]] || fail "candidate source has local modifications"

jq -n --arg tag "$tag" --arg commit "$commit" --arg sums "$sums_sha" --arg evidence "$evidence_sha" \
  --arg cli "$cli_sha" --arg validator "$validator_sha" '{
    schema_version: "v0.2",
    bound: true,
    tag: $tag,
    commit_sha: $commit,
    checksums_sha256: $sums,
    candidate_evidence_sha256: $evidence,
    cli_sha256: $cli,
    validator_sha256: $validator
  }' >"$out/candidate-binding.json"
{
  echo "BPFCOMPAT_CAMPAIGN_CLI=$assets/$CLI_ASSET"
  echo "BPFCOMPAT_VALIDATOR_BIN=$assets/$VALIDATOR_ASSET"
  echo "BPFCOMPAT_VALIDATOR_SHA256=$validator_sha"
} >"$out/candidate.env"
echo "campaign candidate: bound to ${tag} at ${commit}"
