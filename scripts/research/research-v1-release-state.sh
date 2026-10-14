#!/usr/bin/env bash
# Decide, read-only, whether scholarly-release-v1 may publish research-v1.
#
#   research-v1-release-state.sh <repository> <tag> <pinned-commit> <archive-lock.json> <work-dir>
#
# research-v1 is a one-time, immutable research release, created from
# <pinned-commit>. The workflow re-runs whenever its own file changes on main,
# so it must never re-attempt that publication from a later commit. Prints
# exactly one line on stdout, for $GITHUB_OUTPUT:
#
#   publish=true   neither the tag nor the release exists AND this run is the
#                  pinned commit (the original first publication);
#   publish=false  the tag and the release both exist and the release is
#                  verified intact:
#                    - the tag peels to the pinned commit;
#                    - the release is a non-draft, non-prerelease release
#                      with exactly the four archive assets;
#                    - archive-lock.json is byte-identical to the reviewed
#                      lock;
#                    - the manifest and payload ZIP match the lock;
#                    - RELEASE-CHECKSUMS.txt covers exactly the other three
#                      assets and verifies;
#                    - every asset carries a scholarly-release-v1.yml
#                      attestation for the pinned commit on refs/heads/main.
#
# Everything else exits non-zero:
#   - a tag without a release, or a release without a tag;
#   - a mismatched or incomplete release;
#   - a missing release while running from any other commit, which would
#     create a *different* research-v1;
#   - any lookup that could not be completed.
# Nothing is ever skipped silently.
#
# Environment: GITHUB_SHA (the commit under test). Overridable for the
# regression suite only: BPFCOMPAT_RESEARCH_REMOTE (git remote used to peel
# the tag).
set -euo pipefail

[[ "$#" -eq 5 ]] || { echo "usage: $0 <repository> <tag> <pinned-commit> <archive-lock.json> <work-dir>" >&2; exit 2; }
repo="$1"; tag="$2"; pinned="$3"; lock="$4"; work="$5"
remote="${BPFCOMPAT_RESEARCH_REMOTE:-https://github.com/${repo}.git}"
head_sha="${GITHUB_SHA:-}"

fail() {
  echo "::error title=research-v1 release state::$*" >&2
  exit 1
}

[[ "$pinned" =~ ^[0-9a-f]{40}$ ]] || fail "pinned commit is not a full SHA: ${pinned}"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail "GITHUB_SHA is not a full SHA: '${head_sha}'"
[[ -f "$lock" ]] || fail "missing archive lock: ${lock}"
mkdir -p -- "$work"

# Tag: found / absent / error, never guessed.
set +e
refs="$(git ls-remote --exit-code --tags "$remote" "refs/tags/${tag}" "refs/tags/${tag}^{}" 2>/dev/null)"
rc=$?
set -e
tag_commit=""
if [[ "$rc" -eq 2 && -z "$refs" ]]; then
  tag_state=absent
elif [[ "$rc" -eq 0 && -n "$refs" ]]; then
  tag_state=found
  direct=""; peeled=""
  while IFS=$'\t' read -r sha ref; do
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail "malformed ls-remote answer for ${tag}"
    case "$ref" in
      "refs/tags/${tag}^{}") peeled="$sha" ;;
      "refs/tags/${tag}") direct="$sha" ;;
      *) fail "unexpected ref in ls-remote answer: ${ref}" ;;
    esac
  done <<<"$refs"
  # research-v1 was created annotated; a lightweight tag is not that tag.
  [[ -n "$peeled" ]] || fail "${tag} is not an annotated tag"
  [[ -n "$direct" ]] || fail "ls-remote answered only the peeled ref for ${tag}"
  tag_commit="$peeled"
else
  fail "could not query tag ${tag} on ${remote} (exit ${rc})"
fi

# Release: found / absent / error. Only gh's explicit "release not found"
# counts as absent; any other failure is an error.
set +e
release_json="$(gh release view "$tag" --repo "$repo" --json tagName,isDraft,isPrerelease,assets 2>"$work/release.err")"
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  release_state=found
elif grep -Fqx 'release not found' "$work/release.err"; then
  release_state=absent
else
  fail "could not query release ${tag}: $(head -c 300 "$work/release.err")"
fi
rm -f "$work/release.err"

case "${tag_state}/${release_state}" in
  absent/absent)
    [[ "$head_sha" == "$pinned" ]] ||
      fail "${tag} is missing, but it is pinned to ${pinned}; publishing from ${head_sha} would create a different ${tag}. Investigate; it is never re-created automatically"
    echo "research-v1 state: first publication from the pinned commit" >&2
    echo "publish=true"
    exit 0
    ;;
  found/found) ;;
  found/absent) fail "${tag} tag exists without its release (incomplete publication)" ;;
  absent/found) fail "${tag} release exists without its tag (incomplete publication)" ;;
esac

[[ "$tag_commit" == "$pinned" ]] || fail "${tag} peels to ${tag_commit}, expected ${pinned}"

expected_assets='["RELEASE-CHECKSUMS.txt","archive-lock.json","archive-manifest.json","bpfcompat-research-v1-payload.zip"]'
jq -e --arg tag "$tag" --argjson assets "$expected_assets" '
  .tagName == $tag and .isDraft == false and .isPrerelease == false and
  ([.assets[].name] | sort) == $assets
' <<<"$release_json" >/dev/null ||
  fail "${tag} release is not the published four-asset research release: $(jq -c '{tagName,isDraft,isPrerelease,assets:[.assets[].name]}' <<<"$release_json" 2>/dev/null)"

dl="$work/assets"
rm -rf -- "$dl"; mkdir -p -- "$dl"
gh release download "$tag" --repo "$repo" --dir "$dl" || fail "could not download ${tag} assets"
[[ "$(cd "$dl" && find . -maxdepth 1 -type f -printf '%f\n' | sort | jq -Rsc 'split("\n") | map(select(length > 0)) | sort')" == "$expected_assets" ]] ||
  fail "downloaded ${tag} assets do not match the expected four files"

cmp -s -- "$dl/archive-lock.json" "$lock" || fail "${tag} archive-lock.json differs from the reviewed ${lock}"

sha() { sha256sum -- "$1" | awk '{print $1}'; }
jq -e \
  --arg manifest "sha256:$(sha "$dl/archive-manifest.json")" \
  --arg payload "sha256:$(sha "$dl/bpfcompat-research-v1-payload.zip")" \
  --argjson size "$(stat -c %s -- "$dl/bpfcompat-research-v1-payload.zip")" '
    .manifest.sha256 == $manifest and
    .payload_zip.sha256 == $payload and
    .payload_zip.size_bytes == $size
  ' "$lock" >/dev/null || fail "${tag} manifest or payload ZIP does not match the archive lock"

[[ "$(awk '{print $2}' "$dl/RELEASE-CHECKSUMS.txt" | sort | tr '\n' ' ')" == "archive-lock.json archive-manifest.json bpfcompat-research-v1-payload.zip " ]] ||
  fail "${tag} RELEASE-CHECKSUMS.txt does not list exactly the three archive files"
(cd "$dl" && sha256sum --quiet --strict -c RELEASE-CHECKSUMS.txt) >&2 ||
  fail "${tag} RELEASE-CHECKSUMS.txt does not verify"

for asset in archive-lock.json archive-manifest.json bpfcompat-research-v1-payload.zip RELEASE-CHECKSUMS.txt; do
  gh attestation verify "$dl/$asset" \
    --repo "$repo" \
    --signer-workflow "${repo}/.github/workflows/scholarly-release-v1.yml" \
    --source-digest "$pinned" \
    --source-ref refs/heads/main >/dev/null ||
    fail "${tag} ${asset} has no scholarly-release-v1.yml attestation for ${pinned}"
done

echo "research-v1 state: already published at ${pinned} and verified intact; not re-publishing" >&2
echo "publish=false"
