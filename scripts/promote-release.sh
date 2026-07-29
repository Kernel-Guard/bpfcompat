#!/usr/bin/env bash
set -euo pipefail

image="${1:-}"
digest="${2:-}"
release_tag="${3:-}"
channel="${4:-}"

fail() {
  echo "[release-promotion] $*" >&2
  exit 2
}

[[ -n "$image" && -n "$digest" && -n "$release_tag" && -n "$channel" ]] ||
  fail "usage: promote-release.sh IMAGE SHA256_DIGEST RELEASE_TAG CHANNEL"
[[ "$image" =~ ^[a-z0-9][a-z0-9._/-]*$ ]] ||
  fail "invalid image reference"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  fail "digest must be sha256 followed by 64 lowercase hexadecimal characters"

stable_pattern='^v([0-9]+\.[0-9]+\.[0-9]+)$'
prerelease_pattern='^v([0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*)$'
tags=()
release_args=()

case "$channel" in
  stable)
    [[ "$release_tag" =~ $stable_pattern ]] ||
      fail "stable channel requires a vX.Y.Z tag"
    version="${BASH_REMATCH[1]}"
    minor="${version%.*}"
    tags=(
      --tag "${image}:${version}"
      --tag "${image}:${minor}"
      --tag "${image}:latest"
    )
    release_args=(--draft=false --latest)
    ;;
  prerelease)
    [[ "$release_tag" =~ $prerelease_pattern ]] ||
      fail "prerelease channel requires a vX.Y.Z-rc.N tag"
    version="${BASH_REMATCH[1]}"
    tags=(--tag "${image}:${version}")
    release_args=(--draft=false --prerelease)
    ;;
  *)
    fail "channel must be stable or prerelease"
    ;;
esac

docker buildx imagetools create \
  "${tags[@]}" \
  "${image}@${digest}"
docker buildx imagetools inspect "${image}:${version}"
gh release edit "$release_tag" "${release_args[@]}"

echo "[release-promotion] promoted ${release_tag} as ${channel}"
