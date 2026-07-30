#!/usr/bin/env bash
set -euo pipefail

evidence="${1:-}"
repo="${2:-}"
release_tag="${3:-}"
run_id="${4:-}"
run_attempt="${5:-}"
expected_commit="${6:-}"
expected_digest="${7:-}"
expected_channel="${8:-}"
checksums="${9:-}"

fail() {
  echo "[promotion-inputs] $*" >&2
  exit 2
}

[[ -s "$evidence" ]] || fail "candidate evidence is missing or empty"
[[ -s "$checksums" ]] || fail "candidate checksums are missing or empty"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "repository must be owner/name"
[[ "$run_id" =~ ^[1-9][0-9]*$ ]] ||
  fail "candidate run ID must be a positive integer"
[[ "$run_attempt" =~ ^[1-9][0-9]*$ ]] ||
  fail "candidate run attempt must be a positive integer"
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] ||
  fail "expected commit must be a full lowercase SHA"
[[ "$expected_digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  fail "expected image digest must be sha256 followed by 64 lowercase hexadecimal characters"
[[ "$expected_channel" == "stable" || "$expected_channel" == "prerelease" ]] ||
  fail "expected channel must be stable or prerelease"

case "$expected_channel" in
  stable)
    [[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
      fail "stable promotion requires a vX.Y.Z tag"
    ;;
  prerelease)
    [[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*$ ]] ||
      fail "prerelease promotion requires a vX.Y.Z-rc.N tag"
    ;;
esac

checksums_sha256="$(sha256sum "$checksums" | awk '{print $1}')"
expected_image="ghcr.io/kernel-guard/bpfcompat@${expected_digest}"

jq -e \
  --arg repo "$repo" \
  --arg tag "$release_tag" \
  --argjson run_id "$run_id" \
  --argjson run_attempt "$run_attempt" \
  --arg commit "$expected_commit" \
  --arg channel "$expected_channel" \
  --arg image "$expected_image" \
  --arg checksums_sha256 "$checksums_sha256" '
    .schema_version == "v0.1" and
    .repository == $repo and
    (.workflow | contains(".github/workflows/release-artifacts.yml@")) and
    .workflow_run_id == $run_id and
    .workflow_run_attempt == $run_attempt and
    .commit_sha == $commit and
    .tag == $tag and
    .channel == $channel and
    .image == $image and
    .checksums_sha256 == $checksums_sha256 and
    (.positive_report_sha256 | test("^[0-9a-f]{64}$")) and
    (.negative_report_sha256 | test("^[0-9a-f]{64}$")) and
    (.generated_at | fromdateiso8601 > 0)
  ' "$evidence" >/dev/null ||
  fail "candidate evidence does not bind the exact promotion inputs"

echo "[promotion-inputs] PASS tag=${release_tag} run=${run_id}/${run_attempt} commit=${expected_commit} image=${expected_image}"
