#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${ROOT_DIR}/scripts/verify-promotion-inputs.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

commit="$(printf 'a%.0s' {1..40})"
digest="sha256:$(printf 'b%.0s' {1..64})"
printf 'fixture checksums\n' >"$tmp/SHA256SUMS"
checksums_sha="$(sha256sum "$tmp/SHA256SUMS" | awk '{print $1}')"

jq -n \
  --arg commit "$commit" \
  --arg image "ghcr.io/kernel-guard/bpfcompat@${digest}" \
  --arg checksums "$checksums_sha" '{
    schema_version: "v0.1",
    repository: "Kernel-Guard/bpfcompat",
    workflow: "Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/v0.4.0-rc.3",
    workflow_run_id: 12345,
    workflow_run_attempt: 2,
    commit_sha: $commit,
    tag: "v0.4.0-rc.3",
    channel: "prerelease",
    image: $image,
    checksums_sha256: $checksums,
    positive_report_sha256: ("c" * 64),
    negative_report_sha256: ("d" * 64),
    generated_at: "2026-07-30T12:00:00Z"
  }' >"$tmp/evidence.json"

"$script" "$tmp/evidence.json" Kernel-Guard/bpfcompat \
  v0.4.0-rc.3 12345 2 "$commit" "$digest" prerelease \
  "$tmp/SHA256SUMS" >"$tmp/pass.log"
grep -Fq '[promotion-inputs] PASS' "$tmp/pass.log"

for mutation in \
  '.workflow_run_id = 999' \
  '.workflow_run_attempt = 1' \
  '.commit_sha = ("e" * 40)' \
  '.tag = "v0.4.0-rc.4"' \
  '.channel = "stable"' \
  '.image = "ghcr.io/kernel-guard/bpfcompat@sha256:" + ("f" * 64)' \
  '.checksums_sha256 = ("0" * 64)' \
  '.workflow = "Kernel-Guard/bpfcompat/.github/workflows/other.yml@refs/tags/v0.4.0-rc.3"'; do
  jq "$mutation" "$tmp/evidence.json" >"$tmp/bad.json"
  if "$script" "$tmp/bad.json" Kernel-Guard/bpfcompat \
    v0.4.0-rc.3 12345 2 "$commit" "$digest" prerelease \
    "$tmp/SHA256SUMS" >/dev/null 2>&1; then
    echo "[promotion-inputs-test] accepted mutated evidence: ${mutation}" >&2
    exit 1
  fi
done

if "$script" "$tmp/evidence.json" Kernel-Guard/bpfcompat \
  v0.4.0 12345 2 "$commit" "$digest" prerelease \
  "$tmp/SHA256SUMS" >/dev/null 2>&1; then
  echo "[promotion-inputs-test] accepted stable tag for prerelease channel" >&2
  exit 1
fi

echo "[promotion-inputs-test] PASS"
