#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# A tag workflow exports these variables to every child process. Individual
# fixtures below set them only when tag matching is the behavior under test.
unset GITHUB_REF_TYPE GITHUB_REF_NAME

script="scripts/check-release-consistency.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
current_release="$(
  awk -F': ' '$1 == "release_version" {print $2; exit}' release.yaml
)"

write_metadata() {
  local stable="$1"
  local release="$2"
  local channel="$3"
  local operator="${4:-ErenAri}"
  local approval_mode="${5:-solo-maintainer}"
  cat >"$tmp/release.yaml" <<EOF
stable_version: ${stable}
release_version: ${release}
release_channel: ${channel}
release_operator: ${operator}
approval_mode: ${approval_mode}
minimum_go: 1.25.12
report_schema: v0.1
EOF
}

BPFCOMPAT_RELEASE_METADATA=release.yaml "$script" >"$tmp/current.log"
grep -Fq 'channel=prerelease' "$tmp/current.log"

write_metadata 0.3.6 0.3.6 stable
BPFCOMPAT_RELEASE_METADATA="$tmp/release.yaml" "$script" >"$tmp/stable.log"
grep -Fq 'channel=stable' "$tmp/stable.log"

GITHUB_REF_TYPE=tag GITHUB_REF_NAME="v${current_release}" \
  BPFCOMPAT_RELEASE_METADATA=release.yaml "$script" >"$tmp/tag.log"

for bad_case in \
  "0.3.6 0.4.0-rc.1 stable ErenAri solo-maintainer" \
  "0.3.6 0.4.0 prerelease ErenAri solo-maintainer" \
  "0.3.6 0.4.0-rc.0 prerelease ErenAri solo-maintainer" \
  "0.3.6 0.3.6 prerelease ErenAri solo-maintainer" \
  "0.3.6 0.3.6 stable invalid_login_ solo-maintainer" \
  "0.3.6 0.3.6 stable ErenAri two-person"; do
  read -r stable release channel operator approval_mode <<<"$bad_case"
  write_metadata "$stable" "$release" "$channel" "$operator" "$approval_mode"
  if BPFCOMPAT_RELEASE_METADATA="$tmp/release.yaml" \
    "$script" >"$tmp/bad.log" 2>&1; then
    echo "[release-consistency-test] accepted invalid metadata: ${bad_case}" >&2
    exit 1
  fi
done

if GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v9.9.9 \
  BPFCOMPAT_RELEASE_METADATA=release.yaml \
  "$script" >"$tmp/bad-tag.log" 2>&1; then
  echo "[release-consistency-test] accepted mismatched release tag" >&2
  exit 1
fi

echo "[release-consistency-test] PASS"
