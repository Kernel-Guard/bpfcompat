#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# A tag workflow exports these variables to every child process. Individual
# fixtures below set them only when tag matching is the behavior under test.
unset GITHUB_REF_TYPE GITHUB_REF_NAME

script="scripts/check-release-consistency.sh"
tmp="$(mktemp -d)"
scholarly_workflow=".github/workflows/scholarly-release-v1.yml"
cp "$scholarly_workflow" "$tmp/scholarly-release-v1.yml"
research_workflow=".github/workflows/research-materialize-v1.yml"
research_script="scripts/research/materialize-v1.sh"
product_pin_workflow=".github/workflows/codeql.yml"
cp "$research_workflow" "$tmp/research-workflow.yml"
cp "$research_script" "$tmp/research-script.sh"
cp "$product_pin_workflow" "$tmp/product-pin-workflow.yml"
restore() {
  cp "$tmp/scholarly-release-v1.yml" "$scholarly_workflow"
  cp "$tmp/research-workflow.yml" "$research_workflow"
  cp "$tmp/research-script.sh" "$research_script"
  cp "$tmp/product-pin-workflow.yml" "$product_pin_workflow"
  rm -rf "$tmp"
}
trap restore EXIT
current_stable="$(
  awk -F': ' '$1 == "stable_version" {print $2; exit}' release.yaml
)"
current_release="$(
  awk -F': ' '$1 == "release_version" {print $2; exit}' release.yaml
)"
current_go="$(
  awk -F': ' '$1 == "minimum_go" {print $2; exit}' release.yaml
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
minimum_go: ${current_go}
report_schema: v0.1
EOF
}

BPFCOMPAT_RELEASE_METADATA=release.yaml "$script" >"$tmp/current.log"
current_channel="$(awk -F': ' '$1 == "release_channel" {print $2; exit}' release.yaml)"
grep -Fq "channel=${current_channel}" "$tmp/current.log"

# The current stable release as a stable channel: docs and canary pins must
# already agree with it (the stable PR changes stable_version, so this follows).
write_metadata "$current_stable" "$current_stable" stable
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

sed -i 's/RESEARCH_TAG: research-v1/RESEARCH_TAG: v9.9.9/' "$scholarly_workflow"
if BPFCOMPAT_RELEASE_METADATA=release.yaml \
  "$script" >"$tmp/bad-scholarly-tag.log" 2>&1; then
  echo "[release-consistency-test] accepted scholarly workflow with product-style tag" >&2
  exit 1
fi
cp "$tmp/scholarly-release-v1.yml" "$scholarly_workflow"

# Each broken state gate must be rejected for the gate, not by accident.
while IFS='|' read -r gate_mutation gate_reason; do
  sed -i "$gate_mutation" "$scholarly_workflow"
  if BPFCOMPAT_RELEASE_METADATA=release.yaml \
    "$script" >"$tmp/bad-scholarly-gate.log" 2>&1; then
    echo "[release-consistency-test] accepted scholarly workflow with a broken state gate: ${gate_mutation}" >&2
    exit 1
  fi
  if ! grep -Fq -- "$gate_reason" "$tmp/bad-scholarly-gate.log"; then
    echo "[release-consistency-test] broken state gate rejected for the wrong reason: ${gate_mutation}" >&2
    cat "$tmp/bad-scholarly-gate.log" >&2
    exit 1
  fi
  cp "$tmp/scholarly-release-v1.yml" "$scholarly_workflow"
done <<'MUTATIONS'
/if: needs.state.outputs.publish == 'true'/d|missing required control: if: needs.state.outputs.publish == 'true'
/^    needs: state$/d|missing required control: needs: state
s/^      attestations: read$/      contents: write/|must be gated by the read-only state job
s/^  state:$/  status:/|must be gated by the read-only state job
/RESEARCH_COMMIT: 141c491/d|missing required control: RESEARCH_COMMIT
MUTATIONS

sed -i '/--latest=false/d' "$scholarly_workflow"
if BPFCOMPAT_RELEASE_METADATA=release.yaml \
  "$script" >"$tmp/bad-scholarly-latest.log" 2>&1; then
  echo "[release-consistency-test] accepted scholarly workflow without --latest=false" >&2
  exit 1
fi
cp "$tmp/scholarly-release-v1.yml" "$scholarly_workflow"

# Go toolchain pins. Product workflows follow release.yaml minimum_go; the
# frozen research-v1 workflows follow the research contract's EXPECTED_GO
# (scripts/research/materialize-v1.sh) and must never drift with product bumps.
research_go="$(sed -n 's/^EXPECTED_GO="go\(.*\)"$/\1/p' "$research_script")"

sed -i "s/GO_VERSION: \"${research_go}\"/GO_VERSION: \"${current_go}\"/" "$research_workflow"
if [[ "$research_go" != "$current_go" ]] && BPFCOMPAT_RELEASE_METADATA=release.yaml \
  "$script" >"$tmp/bad-research-go.log" 2>&1; then
  echo "[release-consistency-test] accepted a research-v1 workflow that drifted from EXPECTED_GO" >&2
  exit 1
fi
cp "$tmp/research-workflow.yml" "$research_workflow"

sed -i 's/^EXPECTED_GO=.*$/# EXPECTED_GO removed/' "$research_script"
if BPFCOMPAT_RELEASE_METADATA=release.yaml \
  "$script" >"$tmp/bad-research-contract.log" 2>&1; then
  echo "[release-consistency-test] accepted research-v1 workflows without an EXPECTED_GO contract" >&2
  exit 1
fi
cp "$tmp/research-script.sh" "$research_script"

sed -i "s/go-version: \"${current_go}\"/go-version: \"1.0.0\"/" "$product_pin_workflow"
if BPFCOMPAT_RELEASE_METADATA=release.yaml \
  "$script" >"$tmp/bad-product-pin.log" 2>&1; then
  echo "[release-consistency-test] accepted a product workflow with a stale literal go-version pin" >&2
  exit 1
fi
cp "$tmp/product-pin-workflow.yml" "$product_pin_workflow"

echo "[release-consistency-test] PASS"
