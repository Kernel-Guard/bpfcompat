#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

metadata="${BPFCOMPAT_RELEASE_METADATA:-release.yaml}"

field() {
  awk -F': ' -v key="$1" '$1 == key {gsub(/"/, "", $2); print $2; exit}' "$metadata"
}

fail() {
  echo "[release-consistency] $*" >&2
  exit 1
}

[[ -f "$metadata" ]] || fail "missing $metadata"
[[ -f scripts/check-release-state.sh && -f scripts/check-release-state_test.sh ]] ||
  fail "release-state fail-closed checks are missing"
[[ -f scripts/check-production-environment.sh &&
   -f scripts/check-production-environment_test.sh ]] ||
  fail "production environment fail-closed checks are missing"
[[ -f scripts/check-canary-pins.sh && -f scripts/check-canary-pins_test.sh ]] ||
  fail "consumer-canary pin fail-closed checks are missing"

stable_version="$(field stable_version)"
release_version="$(field release_version)"
release_channel="$(field release_channel)"
release_operator="$(field release_operator)"
approval_mode="$(field approval_mode)"
minimum_go="$(field minimum_go)"
report_schema="$(field report_schema)"

[[ -n "$stable_version" && -n "$release_version" && -n "$release_channel" &&
   -n "$release_operator" && -n "$approval_mode" &&
   -n "$minimum_go" && -n "$report_schema" ]] ||
  fail "release metadata fields must not be empty"
[[ "$release_operator" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]] ||
  fail "release_operator must be a valid GitHub login"
[[ "$approval_mode" == "solo-maintainer" ]] ||
  fail "approval_mode must be solo-maintainer"

stable_pattern='^[0-9]+\.[0-9]+\.[0-9]+$'
prerelease_pattern='^[0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*$'
[[ "$stable_version" =~ $stable_pattern ]] ||
  fail "stable_version must be an X.Y.Z version"
case "$release_channel" in
  stable)
    [[ "$release_version" =~ $stable_pattern ]] ||
      fail "stable release_version must be an X.Y.Z version"
    [[ "$release_version" == "$stable_version" ]] ||
      fail "stable release_version must equal stable_version"
    ;;
  prerelease)
    [[ "$release_version" =~ $prerelease_pattern ]] ||
      fail "prerelease release_version must be X.Y.Z-rc.N with N >= 1"
    [[ "$release_version" != "$stable_version" ]] ||
      fail "prerelease release_version must not equal stable_version"
    ;;
  *)
    fail "release_channel must be stable or prerelease"
    ;;
esac

stable_action_tag="v${stable_version}"
stable_container_tag="${stable_version}"
release_tag="v${release_version}"

grep -Fq "## [${release_version}]" CHANGELOG.md ||
  fail "CHANGELOG.md has no ${release_version} release heading"
grep -Fq "VER=${stable_action_tag}" README.md ||
  fail "README.md installer example does not use ${stable_action_tag}"
grep -Fq "ghcr.io/kernel-guard/bpfcompat:${stable_container_tag}" README.md ||
  fail "README.md container example does not use ${stable_container_tag}"
grep -Fq "go ${minimum_go}" go.mod ||
  fail "go.mod does not require Go ${minimum_go}"
grep -Fq "ARG GO_VERSION=${minimum_go}" Dockerfile ||
  fail "Dockerfile does not use Go ${minimum_go}"
grep -Fq "GO_VERSION=\"\${GO_VERSION:-${minimum_go}}\"" scripts/hetzner-bootstrap-vm.sh ||
  fail "Hetzner bootstrap does not default to Go ${minimum_go}"
grep -Fq "\`schema_version\`: **\`${report_schema}\`**" docs/evidence-schema.md ||
  fail "evidence schema documentation does not match ${report_schema}"

release_workflow=".github/workflows/release-artifacts.yml"
for required_control in \
  "Refuse mutation of an already-published release" \
  "Verify candidate attestations" \
  "Candidate VM positive + classified negative" \
  "Candidate ARM64 CLI native smoke" \
  "Stage production readiness evidence" \
  "Stage draft release"; do
  grep -Fq "$required_control" "$release_workflow" ||
    fail "${release_workflow} is missing required control: ${required_control}"
done

promotion_workflow=".github/workflows/promote-release.yml"
[[ -f "$promotion_workflow" ]] ||
  fail "manual promotion workflow is missing"
for required_control in \
  "workflow_dispatch:" \
  "candidate_run_id:" \
  "expected_commit:" \
  "expected_image_digest:" \
  "Manual promotion confirmation" \
  "production-release" \
  "scripts/promote-release.sh" \
  "Promote image and publish release"; do
  grep -Fq "$required_control" "$promotion_workflow" ||
    fail "${promotion_workflow} is missing required control: ${required_control}"
done
if grep -Eq '^[[:space:]]+push:' "$promotion_workflow"; then
  fail "${promotion_workflow} must never have an automatic push trigger"
fi

scholarly_workflow=".github/workflows/scholarly-release-v1.yml"
[[ -f "$scholarly_workflow" ]] ||
  fail "scholarly research release workflow is missing"
for required_control in \
  'branches: [main]' \
  '- ".github/workflows/scholarly-release-v1.yml"' \
  'RESEARCH_TAG: research-v1' \
  'Refuse an existing research v1 tag or release' \
  'Rebuild and verify release-shaped archive' \
  'Create annotated research tag' \
  'Publish GitHub research release' \
  '--verify-tag' \
  '--latest=false'; do
  grep -Fq -- "$required_control" "$scholarly_workflow" ||
    fail "$scholarly_workflow is missing required control: $required_control"
done
if grep -Eq 'workflow_dispatch:|refs/tags/v|tags:[[:space:]]*\[.*v\*|scripts/promote-release\.sh|softprops/action-gh-release@|value=latest' "$scholarly_workflow"; then
  fail "$scholarly_workflow must remain isolated from product release/promotion paths"
fi
if [[ "$(grep -Ec '^[[:space:]]+gh release create ' "$scholarly_workflow")" -ne 1 ]]; then
  fail "$scholarly_workflow must contain exactly one gh release create call"
fi

unexpected_release_writers="$(
  grep -ERl --include='*.yml' --include='*.yaml' \
    'gh release (create|upload|edit)|softprops/action-gh-release@' .github/workflows |
    grep -vFx "$release_workflow" |
    grep -vFx "$promotion_workflow" |
    grep -vFx "$scholarly_workflow" || true
)"
if [[ -n "$unexpected_release_writers" ]]; then
  printf '%s\n' "$unexpected_release_writers" >&2
  fail "an unexpected workflow can publish or mutate releases"
fi

unexpected_latest_writers="$(
  grep -ERl --include='*.yml' --include='*.yaml' \
    -- '--tag .*IMAGE.*:latest|value=latest' .github/workflows |
    grep -vFx "$promotion_workflow" || true
)"
if [[ -n "$unexpected_latest_writers" ]]; then
  printf '%s\n' "$unexpected_latest_writers" >&2
  fail "a workflow other than promote-release can publish the production latest image"
fi

promotion_callers="$(
  grep -ERl --include='*.yml' --include='*.yaml' \
    'scripts/promote-release.sh' .github/workflows || true
)"
[[ "$promotion_callers" == "$promotion_workflow" ]] ||
  fail "only ${promotion_workflow} may invoke scripts/promote-release.sh"

bad_action_refs="$(
  grep -ERn --include='*.md' --include='*.yml' --include='*.yaml' \
    'uses: Kernel-Guard/bpfcompat@v[0-9]+\.[0-9]+\.[0-9]+' README.md docs |
    grep -vF "@${stable_action_tag}" || true
)"
if [[ -n "$bad_action_refs" ]]; then
  printf '%s\n' "$bad_action_refs" >&2
  fail "documentation contains stale action tags"
fi

# Go toolchain pins have two owners.
#
# Product workflows build what we ship, so they follow release.yaml
# minimum_go -- both a top-level GO_VERSION env and any literal
# `go-version: "X"` pin. A stale literal pin is how a security toolchain bump
# silently misses a lane.
#
# The research-v1 workflows reproduce a frozen, DOI-archived dataset whose
# contract pins the exact toolchain it was produced with
# (scripts/research/materialize-v1.sh EXPECTED_GO). They must follow that
# contract and must NOT move with product bumps; changing them would break the
# archived reproducibility claim. They are dispatch-only and read-only
# (contents: read) and ship nothing.
research_contract="scripts/research/materialize-v1.sh"
research_go="$(sed -n 's/^EXPECTED_GO="go\(.*\)"$/\1/p' "$research_contract" 2>/dev/null || true)"
is_research_workflow() {
  [[ "$(basename "$1")" =~ ^research-.*-v1\.ya?ml$ ]]
}
while IFS= read -r workflow; do
  if is_research_workflow "$workflow"; then
    [[ -n "$research_go" ]] ||
      fail "$research_contract has no EXPECTED_GO contract for $workflow"
    grep -Fq "GO_VERSION: \"${research_go}\"" "$workflow" ||
      fail "$workflow does not use the research-v1 contract Go ${research_go:-<missing>}"
  else
    grep -Fq "GO_VERSION: \"${minimum_go}\"" "$workflow" ||
      fail "$workflow does not use Go ${minimum_go}"
  fi
done < <(
  grep -ERl --include='*.yml' --include='*.yaml' \
    '^  GO_VERSION: ' .github/workflows
)
while IFS= read -r pin; do
  workflow="${pin%%:*}"
  is_research_workflow "$workflow" && continue
  [[ "$pin" == *"go-version: \"${minimum_go}\""* ]] ||
    fail "${pin} does not pin Go ${minimum_go}"
done < <(
  grep -ERn --include='*.yml' --include='*.yaml' \
    'go-version: "[^"]+"' .github/workflows || true
)

# The consumer canary is the only lane that consumes a published release the
# way a downstream project does. Metadata is authoritative: a stable_version
# bump that leaves the canary pinned to the previous release means the
# documented consumer path is no longer tested, so that is a failure here and
# not a follow-up chore.
BPFCOMPAT_RELEASE_METADATA="$metadata" bash scripts/check-canary-pins.sh ||
  fail "consumer-canary action pins do not match ${metadata}"

if [[ "${GITHUB_REF_TYPE:-}" == "tag" ]]; then
  [[ "${GITHUB_REF_NAME:-}" == "$release_tag" ]] ||
    fail "release tag ${GITHUB_REF_NAME:-<empty>} does not match metadata ${release_tag}"
fi

echo "[release-consistency] PASS stable=${stable_version} release=${release_version} channel=${release_channel} operator=${release_operator} mode=${approval_mode} go=${minimum_go} schema=${report_schema}"
