#!/usr/bin/env bash
# Rollback drill on a dedicated GHCR alias (backport of main's
# rollback-drill.yml logic, made testable offline).
#
#   rollback-drill.sh validate        exact inputs, ref, operator, identities
#   rollback-drill.sh verify          signature + SLSA provenance + version of both digests
#   rollback-drill.sh drill           alias -> known-good -> candidate -> known-good, evidence
#   rollback-drill.sh restore         idempotently return the alias to the known-good digest
#   rollback-drill.sh verify-evidence check the recorded evidence
#
# Only ${IMAGE}:rollback-drill-vX.Y.Z-rc.N is ever written. `latest`, stable
# aliases, Git refs, tags and releases are never written; `latest` is read to
# prove it is on the known-good digest before and after.
#
# Exit codes: 0 ok, 1 verification/drill failure (alias restored),
# 2 invalid input, 3 RESTORATION FAILED (manual recovery required:
# docs/runbooks/rollback-drill-recovery.md).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRODUCT_IMAGE=ghcr.io/kernel-guard/bpfcompat
RUNBOOK=docs/runbooks/rollback-drill-recovery.md
ISSUER=https://token.actions.githubusercontent.com

invalid() { echo "::error::rollback drill input rejected: $*" >&2; exit 2; }
failed() { echo "::error::rollback drill failed: $*" >&2; exit 1; }
stranded() {
  echo "::error::RESTORATION FAILED: ${IMAGE}:${DRILL_ALIAS} may not point at ${BEFORE_DIGEST}: $*" >&2
  echo "::error::Manual recovery required; follow ${RUNBOOK}" >&2
  exit 3
}

alias_ref() { echo "${IMAGE}:${DRILL_ALIAS}"; }
resolve() { docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' | jq -r .digest; }
embedded_version() { docker run --rm "${IMAGE}@$1" version --json | jq -r .version; }

validate() {
  local repo="${GITHUB_REPOSITORY:-}" release_operator
  [[ -n "${DRILL_ALLOWED_REF:-}" && "${GITHUB_REF:-}" == "$DRILL_ALLOWED_REF" ]] ||
    invalid "ref ${GITHUB_REF:-<unset>} is not the allowed drill ref"
  release_operator="$(awk -F': ' '$1 == "release_operator" {print $2; exit}' "$ROOT_DIR/release.yaml")"
  [[ -n "$release_operator" && "${GITHUB_ACTOR:-}" == "$release_operator" ]] ||
    invalid "actor ${GITHUB_ACTOR:-<unset>} is not the release operator"
  [[ "$repo" == Kernel-Guard/bpfcompat && "${IMAGE:-}" == "$PRODUCT_IMAGE" ]] ||
    invalid "image ${IMAGE:-<unset>} is not the product image of ${repo}"
  [[ "${DRILL_ALIAS:-}" =~ ^rollback-drill-v[0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*$ ]] ||
    invalid "alias must be rollback-drill-vX.Y.Z-rc.N"
  [[ "${BEFORE_DIGEST:-}" =~ ^sha256:[0-9a-f]{64}$ && "${CANDIDATE_DIGEST:-}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    invalid "digests must be immutable sha256:<64 lowercase hex>"
  [[ "$BEFORE_DIGEST" != "$CANDIDATE_DIGEST" ]] || invalid "known-good and candidate digests are identical"
  [[ "${BEFORE_VERSION:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?$ &&
     "${CANDIDATE_VERSION:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?$ ]] ||
    invalid "versions must be vX.Y.Z or vX.Y.Z-rc.N"
  # Images are signed only by release-artifacts.yml at their own tag.
  local prefix="https://github.com/${repo}/.github/workflows/release-artifacts.yml@refs/tags/"
  [[ "${BEFORE_IDENTITY:-}" == "${prefix}${BEFORE_VERSION}" ]] ||
    invalid "known-good identity must be ${prefix}${BEFORE_VERSION}"
  [[ "${CANDIDATE_IDENTITY:-}" == "${prefix}${CANDIDATE_VERSION}" ]] ||
    invalid "candidate identity must be ${prefix}${CANDIDATE_VERSION}"
  [[ "${CONFIRMATION:-}" == "rollback drill ${DRILL_ALIAS}" ]] ||
    invalid "confirmation must be exactly: rollback drill ${DRILL_ALIAS}"
  echo "[rollback-drill] inputs valid for $(alias_ref)"
}

verify() {
  local digest version identity
  for endpoint in before candidate; do
    if [[ "$endpoint" == before ]]; then
      digest="$BEFORE_DIGEST" version="$BEFORE_VERSION" identity="$BEFORE_IDENTITY"
    else
      digest="$CANDIDATE_DIGEST" version="$CANDIDATE_VERSION" identity="$CANDIDATE_IDENTITY"
    fi
    cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" \
      "${IMAGE}@${digest}" >/dev/null || failed "${endpoint} signature does not verify for ${identity}"
    cosign verify-attestation --type https://slsa.dev/provenance/v1 --certificate-identity "$identity" \
      --certificate-oidc-issuer "$ISSUER" "${IMAGE}@${digest}" >/dev/null ||
      failed "${endpoint} SLSA provenance does not verify for ${identity}"
    [[ "$(embedded_version "$digest")" == "$version" ]] || failed "${endpoint} image does not embed ${version}"
  done
  echo "[rollback-drill] both endpoints signed, attested and versioned"
}

# Point the alias at the known-good digest and prove it, or exit 3.
restore_alias() {
  local attempt current
  for attempt in 1 2 3; do
    current="$(resolve "$(alias_ref)" 2>/dev/null || true)"
    [[ "$current" == "$BEFORE_DIGEST" ]] && return 0
    docker buildx imagetools create --tag "$(alias_ref)" "${IMAGE}@${BEFORE_DIGEST}" >/dev/null 2>&1 || true
    [[ "$(resolve "$(alias_ref)" 2>/dev/null || true)" == "$BEFORE_DIGEST" ]] && return 0
    echo "[rollback-drill] restore attempt ${attempt} did not take" >&2
  done
  stranded "three restore attempts failed"
}

restore() {
  local current
  current="$(resolve "$(alias_ref)" 2>/dev/null || true)"
  if [[ -z "$current" || "$current" == null ]]; then
    echo "[rollback-drill] $(alias_ref) does not exist; nothing to restore"
    return 0
  fi
  restore_alias
  echo "[rollback-drill] $(alias_ref) is on the known-good digest ${BEFORE_DIGEST}"
}

drill() {
  local latest_before latest_after promoted_digest final_digest
  local promote_started promote_completed rollback_started rollback_completed
  latest_before="$(resolve "${IMAGE}:latest")" || failed "cannot resolve ${IMAGE}:latest"
  [[ "$latest_before" == "$BEFORE_DIGEST" ]] ||
    failed "${IMAGE}:latest is ${latest_before}, not the known-good ${BEFORE_DIGEST}; refusing to start"

  docker buildx imagetools create --tag "$(alias_ref)" "${IMAGE}@${BEFORE_DIGEST}" >/dev/null ||
    failed "cannot set up $(alias_ref)"
  [[ "$(resolve "$(alias_ref)")" == "$BEFORE_DIGEST" ]] || { restore_alias; failed "setup digest mismatch"; }

  promote_started="$(date +%s%3N)"
  if ! docker buildx imagetools create --tag "$(alias_ref)" "${IMAGE}@${CANDIDATE_DIGEST}" >/dev/null; then
    restore_alias
    failed "promotion write failed; alias restored"
  fi
  promote_completed="$(date +%s%3N)"
  promoted_digest="$(resolve "$(alias_ref)" || true)"
  if [[ "$promoted_digest" != "$CANDIDATE_DIGEST" ]]; then
    restore_alias
    failed "alias resolved to ${promoted_digest} after promotion, not ${CANDIDATE_DIGEST}; alias restored"
  fi
  if [[ "$(embedded_version "$promoted_digest" || true)" != "$CANDIDATE_VERSION" ]]; then
    restore_alias
    failed "promoted image does not embed ${CANDIDATE_VERSION}; alias restored"
  fi

  rollback_started="$(date +%s%3N)"
  docker buildx imagetools create --tag "$(alias_ref)" "${IMAGE}@${BEFORE_DIGEST}" >/dev/null 2>&1 || true
  restore_alias
  rollback_completed="$(date +%s%3N)"
  final_digest="$(resolve "$(alias_ref)")"
  [[ "$(embedded_version "$final_digest")" == "$BEFORE_VERSION" ]] ||
    stranded "restored image does not embed ${BEFORE_VERSION}"
  latest_after="$(resolve "${IMAGE}:latest")"
  [[ "$latest_after" == "$latest_before" ]] || failed "${IMAGE}:latest moved during the drill"

  local completed_at promotion_ms recovery_ms
  completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  promotion_ms=$((promote_completed - promote_started))
  recovery_ms=$((rollback_completed - rollback_started))
  mkdir -p "$EVIDENCE_DIR"
  jq -n \
    --arg operator "$GITHUB_ACTOR" --argjson run_id "$GITHUB_RUN_ID" --arg ref "$GITHUB_REF" \
    --arg completed_at "$completed_at" --arg alias "$(alias_ref)" \
    --arg before "$BEFORE_DIGEST" --arg candidate "$CANDIDATE_DIGEST" \
    --arg before_version "$BEFORE_VERSION" --arg candidate_version "$CANDIDATE_VERSION" \
    --arg final "$final_digest" --arg latest "$latest_after" \
    --argjson promotion_ms "$promotion_ms" --argjson recovery_ms "$recovery_ms" \
    '{schema_version: "v0.1", marker: "[bpfcompat-rollback-drill:v1]", operator: $operator,
      workflow_run_id: $run_id, ref: $ref, completed_at: $completed_at, alias: $alias,
      before_digest: $before, candidate_digest: $candidate,
      before_version: $before_version, candidate_version: $candidate_version,
      final_digest: $final, latest_digest: $latest,
      promotion_elapsed_ms: $promotion_ms, recovery_elapsed_ms: $recovery_ms,
      signature_verified: true, provenance_verified: true, version_verified: true}' \
    >"$EVIDENCE_DIR/evidence.json"
  {
    echo "# bpfcompat Release-Promotion Rollback Drill"
    echo
    echo "[bpfcompat-rollback-drill:v1]"
    echo
    echo "- Operator: \`$GITHUB_ACTOR\`"
    echo "- Workflow run: \`$GITHUB_RUN_ID\` on \`$GITHUB_REF\`"
    echo "- Completed: \`$completed_at\`"
    echo "- Drill alias: \`$(alias_ref)\`"
    echo "- Known-good digest: \`$BEFORE_DIGEST\` (\`$BEFORE_VERSION\`)"
    echo "- Candidate digest: \`$CANDIDATE_DIGEST\` (\`$CANDIDATE_VERSION\`)"
    echo "- Final digest: \`$final_digest\`"
    echo "- Promotion elapsed: \`${promotion_ms} ms\`"
    echo "- Recovery elapsed: \`${recovery_ms} ms\`"
    echo "- Signature, SLSA v1 provenance and embedded version verification: PASS"
    echo "- Protected \`latest\` alias unchanged: \`$latest_after\`"
  } >"$EVIDENCE_DIR/evidence.md"
  echo "[rollback-drill] drill complete; $(alias_ref) restored to ${final_digest}"
}

verify_evidence() {
  local evidence="${EVIDENCE_DIR:-}/evidence.json"
  [[ -s "$evidence" && -s "${EVIDENCE_DIR}/evidence.md" ]] || invalid "evidence is missing"
  jq -e --arg alias "$(alias_ref)" --arg before "$BEFORE_DIGEST" --arg candidate "$CANDIDATE_DIGEST" \
    --argjson run_id "${GITHUB_RUN_ID:-0}" '
    .schema_version == "v0.1" and .marker == "[bpfcompat-rollback-drill:v1]" and
    .alias == $alias and .workflow_run_id == $run_id and
    .before_digest == $before and .candidate_digest == $candidate and
    .final_digest == $before and .latest_digest == $before and
    (.promotion_elapsed_ms | type == "number" and . >= 0) and
    (.recovery_elapsed_ms | type == "number" and . >= 0) and
    .signature_verified == true and .provenance_verified == true and .version_verified == true
  ' "$evidence" >/dev/null || failed "recorded evidence does not prove restoration to the known-good digest"
  grep -Fq '[bpfcompat-rollback-drill:v1]' "${EVIDENCE_DIR}/evidence.md" || failed "evidence.md lacks its marker"
  echo "[rollback-drill] evidence verified"
}

case "${1:-}" in
  validate) validate ;;
  verify) verify ;;
  drill) drill ;;
  restore) restore ;;
  verify-evidence) verify_evidence ;;
  *) echo "usage: rollback-drill.sh validate|verify|drill|restore|verify-evidence" >&2; exit 2 ;;
esac
