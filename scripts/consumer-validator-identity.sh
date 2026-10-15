#!/usr/bin/env bash
# Bind the external-consumer canary to ONE explicit, verified validator.
#
# external-consumer-canary.yml is dispatched by release-candidate-canary at the
# exact RC tag, and its result is recorded as that candidate's
# "external_consumers: pass". Before this script the KubeArmor lane downloaded
# a hard-coded older release validator (V=v0.3.7) inside each guest, so the
# RC evidence never exercised the RC's validator. This script removes every
# implicit version choice:
#
#   resolve        pick the validator identity from the checkout itself:
#                  - HEAD carries exactly one v* tag -> release mode: download
#                    that tag's static validator, require exactly one
#                    SHA256SUMS entry, verify the checksum and the GitHub build
#                    attestation (signer = release-artifacts.yml at that exact
#                    tag, source digest = the checked-out commit);
#                  - no v* tag at HEAD (scheduled run on main) -> source mode:
#                    build the static validator from this checkout.
#                  An explicitly requested tag must equal a tag at HEAD.
#                  Every failure is fatal: there is no fallback to another
#                  version and no fallback from release mode to a source build.
#   verify-report  check a bpfcompat JSON report against the resolved identity:
#                  artifact mode -> .validator.sha256, at least one target,
#                  and every target status == pass with validator
#                  load_status == pass; command mode ->
#                  .command.binary.sha256 plus, for every target, the
#                  guest-observed "bpfcompat-validator-sha256=<sha>" line.
#
# Test seams (never set in CI): BPFCOMPAT_RELEASE_BASE_URL overrides the
# release download base (file:// in tests); BPFCOMPAT_SOURCE_BUILD_CMD
# overrides the source build command.
set -euo pipefail

VALIDATOR_ASSET="bpfcompat-validator-static-linux-amd64"
SIGNER_WORKFLOW_PATH=".github/workflows/release-artifacts.yml"
MARKER="bpfcompat-validator-sha256="

die() {
  echo "[consumer-validator] ERROR: $*" >&2
  exit 1
}
log() { echo "[consumer-validator] $*" >&2; }

usage() {
  cat >&2 <<'USAGE'
usage:
  consumer-validator-identity.sh resolve --out-dir DIR [--tag vX.Y.Z[-rc.N]]
      [--repo owner/repo] [--root CHECKOUT]
  consumer-validator-identity.sh verify-report --identity FILE --report FILE
      --mode artifact|command
USAGE
  exit 2
}

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

resolve() {
  local out_dir="" tag="" repo="${GITHUB_REPOSITORY:-Kernel-Guard/bpfcompat}" root=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out-dir) out_dir="${2:-}"; shift 2 ;;
      --tag) tag="${2:-}"; shift 2 ;;
      --repo) repo="${2:-}"; shift 2 ;;
      --root) root="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -n "$out_dir" ]] || usage
  root="${root:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  [[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid repo: ${repo}"
  if [[ -n "$tag" && ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
    die "invalid requested tag: ${tag}"
  fi
  command -v jq >/dev/null 2>&1 || die "jq is required"

  local commit
  commit="$(git -C "$root" rev-parse --verify 'HEAD^{commit}')" ||
    die "cannot resolve the checkout commit in ${root}"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "unexpected commit id: ${commit}"

  local -a head_tags=()
  local t
  while IFS= read -r t; do
    [[ "$t" =~ ^v[0-9] ]] && head_tags+=("$t")
  done < <(git -C "$root" tag --points-at HEAD)

  local mode selected=""
  if [[ -n "$tag" ]]; then
    for t in "${head_tags[@]}"; do
      [[ "$t" == "$tag" ]] && selected="$t"
    done
    [[ -n "$selected" ]] ||
      die "requested tag ${tag} does not point at the checked-out commit ${commit} (tags at HEAD: ${head_tags[*]:-none}); refusing to mix versions"
    mode=release
  elif [[ "${#head_tags[@]}" -eq 1 ]]; then
    selected="${head_tags[0]}"
    mode=release
  elif [[ "${#head_tags[@]}" -gt 1 ]]; then
    die "checkout HEAD carries several release tags (${head_tags[*]}); pass --tag explicitly"
  else
    mode=source
  fi

  mkdir -p "$out_dir"
  local dest="${out_dir}/bpfcompat-validator"
  rm -f "$dest" "${out_dir}/validator-identity.json"
  local sums_sha="" provenance=""

  if [[ "$mode" == release ]]; then
    local base="${BPFCOMPAT_RELEASE_BASE_URL:-https://github.com/${repo}/releases/download}/${selected}"
    local dl asset expected actual
    dl="$(mktemp -d "${out_dir}/.download.XXXXXX")"
    for asset in "$VALIDATOR_ASSET" SHA256SUMS; do
      curl -fsSL --retry 2 --connect-timeout 10 --max-time 300 \
        -o "${dl}/${asset}" "${base}/${asset}" ||
        die "cannot download ${asset} for ${selected} (no fallback)"
    done
    expected="$(
      awk -v file="$VALIDATOR_ASSET" '
        $2 == file || $2 == ("*" file) {
          if ($1 ~ /^[0-9a-f]+$/ && length($1) == 64) { n++; s = $1 } else { bad = 1 }
        }
        END { if (n == 1 && !bad) print s; else exit 1 }
      ' "${dl}/SHA256SUMS"
    )" || die "${VALIDATOR_ASSET} must have exactly one valid SHA256SUMS entry in ${selected}"
    actual="$(sha256_of "${dl}/${VALIDATOR_ASSET}")"
    [[ "$actual" == "$expected" ]] ||
      die "${VALIDATOR_ASSET} checksum mismatch for ${selected}: got ${actual} want ${expected}"

    if ! command -v gh >/dev/null 2>&1 || ! gh attestation --help >/dev/null 2>&1; then
      die "GitHub CLI attestation verification is required in release mode (no unverified fallback)"
    fi
    local identity="https://github.com/${repo}/${SIGNER_WORKFLOW_PATH}@refs/tags/${selected}"
    local attest_json
    attest_json="$(
      gh attestation verify "${dl}/${VALIDATOR_ASSET}" \
        --repo "$repo" \
        --cert-identity "$identity" \
        --format json
    )" || die "build attestation verification failed for ${VALIDATOR_ASSET}@${selected}"
    jq -e --arg commit "$commit" --arg ref "refs/tags/${selected}" '
      type == "array" and length > 0 and
      all(.[]; .verificationResult.signature.certificate.sourceRepositoryDigest == $commit
               and .verificationResult.signature.certificate.sourceRepositoryRef == $ref)
    ' <<<"$attest_json" >/dev/null ||
      die "attestation for ${VALIDATOR_ASSET}@${selected} does not bind it to ${commit} at refs/tags/${selected}"

    install -m 0755 "${dl}/${VALIDATOR_ASSET}" "$dest"
    sums_sha="$(sha256_of "${dl}/SHA256SUMS")"
    provenance="sha256sums+github-attestation:${identity}"
    rm -rf "$dl"
  else
    log "no release tag at ${commit}; building the static validator from this checkout"
    if [[ -n "${BPFCOMPAT_SOURCE_BUILD_CMD:-}" ]]; then
      (cd "$root" && bash -c "$BPFCOMPAT_SOURCE_BUILD_CMD") >&2 || die "source build failed"
    else
      make -C "$root" validator-static >&2 || die "source build failed"
    fi
    local built="${root}/validator/c-libbpf/bin/bpfcompat-validator"
    [[ -f "$built" ]] || die "source build produced no validator at ${built}"
    install -m 0755 "$built" "$dest"
    provenance="source-build:${commit}"
  fi

  local sha size
  sha="$(sha256_of "$dest")"
  size="$(stat -c %s "$dest")"
  jq -n \
    --arg mode "$mode" \
    --arg tag "$selected" \
    --arg commit "$commit" \
    --arg asset "$VALIDATOR_ASSET" \
    --arg path "$dest" \
    --arg sha "$sha" \
    --argjson size "$size" \
    --arg sums "$sums_sha" \
    --arg provenance "$provenance" \
    '{
      schema: "bpfcompat.consumer-validator-identity.v1",
      mode: $mode,
      tag: (if $tag == "" then null else $tag end),
      commit: $commit,
      asset: (if $mode == "release" then $asset else null end),
      path: $path,
      sha256: $sha,
      size_bytes: $size,
      sha256sums_sha256: (if $sums == "" then null else $sums end),
      provenance: $provenance
    }' >"${out_dir}/validator-identity.json"

  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
      echo "path=${dest}"
      echo "sha256=${sha}"
      echo "mode=${mode}"
      echo "tag=${selected}"
      echo "identity=${out_dir}/validator-identity.json"
    } >>"$GITHUB_OUTPUT"
  fi
  log "validator identity: mode=${mode} tag=${selected:-none} commit=${commit} sha256=${sha}"
}

verify_report() {
  local identity="" report="" mode=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --identity) identity="${2:-}"; shift 2 ;;
      --report) report="${2:-}"; shift 2 ;;
      --mode) mode="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -f "$identity" && -f "$report" ]] || die "identity and report files are required"
  [[ "$mode" == artifact || "$mode" == command ]] || die "--mode must be artifact or command"
  command -v jq >/dev/null 2>&1 || die "jq is required"
  local want got
  want="$(jq -er '.sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' "$identity")" ||
    die "identity file has no valid sha256"

  if [[ "$mode" == artifact ]]; then
    got="$(jq -r '.validator.sha256 // empty' "$report")"
    [[ "$got" == "$want" ]] ||
      die "report validator sha256 ${got:-<missing>} != resolved validator ${want}"
    # A matching validator sha256 proves nothing if the validator never ran
    # or did not load the artifact: require at least one target, and every
    # target (consumer-external profiles are all required and all expected
    # to pass) must have passed with the validator's own load stage = pass.
    jq -e '
      (.targets | type == "array" and length > 0) and
      all(.targets[]; .status == "pass" and .validation.load_status == "pass")
    ' "$report" >/dev/null ||
      die "report has no targets or a target whose status/validator load is not pass"
  else
    got="$(jq -r '.command.binary.sha256 // empty' "$report")"
    [[ "$got" == "$want" ]] ||
      die "report command binary sha256 ${got:-<missing>} != resolved validator ${want}"
    jq -e --arg want "${MARKER}${want}" --arg marker "$MARKER" '
      (.targets | type == "array" and length > 0) and
      all(.targets[];
        ([.functional.tests[]? | select(.name == "command") | (.stdout_tail // "")]
          | join("\n") | split("\n") | map(select(startswith($marker)))) as $m
        | ($m | length) > 0 and all($m[]; . == $want))
    ' "$report" >/dev/null ||
      die "a target did not report the guest-observed validator sha256 ${want}"
  fi
  log "report ${report} is bound to validator ${want}"
}

cmd="${1:-}"
[[ -n "$cmd" ]] || usage
shift
case "$cmd" in
  resolve) resolve "$@" ;;
  verify-report) verify_report "$@" ;;
  *) usage ;;
esac
