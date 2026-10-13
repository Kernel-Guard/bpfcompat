#!/usr/bin/env bash
# Bind the consumer-canary's published-action pins to release.yaml.
#
# consumer-canary.yml is the only lane that consumes bpfcompat the way a
# downstream project does: it resolves a pinned commit to a release, downloads
# and verifies the published assets, and boots a VM. That protection is only
# real while the pins name the releases we actually ship. Bump
# `stable_version: 0.3.7` to `0.3.8` and leave the canary pinned to the v0.3.7
# commit, and the lane goes on testing a release nobody is told to use while
# the documented one is exercised by nothing.
#
# release.yaml is authoritative. For every pin the canary declares:
#   1. the pin is a full 40-character commit SHA (mutable refs are not pins),
#   2. its `# vX.Y.Z` comment names the version release.yaml says it should,
#   3. that tag really does resolve to that commit.
#
# A pin is claimed with a marker comment on the line above it:
#
#     # bpfcompat-pin: stable
#     uses: Kernel-Guard/bpfcompat@179ff61...415 # v0.3.7
#
# `stable` is required unconditionally -- a missing stable pin means the
# documented consumer path has no canary at all, which is the gap this guard
# exists to close, so it is a failure and not a skip.
#
# Preparing the next release candidate is the one state the strict rule
# cannot be met in: the commit that sets release_version to a new RC (and the
# tag build of that very commit) cannot pin the canary to a tag that does not
# exist yet, or to itself. While v<release_version> positively does not exist
# (the remote answered "no such tag"), or resolves to the commit under check,
# the candidate pin may still name an EARLIER rc of the SAME release
# (vX.Y.Z-rc.M, M < N) that is a published, non-draft GitHub prerelease and
# whose tag resolves to the pinned full SHA. Any lookup or API failure fails
# closed. Every later commit is strict again, so the canary must be repinned
# to the new RC before anything else lands. The stable pin rule is unchanged.
#
# `candidate` is enforced only while release_channel is `prerelease`. In the
# stable channel there is no active prerelease to graduate, release_version
# equals stable_version, and whatever prerelease the candidate lane still
# points at is last cycle's -- harmless, and pinning it to the stable release
# would just duplicate the stable job. The next `release_channel: prerelease`
# re-arms the check.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

metadata="${BPFCOMPAT_RELEASE_METADATA:-release.yaml}"
workflow="${BPFCOMPAT_CANARY_WORKFLOW:-.github/workflows/consumer-canary.yml}"

fail=0

note_fail() {
  echo "[canary-pins] $*" >&2
  fail=1
}

die() {
  echo "[canary-pins] $*" >&2
  exit 1
}

[[ -f "$metadata" ]] || die "missing release metadata: ${metadata}"
[[ -f "$workflow" ]] || die "missing consumer canary workflow: ${workflow}"

field() {
  awk -F': ' -v key="$1" '$1 == key {gsub(/"/, "", $2); print $2; exit}' "$metadata"
}

stable_version="$(field stable_version)"
release_version="$(field release_version)"
release_channel="$(field release_channel)"
[[ -n "$stable_version" && -n "$release_version" && -n "$release_channel" ]] ||
  die "release metadata must set stable_version, release_version and release_channel"

# Resolve a tag to the commit it points at, distinguishing three outcomes:
#   LOOKUP_STATE=found   LOOKUP_SHA=<40-hex commit>
#   LOOKUP_STATE=absent  the remote answered and positively has no such tag
#   LOOKUP_STATE=error   the remote could not be queried, or answered with
#                        something that is not a well-formed ref listing
# Callers treat `error` as a failure: an unreachable remote is never evidence
# that a tag does not exist. The local clone is consulted first; the remote
# covers the shallow checkouts some gate workflows use. The remote is
# overridable so the regression suite can point it at a fixture (it already
# was before the bootstrap rule existed).
tag_remote="${BPFCOMPAT_TAG_REMOTE:-origin}"
LOOKUP_STATE=error
LOOKUP_SHA=""
tag_lookup() {
  local tag="$1" out rc sha ref peeled="" direct=""
  LOOKUP_STATE=error
  LOOKUP_SHA=""
  [[ "$tag" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || return 0
  sha="$(git rev-parse -q --verify "refs/tags/${tag}^{commit}" 2>/dev/null || true)"
  if [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    LOOKUP_STATE=found
    LOOKUP_SHA="$sha"
    return 0
  fi
  # Ask for both refs. Only an annotated tag advertises a peeled `^{}` ref; a
  # lightweight one advertises just `refs/tags/<tag>`. --exit-code makes "no
  # such ref" (exit 2) distinguishable from a failed query (any other code).
  set +e
  out="$(git ls-remote --exit-code --tags "$tag_remote" \
    "refs/tags/${tag}" "refs/tags/${tag}^{}" 2>/dev/null)"
  rc=$?
  set -e
  if [[ "$rc" -eq 2 ]]; then
    # "No such ref" is only trusted with an empty listing.
    [[ -z "$out" ]] && LOOKUP_STATE=absent
    return 0
  fi
  [[ "$rc" -eq 0 && -n "$out" ]] || return 0
  while IFS=$'\t' read -r sha ref; do
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || return 0
    case "$ref" in
      "refs/tags/${tag}^{}") peeled="$sha" ;;
      "refs/tags/${tag}") direct="$sha" ;;
      *) return 0 ;;
    esac
  done <<<"$out"
  # Prefer the peeled value when both come back; it is the commit.
  LOOKUP_SHA="${peeled:-$direct}"
  [[ -n "$LOOKUP_SHA" ]] && LOOKUP_STATE=found
  return 0
}

declare -A pin_sha=() pin_version=() pin_line=()

while IFS='|' read -r channel sha version line; do
  case "$channel" in
    stable | candidate) ;;
    *)
      note_fail "${workflow}:${line} unknown pin channel '${channel}' (expected stable or candidate)"
      continue
      ;;
  esac
  if [[ -n "${pin_sha[$channel]:-}" ]]; then
    note_fail "${workflow}:${line} declares a second '${channel}' pin (first at line ${pin_line[$channel]}); each channel must have exactly one"
    continue
  fi
  pin_sha["$channel"]="$sha"
  pin_version["$channel"]="$version"
  pin_line["$channel"]="$line"
done < <(
  awk '
    match($0, /bpfcompat-pin:[[:space:]]*[A-Za-z0-9_-]+/) {
      channel = substr($0, RSTART, RLENGTH)
      sub(/bpfcompat-pin:[[:space:]]*/, "", channel)
      next
    }
    channel != "" && /uses:[[:space:]]*Kernel-Guard\/bpfcompat@/ {
      ref = $0
      sub(/.*Kernel-Guard\/bpfcompat@/, "", ref)
      sub(/[^0-9A-Za-z._-].*/, "", ref)
      version = ""
      if (match($0, /#[[:space:]]*v[0-9][0-9A-Za-z._-]*/)) {
        version = substr($0, RSTART, RLENGTH)
        sub(/#[[:space:]]*/, "", version)
      }
      print channel "|" ref "|" version "|" NR
      channel = ""
    }
  ' "$workflow"
)

check_pin() {
  local channel="$1" expected="$2"
  local sha="${pin_sha[$channel]:-}" line="${pin_line[$channel]:-}"

  # Covers a deleted job, a marker with no `uses:` under it, and a misspelled
  # channel name alike: whatever the cause, this channel has no live pin.
  if [[ -z "$sha" ]]; then
    note_fail "${workflow} declares no '# bpfcompat-pin: ${channel}' pin, so the ${channel} consumer path (${expected}) has no canary"
    return
  fi
  if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    note_fail "${workflow}:${line} ${channel} pin '${sha}' is not a full 40-character commit SHA; a mutable ref cannot prove which release was consumed"
    return
  fi
  if [[ "${pin_version[$channel]}" != "$expected" ]]; then
    note_fail "${workflow}:${line} ${channel} pin is commented '${pin_version[$channel]:-<no # vX.Y.Z comment>}' but release.yaml says ${expected}"
    return
  fi

  tag_lookup "$expected"
  case "$LOOKUP_STATE" in
    absent)
      note_fail "${workflow}:${line} ${channel} pin names ${expected}, which is not a tag in this repository"
      return
      ;;
    error)
      note_fail "${workflow}:${line} could not verify tag ${expected} (remote unreachable or malformed answer); failing closed"
      return
      ;;
  esac
  if [[ "$LOOKUP_SHA" != "$sha" ]]; then
    note_fail "${workflow}:${line} ${channel} pin is ${sha} but ${expected} is ${LOOKUP_SHA}; the canary is exercising a stale release"
    return
  fi

  echo "[canary-pins] ${channel} ${expected} ${sha}"
}

check_pin stable "v${stable_version}"

# A release published as a non-draft GitHub prerelease. Any failure to ask
# (no gh, no token, API error) is a failure, never a pass.
canary_repo="Kernel-Guard/bpfcompat"
published_prerelease() {
  local state
  state="$(gh api "repos/${canary_repo}/releases/tags/$1" --jq '"\(.draft) \(.prerelease)"' 2>/dev/null)" || return 1
  [[ "$state" == "false true" ]]
}

# check_bootstrap_candidate <family> <rc-number>: while v<family>-rc.<n> is
# being prepared or built, the canary may still pin an EARLIER rc of the SAME
# release that is a published prerelease and resolves to the pinned commit.
check_bootstrap_candidate() {
  local family="$1" target_rc="$2"
  local sha="${pin_sha[candidate]:-}" line="${pin_line[candidate]:-}" version="${pin_version[candidate]:-}"
  if [[ -z "$sha" ]]; then
    note_fail "${workflow} declares no '# bpfcompat-pin: candidate' pin, so the candidate consumer path has no canary"
    return
  fi
  if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    note_fail "${workflow}:${line} candidate pin '${sha}' is not a full 40-character commit SHA"
    return
  fi
  local pinned_rc
  if [[ "$version" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)-rc\.([1-9][0-9]*)$ && "${BASH_REMATCH[1]}" == "$family" ]]; then
    pinned_rc="${BASH_REMATCH[2]}"
  else
    note_fail "${workflow}:${line} candidate pin '${version:-<no comment>}' must be an earlier rc of ${family} while v${release_version} is being prepared"
    return
  fi
  if (( pinned_rc >= target_rc )); then
    note_fail "${workflow}:${line} candidate pin ${version} is not earlier than v${release_version}"
    return
  fi
  tag_lookup "$version"
  if [[ "$LOOKUP_STATE" != found ]]; then
    note_fail "${workflow}:${line} could not resolve ${version} (${LOOKUP_STATE}); failing closed"
    return
  fi
  if [[ "$LOOKUP_SHA" != "$sha" ]]; then
    note_fail "${workflow}:${line} candidate pin is ${sha} but ${version} is ${LOOKUP_SHA}"
    return
  fi
  if ! published_prerelease "$version"; then
    note_fail "${workflow}:${line} ${version} is not a verified published prerelease (draft, missing, or the GitHub API could not be queried)"
    return
  fi
  echo "[canary-pins] candidate bootstrap: v${release_version} is being prepared; canary still pins published prerelease ${version} ${sha} (repin after the tag)"
}

case "$release_channel" in
  prerelease)
    if [[ "$release_version" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-rc\.([1-9][0-9]*)$ ]]; then
      target_family="${BASH_REMATCH[1]}"
      target_rc="${BASH_REMATCH[2]}"
      tag_lookup "v${release_version}"
      case "$LOOKUP_STATE" in
        absent)
          # The new RC is being prepared: its tag positively does not exist.
          check_bootstrap_candidate "$target_family" "$target_rc"
          ;;
        found)
          head_commit="$(git rev-parse -q --verify HEAD 2>/dev/null || true)"
          if [[ "$head_commit" =~ ^[0-9a-f]{40}$ && "$LOOKUP_SHA" == "$head_commit" ]]; then
            # The tag build of the new RC itself.
            check_bootstrap_candidate "$target_family" "$target_rc"
          else
            check_pin candidate "v${release_version}"
          fi
          ;;
        *)
          note_fail "cannot determine whether v${release_version} exists (remote unreachable or malformed answer); failing closed"
          ;;
      esac
    else
      check_pin candidate "v${release_version}"
    fi
    ;;
  stable)
    if [[ -n "${pin_line[candidate]:-}" ]]; then
      echo "[canary-pins] candidate pin not enforced: release_channel=stable has no prerelease to graduate"
    fi
    ;;
  *)
    note_fail "unknown release_channel '${release_channel}' (expected stable or prerelease)"
    ;;
esac

if (( fail )); then
  echo "[canary-pins] repin ${workflow} to the releases release.yaml declares, or update release.yaml" >&2
  exit 1
fi

echo "[canary-pins] PASS stable=v${stable_version} channel=${release_channel}"
