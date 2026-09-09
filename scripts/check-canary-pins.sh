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

# Resolve a tag to the commit it points at. Prefer the local clone; fall back to
# the remote for the shallow checkouts some gate workflows use. `set -euo
# pipefail` is in force, so a failing remote (no origin, network down) must be
# swallowed here or it aborts the script from inside a command substitution and
# skips the caller's error path. The remote is overridable so the regression
# suite, whose fixture tags all resolve locally, never reaches the network.
tag_remote="${BPFCOMPAT_TAG_REMOTE:-origin}"
tag_commit() {
  local tag="$1" sha=""
  sha="$(git rev-parse -q --verify "refs/tags/${tag}^{commit}" 2>/dev/null || true)"
  if [[ -z "$sha" ]]; then
    # Ask for both refs. Only an annotated tag advertises a peeled `^{}` ref;
    # a lightweight one advertises just `refs/tags/<tag>`, pointing straight at
    # the commit. Every release tag is annotated today, so querying the peeled
    # ref alone happens to work -- and would report the next lightweight tag as
    # nonexistent, failing the release gate for a tag that is right there.
    # Prefer the peeled value when both come back; it is the commit.
    sha="$(git ls-remote --tags "$tag_remote" \
      "refs/tags/${tag}" "refs/tags/${tag}^{}" 2>/dev/null |
      awk '
        $2 ~ /\^\{\}$/ { peeled = $1 }
        $2 !~ /\^\{\}$/ { direct = $1 }
        END { print peeled != "" ? peeled : direct }
      ' || true)"
  fi
  printf '%s' "$sha"
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

  local actual
  actual="$(tag_commit "$expected")"
  if [[ -z "$actual" ]]; then
    note_fail "${workflow}:${line} ${channel} pin names ${expected}, which is not a tag in this repository"
    return
  fi
  if [[ "$actual" != "$sha" ]]; then
    note_fail "${workflow}:${line} ${channel} pin is ${sha} but ${expected} is ${actual}; the canary is exercising a stale release"
    return
  fi

  echo "[canary-pins] ${channel} ${expected} ${sha}"
}

check_pin stable "v${stable_version}"

case "$release_channel" in
  prerelease)
    check_pin candidate "v${release_version}"
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
