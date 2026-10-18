#!/usr/bin/env bash
# Guard the bpfcompat pins that appear in user-facing docs.
#
# v0.3.6 shipped an action that hard-failed on every amd64 runner. The bug was
# fixed in v0.3.7, but README.md, docs/*.md and all four docs/integrations
# templates kept pointing at v0.3.6 for two weeks, so every documented
# copy-paste path stayed broken. Nothing in CI noticed, because no check ever
# looked at the pins in the docs.
#
# This asserts three things about every `Kernel-Guard/bpfcompat@<ref>` we
# publish:
#   1. a commit-SHA pin carries a `# vX.Y.Z` comment naming the release it is,
#   2. that comment is true -- the tag really does resolve to that commit, and
#   3. every documented pin names the same version, so docs cannot drift apart.
#
# Only `uses:` lines are checked -- those are the copy-paste surface a reader
# actually runs. Prose that names an old version inside a dated evidence record
# (docs/external-ci-proof.md) is history, not an instruction, and is left alone.
# `@main` and `@latest` are deliberate and exempt, as is any line carrying an
# explicit `doc-pins: allow` marker.
#
# The stable release pull request is the one state rule 2 cannot be met in:
# the release-consistency gate requires its docs to name vX.Y.Z, and that tag
# is created only after the PR merges. So while release.yaml says
# release_channel `stable`, a tag-form pin on exactly v<stable_version> is
# accepted when the remote positively has no such tag; an unreachable remote
# still fails. Commit-SHA pins never get this exemption.
#
# The integration templates are pinned by commit SHA (docs/integrations), so
# they cannot name vX.Y.Z until its tag exists. During the same stable window
# -- the stable PR while vX.Y.Z is absent, and the vX.Y.Z tag build itself --
# rule 3 allows exactly one other version beside v<stable_version>: the most
# recent earlier stable release tag (vA.B.C < X.Y.Z). Every later commit is
# strict again, so the templates are repinned once the tag exists.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
declare -A versions=()

note_fail() {
  echo "[doc-pins] $*" >&2
  fail=1
}

# Resolve an annotated or lightweight tag to the commit it points at, falling
# back to the remote when the local clone has no tags (shallow checkout).
tag_commit() {
  local tag="$1" sha=""
  sha="$(git rev-parse -q --verify "refs/tags/${tag}^{commit}" 2>/dev/null || true)"
  if [[ -z "$sha" ]]; then
    # `set -euo pipefail` is in force: a failing remote (no `origin`, network
    # down, SIGPIPE from `head`) would abort the whole script from inside this
    # command substitution and skip the note_fail path, so swallow it here and
    # let the caller report "tag does not exist".
    sha="$(git ls-remote --tags origin "refs/tags/${tag}^{}" 2>/dev/null | awk 'NR == 1 {print $1}' || true)"
  fi
  printf '%s' "$sha"
}

# The release the stable PR is preparing, or nothing outside the stable channel.
release_value() { awk -F': *' -v k="$1" '$1 == k { gsub(/["\r]/, "", $2); print $2 }' release.yaml; }
preparing=""
[[ "$(release_value release_channel)" == stable ]] && preparing="v$(release_value stable_version)"
prepared=""

# version_lt A B: X.Y.Z version A sorts strictly before X.Y.Z version B.
version_lt() {
  local -a a b
  local i
  IFS=. read -r -a a <<<"$1"
  IFS=. read -r -a b <<<"$2"
  for i in 0 1 2; do
    if (( 10#${a[i]} != 10#${b[i]} )); then
      (( 10#${a[i]} < 10#${b[i]} ))
      return
    fi
  done
  return 1
}

# previous_stable <vX.Y.Z>: the newest vA.B.C tag on the remote below it, or
# nothing when the remote cannot be listed.
previous_stable() {
  local tags tag newest=""
  tags="$(git ls-remote --tags --refs origin 'refs/tags/v*' 2>/dev/null)" || return 0
  while read -r _ tag; do
    tag="${tag#refs/tags/}"
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    version_lt "${tag#v}" "${1#v}" || continue
    if [[ -z "$newest" ]] || version_lt "${newest#v}" "${tag#v}"; then newest="$tag"; fi
  done <<<"$tags"
  printf '%s' "$newest"
}

# tag_absent <tag>: the remote answered and has no such tag (git ls-remote
# --exit-code returns 2); a remote that cannot be queried is not "absent".
tag_absent() {
  local rc=0
  git ls-remote --exit-code --tags origin "refs/tags/$1" >/dev/null 2>&1 || rc=$?
  [[ $rc -eq 2 ]]
}

while IFS= read -r hit; do
  file="${hit%%:*}"
  rest="${hit#*:}"
  line="${rest%%:*}"
  text="${rest#*:}"

  # Only the copy-paste surface: an actual workflow step a reader would run.
  [[ "$text" == *uses:* ]] || continue
  [[ "$text" == *"doc-pins: allow"* ]] && continue

  ref="$(sed -E 's|.*Kernel-Guard/bpfcompat@([A-Za-z0-9._-]+).*|\1|' <<<"$text")"
  case "$ref" in
    main | latest) continue ;;
  esac

  if [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
    if ! [[ "$text" =~ \#[[:space:]]*(v[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.-]*) ]]; then
      note_fail "$file:$line SHA pin has no '# vX.Y.Z' comment naming its release"
      continue
    fi
    version="${BASH_REMATCH[1]}"
    actual="$(tag_commit "$version")"
    if [[ -z "$actual" ]]; then
      note_fail "$file:$line claims $version, but that tag does not exist"
      continue
    fi
    if [[ "$actual" != "$ref" ]]; then
      note_fail "$file:$line claims $version, but $version is $actual (pin is $ref)"
      continue
    fi
  elif [[ "$ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    version="$ref"
    if [[ -z "$(tag_commit "$version")" ]]; then
      if [[ -n "$preparing" && "$version" == "$preparing" ]] && tag_absent "$version"; then
        prepared="$version"
      else
        note_fail "$file:$line pins $version, which is not a released tag"
        continue
      fi
    fi
  else
    note_fail "$file:$line pins '$ref', which is neither a release tag nor a commit SHA"
    continue
  fi

  versions["$version"]+="$file:$line "
done < <(grep -rn 'Kernel-Guard/bpfcompat@' README.md docs 2>/dev/null || true)

# A guard that finds nothing is a guard that passes forever. The docs always
# carry pins; zero matches means the docs moved or the pattern rotted.
if (( ${#versions[@]} == 0 )); then
  note_fail "found no 'uses: Kernel-Guard/bpfcompat@...' pins in README.md or docs -- the docs moved, or this check no longer matches them"
fi

# The stable window: v<stable_version> is being prepared (positively absent)
# or this is its tag build (it resolves to HEAD).
window_previous=""
if [[ -n "$preparing" && ${#versions[@]} -eq 2 && -n "${versions[$preparing]:-}" ]]; then
  head_commit="$(git rev-parse -q --verify 'HEAD^{commit}' 2>/dev/null || true)"
  if [[ -n "$prepared" ]] || [[ -n "$head_commit" && "$(tag_commit "$preparing")" == "$head_commit" ]]; then
    window_previous="$(previous_stable "$preparing")"
  fi
fi
if (( ${#versions[@]} == 2 )) && [[ -n "$window_previous" && -n "${versions[$window_previous]:-}" ]]; then
  echo "[doc-pins] stable window for ${preparing}: SHA-pinned templates may stay on ${window_previous} until the tag exists (${versions[$window_previous]% })"
elif (( ${#versions[@]} > 1 )); then
  note_fail "docs pin more than one bpfcompat version:"
  for v in "${!versions[@]}"; do
    echo "           $v -> ${versions[$v]}" >&2
  done
fi

if (( fail )); then
  echo "[doc-pins] update the pins so every documented path uses one current release" >&2
  exit 1
fi

if [[ -n "$window_previous" ]]; then
  echo "[doc-pins] ok: documented pins name ${preparing}, the stable release being prepared or built; SHA-pinned templates stay on ${window_previous} until its tag exists"
elif [[ -n "$prepared" ]]; then
  echo "[doc-pins] ok: every documented action pin names ${prepared}, the stable release being prepared (its tag does not exist yet)"
else
  echo "[doc-pins] ok: every documented action pin resolves to ${!versions[*]}"
fi
