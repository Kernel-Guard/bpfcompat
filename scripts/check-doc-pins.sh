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
    sha="$(git ls-remote --tags origin "refs/tags/${tag}^{}" 2>/dev/null | awk '{print $1}' | head -1)"
  fi
  printf '%s' "$sha"
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
      note_fail "$file:$line pins $version, which is not a released tag"
      continue
    fi
  else
    note_fail "$file:$line pins '$ref', which is neither a release tag nor a commit SHA"
    continue
  fi

  versions["$version"]+="$file:$line "
done < <(grep -rn 'Kernel-Guard/bpfcompat@' README.md docs 2>/dev/null || true)

if (( ${#versions[@]} > 1 )); then
  note_fail "docs pin more than one bpfcompat version:"
  for v in "${!versions[@]}"; do
    echo "           $v -> ${versions[$v]}" >&2
  done
fi

if (( fail )); then
  echo "[doc-pins] update the pins so every documented path uses one current release" >&2
  exit 1
fi

echo "[doc-pins] ok: every documented action pin resolves to ${!versions[*]}"
