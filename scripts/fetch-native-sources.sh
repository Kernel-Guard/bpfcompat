#!/usr/bin/env bash
# Fetch the exact source packages listed in distribution/native-sources.lock.
#
#   fetch-native-sources.sh [--cache <dir>] <out-dir> [<lock>]
#
# Writes <out-dir>/<package>/<file> for every file= line and refuses (exit 1)
# on a missing file, a size or sha256 mismatch, or a duplicate entry. With
# --cache, a file of the same name under <dir> (any depth) is used when its
# hash matches, so already-verified downloads are not fetched again; a cached
# file with a different hash is ignored, never trusted.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache=""
if [[ "${1:-}" == "--cache" ]]; then cache="${2:-}"; shift 2; fi
[[ $# -ge 1 && $# -le 2 ]] || { echo "usage: $0 [--cache <dir>] <out-dir> [<lock>]" >&2; exit 2; }
out="$1"
lock="${2:-$ROOT/distribution/native-sources.lock}"
die() { echo "fetch-native-sources: $*" >&2; exit 1; }
[[ -f "$lock" ]] || die "lock $lock not found"

entries="$(awk 'index($0, "file=") == 1 { print substr($0, 6) }' "$lock")"
[[ -n "$entries" ]] || die "$lock lists no files"
dups="$(awk '{ print $2 }' <<<"$entries" | LC_ALL=C sort | uniq -d)"
[[ -z "$dups" ]] || die "$lock lists a file twice: $dups"

n=0
while read -r pkg name size sha url extra; do
  [[ -z "${extra:-}" && "$pkg" =~ ^[a-z0-9][a-z0-9.+-]*$ && "$name" =~ ^[A-Za-z0-9][A-Za-z0-9.+~_-]*$ &&
    "$size" =~ ^[0-9]+$ && "$sha" =~ ^[0-9a-f]{64}$ && "$url" == https://* ]] ||
    die "malformed lock entry: $pkg $name $size $sha $url ${extra:-}"
  dest="$out/$pkg/$name"
  mkdir -p "$out/$pkg"
  got=""
  if [[ -n "$cache" ]]; then
    while IFS= read -r -d '' c; do
      if [[ "$(sha256sum "$c" | cut -d' ' -f1)" == "$sha" ]]; then got="$c"; break; fi
    done < <(find "$cache" -type f -name "$name" -print0 2>/dev/null)
  fi
  if [[ -n "$got" ]]; then
    cp "$got" "$dest"
  else
    curl -fsSL --retry 3 --connect-timeout 20 --max-time 1800 -o "$dest" "$url" ||
      die "download failed: $url"
  fi
  [[ "$(stat -c %s "$dest")" == "$size" ]] || die "$name: size $(stat -c %s "$dest"), lock says $size"
  [[ "$(sha256sum "$dest" | cut -d' ' -f1)" == "$sha" ]] || die "$name: sha256 does not match the lock"
  n=$((n + 1))
done <<<"$entries"
echo "fetch-native-sources: $n files verified against $(basename "$lock") -> $out"
