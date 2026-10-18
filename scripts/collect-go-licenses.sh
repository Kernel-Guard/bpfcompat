#!/usr/bin/env bash
# Collect the license material of every Go module linked into shipped binaries.
#
#   collect-go-licenses.sh <out-dir> <binary> [<binary> ...]
#
# The module list comes from each binary's own build information
# (`go version -m`), not from go.mod, so it is exactly what was linked. For
# every dependency module the vendored copy (vendor/<module>) must exist at the
# same version, and every license-like file under it (LICENSE*, LICENCE*,
# COPYING*, NOTICE*, PATENTS*, AUTHORS*, CONTRIBUTORS*, at any depth, so nested
# third-party code inside a module is covered) is copied verbatim. The Go
# toolchain's own LICENSE and PATENTS come from GOROOT, and the toolchain must
# be the one that built the binaries. bpfcompat's LICENSE and NOTICE are copied
# from the repository root.
#
# Output (deterministic, no timestamps):
#   <out-dir>/bpfcompat/{LICENSE,NOTICE}
#   <out-dir>/go/toolchain/{LICENSE,PATENTS,VERSION}
#   <out-dir>/go/modules/<module path>/<path inside the module>
#   <out-dir>/go/modules.tsv  module, version, go.sum hash, binaries, files
#
# It copies texts only: it does not decide which license applies or whether
# anything else is owed. Needs only bash, awk, sort and the go command (it runs
# inside the Docker builder stage too). Exit 1 on any missing input.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -ge 2 ]] || { echo "usage: $0 <out-dir> <binary> [<binary> ...]" >&2; exit 2; }
out="$1"
shift
die() { echo "collect-go-licenses: $*" >&2; exit 1; }
command -v go >/dev/null || die "the go command is required"

LICENSE_RE='^(licen[cs]e|copying|notice|patents|authors|contributors)([._-].*)?$'

[[ ! -e "$out" ]] || [[ -z "$(ls -A "$out")" ]] || die "$out must be empty or absent"
mkdir -p "$out/bpfcompat" "$out/go/toolchain" "$out/go/modules"
for f in LICENSE NOTICE; do
  [[ -s "$ROOT/$f" ]] || die "repository $f is missing"
  cp "$ROOT/$f" "$out/bpfcompat/$f"
done

goroot="$(go env GOROOT)"
toolchain="$(go env GOVERSION)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
: >"$work/deps"
for bin in "$@"; do
  [[ -f "$bin" ]] || die "binary $bin not found"
  go version -m "$bin" >"$work/info" 2>/dev/null || die "$bin carries no Go build information"
  built_by="$(awk 'NR == 1 { print $NF }' "$work/info")"
  [[ "$built_by" == "$toolchain" ]] ||
    die "$bin was built by $built_by but GOROOT is $toolchain; run with the toolchain that built it"
  name="$(basename "$bin")"
  # A replaced module ("=>" line) would ship code from somewhere other than the
  # vendored copy at that version: refuse rather than guess.
  if awk '$1 == "=>"' "$work/info" | grep -q .; then
    die "$bin links a replaced module; the vendored copy would not be its source"
  fi
  awk -v b="$name" '$1 == "dep" { print $2 "\t" $3 "\t" ($4 == "" ? "-" : $4) "\t" b }' "$work/info" >>"$work/deps"
done
[[ -s "$work/deps" ]] || die "no dependency modules found in the given binaries"

for f in LICENSE PATENTS; do
  [[ -s "$goroot/$f" ]] || die "Go toolchain $f not found in $goroot"
  cp "$goroot/$f" "$out/go/toolchain/$f"
done
printf '%s\n' "$toolchain" >"$out/go/toolchain/VERSION"

modules_txt="$ROOT/vendor/modules.txt"
[[ -f "$modules_txt" ]] || die "vendor/modules.txt not found"
printf 'module\tversion\tsum\tbinaries\tfiles\n' >"$out/go/modules.tsv"
LC_ALL=C sort -u "$work/deps" | awk -F'\t' '
  { key = $1 "\t" $2 "\t" $3; if (key in bins) bins[key] = bins[key] "," $4; else bins[key] = $4 }
  END { for (k in bins) print k "\t" bins[k] }' | LC_ALL=C sort >"$work/modules"
while IFS=$'\t' read -r mod ver sum bins; do
  grep -qxF "# $mod $ver" "$modules_txt" ||
    die "$mod $ver is linked but vendor/modules.txt does not record that version"
  src="$ROOT/vendor/$mod"
  [[ -d "$src" ]] || die "$mod is linked but vendor/$mod is missing"
  (cd "$src" && find . -type f | sed 's|^\./||' | LC_ALL=C sort) |
    awk -v re="$LICENSE_RE" '{ n = split($0, p, "/"); if (tolower(p[n]) ~ re) print }' >"$work/files"
  [[ -s "$work/files" ]] || die "$mod $ver has no license file under vendor/$mod"
  while IFS= read -r rel; do
    mkdir -p "$out/go/modules/$mod/$(dirname "$rel")"
    cp "$src/$rel" "$out/go/modules/$mod/$rel"
  done <"$work/files"
  printf '%s\t%s\t%s\t%s\t%s\n' "$mod" "$ver" "$sum" "$bins" "$(paste -sd, "$work/files")" >>"$out/go/modules.tsv"
done <"$work/modules"
echo "collect-go-licenses: $(($(wc -l <"$out/go/modules.tsv") - 1)) modules from $# binaries ($toolchain) -> $out"
