#!/usr/bin/env bash
# Runs inside the pinned validator builder, right after the shipped validator
# was built there (scripts/build-validator-pinned.sh --inside with
# BPFCOMPAT_VALIDATOR_DIST=1). Records how that exact binary was made and from
# what, so the release can carry it:
#
#   validator-distribution-inside.sh <built-validator-dir> <out-dir>
#
# 1. Splits the Makefile's own compile+link command into a compile of main.o
#    and a link of main.o, links again with the linker's member trace and map,
#    and refuses unless that relinked binary is byte-identical to the built one.
# 2. For every link input (start files, static archives) and every header the
#    compile read, records path, sha256 and the owning Ubuntu package with its
#    version and source package. Any input without an owning package fails.
# 3. Copies each owning package's /usr/share/doc/<pkg>/copyright verbatim and
#    every /usr/share/common-licenses text they reference. Missing ones fail.
# 4. Copies every link input file (for an optional link-inputs asset).
#
# It records facts about the build; it does not decide which license applies or
# what any of it obliges. Needs bash, coreutils, dpkg, make and the compiler
# (no jq or python in the builder image). Output is sorted and has no times.
set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 <built-validator-dir> <out-dir>" >&2; exit 2; }
src="$1"
out="$2"
die() { echo "::error::validator-distribution: $*" >&2; exit 1; }

built="$src/bin/bpfcompat-validator"
[[ -s "$built" ]] || die "no built validator at $built"
mkdir -p "$out/copyright" "$out/common-licenses" "$out/link-inputs"

# The recipe is the Makefile's, read back rather than restated, so a flag
# change there is followed here (and then must still reproduce the binary).
recipe="$(make -s -n -C "$src" --always-make all LIBBPF_LINK_MODE=static 2>/dev/null |
  grep -F ' src/main.c -o bin/bpfcompat-validator ' || true)"
[[ "$(grep -c . <<<"$recipe")" -eq 1 ]] || die "cannot read the single compile+link command from the Makefile"
recipe="$(tr -s ' ' <<<"$recipe")"
before="${recipe%% src/main.c -o bin/bpfcompat-validator *}"
libs="${recipe#* src/main.c -o bin/bpfcompat-validator }"
cc="${before%% *}"
compile="$before -c src/main.c -o main.o"
link="$cc main.o -o bpfcompat-validator.relinked $libs"
{
  echo "# Run in validator/c-libbpf inside the pinned builder (validator/build-inputs.lock)."
  echo "# Makefile recipe (LIBBPF_LINK_MODE=static):"
  echo "$recipe"
  echo "# The same recipe split into compile and link:"
  echo "$compile"
  echo "$link"
} >"$out/commands.txt"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp -r "$src/." "$work/"
(
  cd "$work"
  rm -f main.o bpfcompat-validator.relinked
  eval "$compile"
  eval "$link -Wl,-t,-t -Wl,-Map=link.map" >link-trace.raw 2>&1
  eval "${before} -M src/main.c" >compile-deps.raw
) || die "the split compile/link failed"
want="$(sha256sum "$built" | cut -d' ' -f1)"
have="$(sha256sum "$work/bpfcompat-validator.relinked" | cut -d' ' -f1)"
[[ "$have" == "$want" ]] ||
  die "main.o relinked to $have, not the built validator $want; the relink record would not describe the shipped binary"
printf '%s  bpfcompat-validator\n' "$have" >"$out/relinked.sha256"
cp "$work/main.o" "$out/main.o"
sed "s|$work|/build/validator/c-libbpf|g" "$work/link.map" >"$out/link.map"

owner() { # <path> -> package name owning it, or nothing
  local p="$1" r o
  r="$(readlink -f "$p")"
  o="$(dpkg -S "$r" 2>/dev/null | head -1 | cut -d: -f1)" || true
  [[ -n "$o" ]] || o="$(dpkg -S "$p" 2>/dev/null | head -1 | cut -d: -f1)" || true
  printf '%s' "$o"
}

# Link inputs: every file the linker opened, and every archive member it took.
: >"$work/files"
: >"$out/members.tsv.tmp"
while IFS= read -r line; do
  if [[ "$line" =~ ^\((.+)\)(.+)$ ]]; then
    printf '%s\t%s\n' "$(readlink -f "${BASH_REMATCH[1]}")" "${BASH_REMATCH[2]}" >>"$out/members.tsv.tmp"
  elif [[ "$line" == /* ]]; then
    readlink -f "$line" >>"$work/files"
  elif [[ "$line" == main.o ]]; then
    :
  else
    die "unrecognised linker trace line: $line"
  fi
done <"$work/link-trace.raw"
cut -f1 "$out/members.tsv.tmp" >>"$work/files"
{ printf 'archive\tmember\n'; LC_ALL=C sort -u "$out/members.tsv.tmp"; } >"$out/members.tsv"
rm -f "$out/members.tsv.tmp"
sed "s|$work|/build/validator/c-libbpf|g" "$work/link-trace.raw" >"$out/link-trace.txt"

# Headers the compile read (the dependency list), minus the validator's own.
tr ' \\' '\n\n' <"$work/compile-deps.raw" | grep '^/' | while IFS= read -r h; do readlink -f "$h"; done |
  grep -v "^$work/" | LC_ALL=C sort -u >"$work/headers"

: >"$work/pkgs"
printf 'role\tpath\tsha256\tpackage\n' >"$out/inputs.tsv"
for role in link-input header; do
  list="$work/files"
  [[ "$role" == header ]] && list="$work/headers"
  LC_ALL=C sort -u "$list" | while IFS= read -r f; do
    [[ -f "$f" ]] || die "$role $f does not exist"
    pkg="$(owner "$f")"
    [[ -n "$pkg" ]] || die "$role $f belongs to no installed package"
    printf '%s\t%s\t%s\t%s\n' "$role" "$f" "$(sha256sum "$f" | cut -d' ' -f1)" "$pkg" >>"$out/inputs.tsv"
    echo "$pkg" >>"$work/pkgs"
    if [[ "$role" == link-input ]]; then
      mkdir -p "$out/link-inputs$(dirname "$f")"
      cp "$f" "$out/link-inputs$f"
    fi
  done
done

printf 'package\tversion\tsource\tsource_version\troles\n' >"$out/packages.tsv"
LC_ALL=C sort -u "$work/pkgs" | while IFS= read -r pkg; do
  info="$(dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}' "$pkg")" ||
    die "dpkg-query cannot describe $pkg"
  roles="$(awk -F'\t' -v p="$pkg" '$4 == p { print $1 }' "$out/inputs.tsv" | LC_ALL=C sort -u | paste -sd,)"
  printf '%s\t%s\n' "$info" "$roles" >>"$out/packages.tsv"
  cr="/usr/share/doc/$pkg/copyright"
  [[ -s "$cr" ]] || die "$pkg has no $cr"
  mkdir -p "$out/copyright/$pkg"
  cp -L "$cr" "$out/copyright/$pkg/copyright"
done

# Texts the copyright files point to instead of reproducing.
{ grep -rhoE '/usr/share/common-licenses/[A-Za-z0-9.+_-]*[A-Za-z0-9+_-]' "$out/copyright" || true; } |
  LC_ALL=C sort -u | while IFS= read -r ref; do
    [[ -f "$ref" ]] || die "a copyright file references $ref, which is not installed"
    cp -L "$ref" "$out/common-licenses/$(basename "$ref")"
  done

(cd "$out" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS)
# Hand the files to the caller's user (the container runs as root).
chown -R "$(stat -c %u:%g "$(dirname "$out")")" "$out"
echo "validator-distribution: relink reproduced $have; $(($(wc -l <"$out/inputs.tsv") - 1)) inputs from $(($(wc -l <"$out/packages.tsv") - 1)) packages"
