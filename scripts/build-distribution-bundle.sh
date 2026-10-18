#!/usr/bin/env bash
# Assemble the release's distribution assets from the build's own records.
#
#   build-distribution-bundle.sh \
#     --go-dir <dir>           collect-go-licenses.sh output for the shipped CLIs
#     --native-dir <dir>       build-validator-pinned.sh <out-dist-dir> output
#     --validator <file>       the shipped validator binary
#     --build-inputs <file>    its validator-build-inputs.json
#     --version <vX.Y.Z...>    release version, recorded in the inventory
#     --commit <sha>           release commit, recorded in the inventory
#     --out <dir>              where the assets are written (must be empty)
#     [--with-link-inputs]     also write the link-inputs archive
#     [--sources-dir <dir>]    also write the native-sources archive from
#                              fetch-native-sources.sh output
#     [--policy <file>]        default distribution/policy.json
#
# Assets (byte-for-byte reproducible from the same inputs):
#   bpfcompat-third-party-licenses.tar.gz
#   bpfcompat-validator-relink-kit-linux-amd64.tar.gz
#   bpfcompat-validator-link-inputs-linux-amd64.tar.gz   (--with-link-inputs)
#   bpfcompat-validator-native-sources.tar               (--sources-dir)
#
# Refuses (exit 1) when any expected input is missing or inconsistent: the
# relinked, built and recorded validator digests must agree, the native record
# must verify against its own SHA256SUMS, every linked package's source version
# must be in distribution/native-sources.lock, and the validator source tree
# must be the one the build record names. It never fills a gap with a default.
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() { echo "build-distribution-bundle: $*" >&2; exit 1; }
go_dir="" native_dir="" validator="" build_inputs="" version="" commit="" out=""
with_link_inputs=0 sources_dir="" policy="$ROOT/distribution/policy.json"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --go-dir) go_dir="$2"; shift 2 ;;
    --native-dir) native_dir="$2"; shift 2 ;;
    --validator) validator="$2"; shift 2 ;;
    --build-inputs) build_inputs="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --commit) commit="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --with-link-inputs) with_link_inputs=1; shift ;;
    --sources-dir) sources_dir="$2"; shift 2 ;;
    --policy) policy="$2"; shift 2 ;;
    *) echo "build-distribution-bundle: unknown argument $1" >&2; exit 2 ;;
  esac
done
for v in go_dir native_dir validator build_inputs version commit out; do
  [[ -n "${!v}" ]] || { echo "build-distribution-bundle: --${v//_/-} is required" >&2; exit 2; }
done
for t in jq tar gzip sha256sum git; do command -v "$t" >/dev/null || die "$t is required"; done
[[ ! -e "$out" || -z "$(ls -A "$out")" ]] || die "$out must be empty or absent"

# ------------------------------------------------------------ input checks
for f in go/modules.tsv go/toolchain/LICENSE go/toolchain/PATENTS go/toolchain/VERSION bpfcompat/LICENSE bpfcompat/NOTICE; do
  [[ -s "$go_dir/$f" ]] || die "Go license input $go_dir/$f is missing"
done
[[ "$(wc -l <"$go_dir/go/modules.tsv")" -ge 2 ]] || die "$go_dir/go/modules.tsv lists no modules"
for f in SHA256SUMS main.o commands.txt link-trace.txt link.map inputs.tsv members.tsv packages.tsv relinked.sha256; do
  [[ -s "$native_dir/$f" ]] || die "native distribution input $native_dir/$f is missing"
done
(cd "$native_dir" && sha256sum --quiet -c SHA256SUMS) || die "the native distribution record does not match its SHA256SUMS"
[[ -s "$validator" ]] || die "validator $validator not found"
[[ -s "$build_inputs" ]] || die "build record $build_inputs not found"
bash "$ROOT/scripts/check-distribution-policy.sh" "$policy" >/dev/null || die "distribution policy $policy is invalid"

vsha="$(sha256sum "$validator" | cut -d' ' -f1)"
rsha="$(awk 'NR == 1 { print $1 }' "$native_dir/relinked.sha256")"
bsha="$(jq -r '.sha256 // empty' "$build_inputs")"
[[ "$vsha" == "$rsha" && "$vsha" == "$bsha" ]] ||
  die "validator digests disagree: shipped $vsha, relinked ${rsha:-none}, build record ${bsha:-none}"
tree="$(jq -r '.validator_tree // empty' "$build_inputs")"
[[ "$(git -C "$ROOT" rev-parse HEAD:validator/c-libbpf)" == "$tree" ]] ||
  die "validator/c-libbpf at HEAD is not the tree $tree the build record names"
[[ -z "$(git -C "$ROOT" status --porcelain -- validator/c-libbpf)" ]] || die "validator/c-libbpf has uncommitted changes"

lock_sources="$ROOT/distribution/native-sources.lock"
[[ -s "$lock_sources" ]] || die "distribution/native-sources.lock is missing"
while IFS=$'\t' read -r pkg pver src sver roles; do
  [[ "$roles" == *link-input* ]] || continue
  grep -qxF "source=$src $sver" "$lock_sources" ||
    die "$pkg links code from source $src $sver, which distribution/native-sources.lock does not list"
done < <(tail -n +2 "$native_dir/packages.tsv")
mapfile -t cr_pkgs < <(tail -n +2 "$native_dir/packages.tsv" | cut -f1)
for p in "${cr_pkgs[@]}"; do
  [[ -s "$native_dir/copyright/$p/copyright" ]] || die "no copyright file recorded for $p"
done
# Every text an inventory line names must exist: no entry is ever recorded
# without its file.
while IFS=$'\t' read -r mod _ _ _ files; do
  while IFS= read -r rel; do
    [[ -n "$rel" && -s "$go_dir/go/modules/$mod/$rel" ]] || die "Go license text go/modules/$mod/${rel:-<none>} is missing"
  done < <(tr ',' '\n' <<<"$files")
done < <(tail -n +2 "$go_dir/go/modules.tsv")
while IFS= read -r ref; do
  [[ -s "$native_dir/common-licenses/$(basename "$ref")" ]] ||
    die "a copyright file references $ref, but the native record has no common-licenses/$(basename "$ref")"
done < <(grep -rhoE '/usr/share/common-licenses/[A-Za-z0-9.+_-]*[A-Za-z0-9+_-]' "$native_dir/copyright" | LC_ALL=C sort -u || true)

# ------------------------------------------------------------ helpers
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$out"
normalize() { # <dir>: fixed modes so the archive does not depend on umask
  find "$1" -type d -exec chmod 0755 {} +
  find "$1" -type f -exec chmod 0644 {} +
}
seal() { # <dir>: write SHA256SUMS of every file in it
  (cd "$1" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sed 's|  \./|  |' >SHA256SUMS)
}
archive() { # <parent> <top> <output> [gz]
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner --format=gnu \
    -C "$1" -cf "$3.tmp" "$2"
  if [[ "${4:-}" == gz ]]; then gzip -n -9 <"$3.tmp" >"$3"; rm -f "$3.tmp"; else mv "$3.tmp" "$3"; fi
}

# ------------------------------------------------------------ license bundle
L="$stage/bpfcompat-third-party-licenses"
mkdir -p "$L/native"
cp "$ROOT/distribution/license-bundle/README.md" "$L/README.md"
cp -r "$go_dir/bpfcompat" "$go_dir/go" "$L/"
cp "$native_dir/packages.tsv" "$native_dir/inputs.tsv" "$native_dir/members.tsv" "$L/native/"
cp -r "$native_dir/copyright" "$native_dir/common-licenses" "$L/native/"
cp "$policy" "$L/distribution-policy.json"

go_json="$(tail -n +2 "$go_dir/go/modules.tsv" | while IFS=$'\t' read -r mod ver _ bins files; do
  fj="$(tr ',' '\n' <<<"$files" | while IFS= read -r rel; do
    jq -n --arg p "go/modules/$mod/$rel" --arg s "$(sha256sum "$L/go/modules/$mod/$rel" | cut -d' ' -f1)" '{path: $p, sha256: $s}'
  done | jq -s .)"
  jq -n --arg m "$mod" --arg v "$ver" --arg b "$bins" --argjson f "$fj" \
    '{module: $m, version: $v, binaries: ($b | split(",")), files: $f}'
done | jq -s .)"
pkg_json="$(tail -n +2 "$native_dir/packages.tsv" | while IFS=$'\t' read -r pkg pver src sver roles; do
  jq -n --arg p "$pkg" --arg v "$pver" --arg s "$src" --arg sv "$sver" --arg r "$roles" \
    --arg c "$(sha256sum "$L/native/copyright/$pkg/copyright" | cut -d' ' -f1)" \
    --argjson inputs "$(awk -F'\t' -v p="$pkg" 'NR > 1 && $4 == p && $1 == "link-input" { print $2 }' "$native_dir/inputs.tsv" | jq -R . | jq -s .)" \
    '{package: $p, version: $v, source: $s, source_version: $sv, roles: ($r | split(",")),
      link_inputs: $inputs, copyright: {path: "native/copyright/\($p)/copyright", sha256: $c}}'
done | jq -s .)"
members_json="$(tail -n +2 "$native_dir/members.tsv" | awk -F'\t' '{ n = split($1, a, "/"); c[a[n]]++ } END { for (k in c) print k "\t" c[k] }' |
  LC_ALL=C sort | jq -R 'split("\t") | {(.[0]): (.[1] | tonumber)}' | jq -s 'add')"
common_json="$(cd "$L/native/common-licenses" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r n; do
  jq -n --arg p "native/common-licenses/$n" --arg s "$(sha256sum "$n" | cut -d' ' -f1)" '{path: $p, sha256: $s}'; done | jq -s .)"

jq -n \
  --arg version "$version" --arg commit "$commit" \
  --arg toolchain "$(cat "$go_dir/go/toolchain/VERSION")" \
  --arg tl "$(sha256sum "$L/go/toolchain/LICENSE" | cut -d' ' -f1)" \
  --arg tp "$(sha256sum "$L/go/toolchain/PATENTS" | cut -d' ' -f1)" \
  --argjson modules "$go_json" --argjson packages "$pkg_json" \
  --argjson members "$members_json" --argjson common "$common_json" \
  --arg vsha "$vsha" --arg bsha "$(sha256sum "$build_inputs" | cut -d' ' -f1)" \
  --slurpfile record "$build_inputs" \
  --arg headers "$(awk -F'\t' 'NR > 1 && $1 == "header"' "$native_dir/inputs.tsv" | wc -l)" \
  --arg nslock "$(sha256sum "$lock_sources" | cut -d' ' -f1)" \
  --slurpfile policy "$policy" '
  {
    schema_version: "v1",
    bpfcompat: {version: $version, commit: $commit},
    observed: {
      go: {
        toolchain: $toolchain,
        toolchain_texts: [{path: "go/toolchain/LICENSE", sha256: $tl}, {path: "go/toolchain/PATENTS", sha256: $tp}],
        modules: $modules,
        source: "go version -m of each shipped CLI binary; texts from vendor/<module>"
      },
      validator: {
        artifact: "bpfcompat-validator-static-linux-amd64",
        sha256: $vsha,
        build_record_sha256: $bsha,
        builder_image: $record[0].builder_image,
        apt_snapshot: $record[0].apt_snapshot,
        relink_reproduced: true,
        linked_members_by_archive: $members,
        headers_read: ($headers | tonumber),
        packages: $packages,
        common_licenses: $common,
        native_sources_lock_sha256: $nslock,
        source: "linker trace (-t -t) and dpkg ownership inside the pinned builder"
      }
    },
    recorded_decisions: ($policy[0].decisions | with_entries(.value |= {status, value, questions})),
    not_established: [
      "No license option is elected by this bundle; see recorded_decisions.",
      "Mapping an archive member to the library source file it was compiled from is by name, not exact.",
      "That shipping these texts, or any other material, meets any license condition.",
      "Retention of the third-party source archives named in native-sources.lock."
    ]
  }' >"$L/INVENTORY.json"
normalize "$L"
seal "$L"
archive "$stage" bpfcompat-third-party-licenses "$out/bpfcompat-third-party-licenses.tar.gz" gz

# ------------------------------------------------------------ relink kit
K="$stage/bpfcompat-validator-relink-kit"
mkdir -p "$K/build" "$K/tools" "$K/validator-source" "$K/bpfcompat"
cp "$ROOT/distribution/relink-kit/README.md" "$K/README.md"
cp "$ROOT/distribution/relink-kit/relink.sh" "$K/relink.sh"
cp "$native_dir/main.o" "$K/main.o"
for f in commands.txt link-trace.txt link.map inputs.tsv members.tsv packages.tsv; do cp "$native_dir/$f" "$K/build/$f"; done
cp "$build_inputs" "$K/build/validator-build-inputs.json"
cp "$ROOT/validator/build-inputs.lock" "$K/build/build-inputs.lock"
cp "$lock_sources" "$K/build/native-sources.lock"
cp "$ROOT/scripts/build-validator-pinned.sh" "$K/tools/build-validator-pinned.sh"
cp "$go_dir/bpfcompat/LICENSE" "$go_dir/bpfcompat/NOTICE" "$K/bpfcompat/"
git -C "$ROOT" ls-files -z -- validator/c-libbpf | while IFS= read -r -d '' f; do
  mkdir -p "$K/validator-source/$(dirname "${f#validator/c-libbpf/}")"
  git -C "$ROOT" show "HEAD:$f" >"$K/validator-source/${f#validator/c-libbpf/}"
done
normalize "$K"
chmod 0755 "$K/relink.sh" "$K/tools/build-validator-pinned.sh"
seal "$K"
archive "$stage" bpfcompat-validator-relink-kit "$out/bpfcompat-validator-relink-kit-linux-amd64.tar.gz" gz

# ------------------------------------------------------------ optional assets
if [[ "$with_link_inputs" == 1 ]]; then
  I="$stage/bpfcompat-validator-link-inputs"
  [[ -d "$native_dir/link-inputs" && -n "$(find "$native_dir/link-inputs" -type f)" ]] ||
    die "the native record holds no link-input files"
  mkdir -p "$I"
  cp -r "$native_dir/link-inputs/." "$I/"
  cp "$native_dir/inputs.tsv" "$native_dir/packages.tsv" "$I/"
  normalize "$I"
  seal "$I"
  archive "$stage" bpfcompat-validator-link-inputs "$out/bpfcompat-validator-link-inputs-linux-amd64.tar.gz" gz
fi
if [[ -n "$sources_dir" ]]; then
  S="$stage/bpfcompat-validator-native-sources"
  mkdir -p "$S"
  while read -r pkg name _ sha _; do
    [[ -f "$sources_dir/$pkg/$name" ]] || die "source file $pkg/$name is missing from $sources_dir"
    [[ "$(sha256sum "$sources_dir/$pkg/$name" | cut -d' ' -f1)" == "$sha" ]] || die "$pkg/$name does not match native-sources.lock"
    mkdir -p "$S/$pkg"
    cp "$sources_dir/$pkg/$name" "$S/$pkg/$name"
  done < <(awk 'index($0, "file=") == 1 { print substr($0, 6) }' "$lock_sources")
  cp "$lock_sources" "$S/native-sources.lock"
  normalize "$S"
  seal "$S"
  archive "$stage" bpfcompat-validator-native-sources "$out/bpfcompat-validator-native-sources.tar"
fi
(cd "$out" && ls -1)
