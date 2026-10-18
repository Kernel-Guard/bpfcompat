#!/usr/bin/env bash
# Regression cover for the release distribution assets:
#   scripts/check-distribution-policy.sh, scripts/collect-go-licenses.sh,
#   scripts/fetch-native-sources.sh, scripts/build-distribution-bundle.sh and
#   distribution/relink-kit/relink.sh.
#
# Runs without docker or network. The Go side uses the real CLI built from this
# tree; the native side (normally produced inside the pinned builder by
# scripts/validator-distribution-inside.sh) is a synthetic record with the same
# layout. Each case runs the real scripts from a throwaway copy of the
# repository so that inputs can be broken without touching the checkout.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
failures=0
fail() { echo "[distribution-test] FAIL: $*" >&2; failures=$((failures + 1)); }
ok() { echo "[distribution-test] ok: $*"; }
expect_fail() { # <description> <expected message (ERE)> <command...>
  local d="$1" want="$2"; shift 2
  if "$@" >"$tmp/last.log" 2>&1; then fail "$d: succeeded, expected refusal"
  elif grep -Eq -- "$want" "$tmp/last.log"; then ok "$d refused"
  else fail "$d: refused for another reason: $(tail -1 "$tmp/last.log")"; fi
}

# ---------------------------------------------------------------- fixtures
(cd "$ROOT_DIR" && CGO_ENABLED=0 go build -trimpath -o "$tmp/bin/bpfcompat-linux-amd64" ./cmd/bpfcompat &&
  CGO_ENABLED=0 GOARCH=arm64 go build -trimpath -o "$tmp/bin/bpfcompat-linux-arm64" ./cmd/bpfcompat)

# make_root <dir>: a git repository with the files the scripts read.
make_root() {
  local r="$1"
  mkdir -p "$r"
  (cd "$ROOT_DIR" && tar --exclude=validator/c-libbpf/bin -cf - scripts distribution vendor validator/c-libbpf validator/build-inputs.lock LICENSE NOTICE) |
    tar -xf - -C "$r"
  git -C "$r" init -q
  git -C "$r" add -A
  git -C "$r" -c user.name=t -c user.email=t@example.invalid commit -qm fixture
}
R="$tmp/root"
make_root "$R"
TREE="$(git -C "$R" rev-parse HEAD:validator/c-libbpf)"

# A synthetic native record shaped like validator-distribution-inside.sh output.
make_native() { # <dir> <validator-file>
  local n="$1" v="$2" sha
  mkdir -p "$n/copyright/libfoo-dev" "$n/copyright/libc6-dev" "$n/common-licenses" "$n/link-inputs/usr/lib"
  printf 'validator binary\n' >"$v"
  sha="$(sha256sum "$v" | cut -d' ' -f1)"
  printf 'object\n' >"$n/main.o"
  printf '# commands\ncc -O2 src/main.c -o bin/bpfcompat-validator -static\ncc -O2 -c src/main.c -o main.o\ncc main.o -o bpfcompat-validator.relinked -static -lfoo\n' >"$n/commands.txt"
  printf '/usr/lib/libfoo.a\n(/usr/lib/libfoo.a)foo.o\n' >"$n/link-trace.txt"
  printf 'map\n' >"$n/link.map"
  printf 'archive\tmember\n/usr/lib/libfoo.a\tfoo.o\n/usr/lib/libc.a\tprintf.o\n' >"$n/members.tsv"
  printf 'role\tpath\tsha256\tpackage\nlink-input\t/usr/lib/libfoo.a\t%s\tlibfoo-dev\nlink-input\t/usr/lib/libc.a\t%s\tlibc6-dev\nheader\t/usr/include/foo.h\t%s\tlibfoo-dev\n' \
    "$(printf a | sha256sum | cut -d' ' -f1)" "$(printf b | sha256sum | cut -d' ' -f1)" "$(printf c | sha256sum | cut -d' ' -f1)" >"$n/inputs.tsv"
  printf 'package\tversion\tsource\tsource_version\troles\nlibc6-dev\t2.39-0ubuntu8.9\tglibc\t2.39-0ubuntu8.9\tlink-input\nlibfoo-dev\t1:1.3.0-2build2\tlibbpf\t1.3.0-2build2\theader,link-input\n' >"$n/packages.tsv"
  printf 'Format: x\nLicense: LGPL-2.1, see /usr/share/common-licenses/LGPL-2.1.\n' >"$n/copyright/libfoo-dev/copyright"
  printf 'glibc copyright\n' >"$n/copyright/libc6-dev/copyright"
  printf 'LGPL 2.1 text\n' >"$n/common-licenses/LGPL-2.1"
  printf 'archive\n' >"$n/link-inputs/usr/lib/libfoo.a"
  printf '%s  bpfcompat-validator\n' "$sha" >"$n/relinked.sha256"
  (cd "$n" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS)
  jq -n --arg s "$sha" --arg t "$TREE" '{schema_version: "v0.1", sha256: $s, validator_tree: $t,
    builder_image: "docker.io/library/ubuntu@sha256:x", apt_snapshot: "20261014T154800Z"}' >"$(dirname "$n")/build-inputs.json"
}
make_native "$tmp/n/dist" "$tmp/n/validator"

bundle() { # <root> <native-parent> <out> [extra args]
  local r="$1" np="$2" o="$3"; shift 3
  bash "$r/scripts/build-distribution-bundle.sh" --go-dir "$tmp/go" --native-dir "$np/dist" \
    --validator "$np/validator" --build-inputs "$np/build-inputs.json" \
    --version v9.9.9-test --commit 0123456789abcdef --out "$o" "$@"
}

# ---------------------------------------------------------------- policy
P="$R/distribution/policy.json"
bash "$R/scripts/check-distribution-policy.sh" "$P" >/dev/null && ok "repository policy is well-formed" || fail "repository policy rejected"
expect_fail "stable with undecided decisions" 'is undecided' bash "$R/scripts/check-distribution-policy.sh" --require-decided "$P"
[[ "$(bash "$R/scripts/check-distribution-policy.sh" --ship ship_link_inputs_asset "$P")" == false ]] &&
  ok "undecided optional asset is withheld" || fail "undecided optional asset was shipped"
jq '.decisions |= with_entries(.value.status = "decided" | .value.value = .value.allowed[0])' "$P" >"$tmp/decided.json"
bash "$R/scripts/check-distribution-policy.sh" --require-decided "$tmp/decided.json" >/dev/null &&
  ok "stable accepted once every decision is recorded" || fail "fully decided policy refused"
[[ "$(bash "$R/scripts/check-distribution-policy.sh" --ship ship_link_inputs_asset "$tmp/decided.json")" == true ]] &&
  ok "decided optional asset is shipped" || fail "decided true did not ship"
jq '.decisions.libbpf_license_option |= (.status = "decided" | .value = "MIT")' "$P" >"$tmp/bad1.json"
expect_fail "decided value outside allowed" 'not in allowed' bash "$R/scripts/check-distribution-policy.sh" "$tmp/bad1.json"
jq '.decisions.libbpf_license_option.value = "BSD-2-Clause"' "$P" >"$tmp/bad2.json"
expect_fail "undecided decision with a value" 'must have value null' bash "$R/scripts/check-distribution-policy.sh" "$tmp/bad2.json"
expect_fail "--ship on a license decision" 'not a ship/omit decision' bash "$R/scripts/check-distribution-policy.sh" --ship libbpf_license_option "$P"

# ---------------------------------------------------------------- Go licenses
bash "$R/scripts/collect-go-licenses.sh" "$tmp/go" "$tmp/bin/bpfcompat-linux-amd64" "$tmp/bin/bpfcompat-linux-arm64" >/dev/null &&
  ok "Go licenses collected" || fail "Go license collection failed"
mods="$(tail -n +2 "$tmp/go/go/modules.tsv" | wc -l)"
want="$(cd "$ROOT_DIR" && go version -m "$tmp/bin/bpfcompat-linux-amd64" | awk '$1 == "dep"' | wc -l)"
[[ "$mods" -eq "$want" && "$mods" -gt 0 ]] && ok "every linked module listed ($mods)" || fail "modules.tsv has $mods, binary links $want"
grep -q $'^github.com/klauspost/compress\t.*internal/snapref/LICENSE' "$tmp/go/go/modules.tsv" &&
  ok "nested license files inside a module are collected" || fail "nested license file missing"
[[ -s "$tmp/go/go/toolchain/PATENTS" && -s "$tmp/go/go/modules/golang.org/x/sys/PATENTS" ]] &&
  ok "Go PATENTS texts included" || fail "PATENTS missing"
if grep -q 'gotest.tools' "$tmp/go/go/modules.tsv"; then fail "test-only module listed"; else ok "test-only modules are not listed"; fi

R2="$tmp/root-nolicense"; make_root "$R2"
find "$R2/vendor/github.com/beorn7/perks" -maxdepth 1 -name 'LICENSE*' -delete
expect_fail "module without a license file" 'has no license file' bash "$R2/scripts/collect-go-licenses.sh" "$tmp/go2" "$tmp/bin/bpfcompat-linux-amd64"
R3="$tmp/root-version"; make_root "$R3"
sed -i 's|^# gopkg.in/yaml.v3 v3.0.1$|# gopkg.in/yaml.v3 v3.0.0|' "$R3/vendor/modules.txt"
expect_fail "vendored version differs from the linked one" 'does not record that version' bash "$R3/scripts/collect-go-licenses.sh" "$tmp/go3" "$tmp/bin/bpfcompat-linux-amd64"
printf 'not a go binary\n' >"$tmp/notgo"
expect_fail "binary without build information" 'no Go build information' bash "$R/scripts/collect-go-licenses.sh" "$tmp/go4" "$tmp/notgo"
mkdir -p "$tmp/go5" && touch "$tmp/go5/stale"
expect_fail "non-empty output directory" 'must be empty' bash "$R/scripts/collect-go-licenses.sh" "$tmp/go5" "$tmp/bin/bpfcompat-linux-amd64"

# ---------------------------------------------------------------- bundle
bundle "$R" "$tmp/n" "$tmp/out1" >/dev/null && ok "bundle built" || fail "bundle build failed: $(cat "$tmp/last.log" 2>/dev/null)"
bundle "$R" "$tmp/n" "$tmp/out2" >/dev/null || fail "second bundle build failed"
for a in bpfcompat-third-party-licenses.tar.gz bpfcompat-validator-relink-kit-linux-amd64.tar.gz; do
  [[ -s "$tmp/out1/$a" ]] || fail "$a not produced"
  cmp -s "$tmp/out1/$a" "$tmp/out2/$a" && ok "$a is byte-for-byte reproducible" || fail "$a differs between identical builds"
done
[[ "$(ls "$tmp/out1" | wc -l)" -eq 2 ]] && ok "optional assets absent unless requested" || fail "unexpected assets: $(ls "$tmp/out1")"
mkdir -p "$tmp/x" && tar -xzf "$tmp/out1/bpfcompat-third-party-licenses.tar.gz" -C "$tmp/x"
tar -xzf "$tmp/out1/bpfcompat-validator-relink-kit-linux-amd64.tar.gz" -C "$tmp/x"
(cd "$tmp/x/bpfcompat-third-party-licenses" && sha256sum --quiet -c SHA256SUMS) && ok "license bundle SHA256SUMS covers its files" || fail "license bundle checksums"
(cd "$tmp/x/bpfcompat-validator-relink-kit" && sha256sum --quiet -c SHA256SUMS) && ok "relink kit SHA256SUMS covers its files" || fail "relink kit checksums"
for d in bpfcompat-third-party-licenses bpfcompat-validator-relink-kit; do
  listed="$(awk '{print $2}' "$tmp/x/$d/SHA256SUMS" | LC_ALL=C sort)"
  actual="$(cd "$tmp/x/$d" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort)"
  [[ "$listed" == "$actual" ]] && ok "$d: every file is checksummed" || fail "$d: SHA256SUMS does not list exactly the files"
done
if tar -tzvf "$tmp/out1/bpfcompat-third-party-licenses.tar.gz" | awk '$2 != "0/0" || $4 != "1970-01-01"' | grep -q .; then
  fail "archive entries carry owners or times"; else ok "archive entries have fixed owner and time"; fi
inv="$tmp/x/bpfcompat-third-party-licenses/INVENTORY.json"
jq -e --arg v "$(sha256sum "$tmp/n/validator" | cut -d' ' -f1)" --argjson m "$mods" '
  .observed.validator.sha256 == $v and (.observed.go.modules | length) == $m and
  .observed.validator.relink_reproduced == true and
  .observed.validator.linked_members_by_archive == {"libc.a": 1, "libfoo.a": 1} and
  ([.recorded_decisions[] | select(.status == "undecided")] | length) == ([.recorded_decisions[]] | length) and
  (.not_established | length) > 0' "$inv" >/dev/null && ok "inventory separates facts, decisions and gaps" || fail "inventory content"
jq -e '[.observed.go.modules[].files[], .observed.validator.packages[].copyright, .observed.validator.common_licenses[]] | all(.sha256 | test("^[0-9a-f]{64}$"))' "$inv" >/dev/null &&
  ok "every inventoried text has a sha256" || fail "inventory hashes"
bad=0
while read -r p s; do
  [[ "$(sha256sum "$tmp/x/bpfcompat-third-party-licenses/$p" | cut -d' ' -f1)" == "$s" ]] || bad=1
done < <(jq -r '.observed.go.modules[].files[], .observed.validator.packages[].copyright | "\(.path) \(.sha256)"' "$inv")
[[ "$bad" == 0 ]] && ok "inventory hashes match the bundled texts" || fail "inventory hash mismatch"
[[ -x "$tmp/x/bpfcompat-validator-relink-kit/relink.sh" && -s "$tmp/x/bpfcompat-validator-relink-kit/validator-source/src/main.c" ]] &&
  ok "relink kit carries relink.sh and the validator source" || fail "relink kit layout"

# Missing or inconsistent inputs.
cp -r "$tmp/n" "$tmp/n-sha" && printf 'other\n' >"$tmp/n-sha/validator"
expect_fail "shipped validator differs from the relinked one" 'validator digests disagree' bundle "$R" "$tmp/n-sha" "$tmp/o-sha"
cp -r "$tmp/n" "$tmp/n-tamper" && printf 'tampered\n' >>"$tmp/n-tamper/dist/link.map"
expect_fail "native record changed after it was sealed" 'does not match its SHA256SUMS' bundle "$R" "$tmp/n-tamper" "$tmp/o-tamper"
cp -r "$tmp/n" "$tmp/n-nocr" && rm "$tmp/n-nocr/dist/copyright/libc6-dev/copyright"
(cd "$tmp/n-nocr/dist" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS)
expect_fail "owning package without a copyright file" 'no copyright file recorded' bundle "$R" "$tmp/n-nocr" "$tmp/o-nocr"
cp -r "$tmp/n" "$tmp/n-ver" && sed -i 's/\tglibc\t2.39-0ubuntu8.9\t/\tglibc\t2.39-0ubuntu8.10\t/' "$tmp/n-ver/dist/packages.tsv"
(cd "$tmp/n-ver/dist" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS)
expect_fail "linked source version absent from native-sources.lock" 'does not list' bundle "$R" "$tmp/n-ver" "$tmp/o-ver"
cp -r "$tmp/n" "$tmp/n-nomem" && rm "$tmp/n-nomem/dist/members.tsv"
expect_fail "missing linker member list" 'members.tsv is missing' bundle "$R" "$tmp/n-nomem" "$tmp/o-nomem"
cp -r "$tmp/n" "$tmp/n-tree" && jq '.validator_tree = "0000000000000000000000000000000000000000"' "$tmp/n/build-inputs.json" >"$tmp/n-tree/build-inputs.json"
expect_fail "build record names another validator tree" 'is not the tree' bundle "$R" "$tmp/n-tree" "$tmp/o-tree"
rm -rf "$tmp/go-missing" && cp -r "$tmp/go" "$tmp/go-missing" && rm "$tmp/go-missing/go/toolchain/PATENTS"
expect_fail "missing Go toolchain PATENTS" 'PATENTS is missing' bash "$R/scripts/build-distribution-bundle.sh" --go-dir "$tmp/go-missing" \
  --native-dir "$tmp/n/dist" --validator "$tmp/n/validator" --build-inputs "$tmp/n/build-inputs.json" \
  --version v9 --commit c --out "$tmp/o-gomiss"

# Optional assets.
bundle "$R" "$tmp/n" "$tmp/out-li" --with-link-inputs >/dev/null &&
  tar -tzf "$tmp/out-li/bpfcompat-validator-link-inputs-linux-amd64.tar.gz" | grep -q 'usr/lib/libfoo.a' &&
  ok "link-inputs asset carries the link input files" || fail "link-inputs asset"
cp -r "$tmp/n" "$tmp/n-noli" && rm -rf "$tmp/n-noli/dist/link-inputs"
(cd "$tmp/n-noli/dist" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS)
expect_fail "link-inputs asset without link input files" 'holds no link-input files' bundle "$R" "$tmp/n-noli" "$tmp/o-noli" --with-link-inputs

# Native sources: a small lock in a separate root, served from a cache.
R4="$tmp/root-src"; make_root "$R4"
mkdir -p "$tmp/cache/a" && printf 'source tarball\n' >"$tmp/cache/a/libbpf_1.3.0.orig.tar.gz"
s1="$(sha256sum "$tmp/cache/a/libbpf_1.3.0.orig.tar.gz" | cut -d' ' -f1)"
{ printf 'source=libbpf 1.3.0-2build2\nsource=glibc 2.39-0ubuntu8.9\n'
  printf 'file=libbpf libbpf_1.3.0.orig.tar.gz %s %s https://127.0.0.1:9/never\n' "$(stat -c %s "$tmp/cache/a/libbpf_1.3.0.orig.tar.gz")" "$s1"
} >"$R4/distribution/native-sources.lock"
git -C "$R4" -c user.name=t -c user.email=t@example.invalid commit -qam lock
bash "$R4/scripts/fetch-native-sources.sh" --cache "$tmp/cache" "$tmp/src-ok" >/dev/null &&
  ok "sources served from a verified cache without network" || fail "cached source fetch"
bundle "$R4" "$tmp/n" "$tmp/out-src" --sources-dir "$tmp/src-ok" >/dev/null &&
  tar -tf "$tmp/out-src/bpfcompat-validator-native-sources.tar" | grep -q 'libbpf/libbpf_1.3.0.orig.tar.gz' &&
  ok "native-sources asset built from verified files" || fail "native-sources asset"
printf 'corrupted\n' >"$tmp/src-ok/libbpf/libbpf_1.3.0.orig.tar.gz"
expect_fail "native-sources asset from a corrupted file" 'does not match native-sources.lock' bundle "$R4" "$tmp/n" "$tmp/out-src2" --sources-dir "$tmp/src-ok"
mkdir -p "$tmp/badcache" && printf 'wrong bytes\n' >"$tmp/badcache/libbpf_1.3.0.orig.tar.gz"
expect_fail "cache with wrong hash and no network" 'download failed' bash "$R4/scripts/fetch-native-sources.sh" --cache "$tmp/badcache" "$tmp/src-bad"
printf 'file=libbpf x.tar.gz 1 notahash https://example.invalid/x\n' >"$tmp/badlock"
expect_fail "malformed sources lock" 'malformed lock entry' bash "$R/scripts/fetch-native-sources.sh" "$tmp/src-mal" "$tmp/badlock"
bash "$R/scripts/fetch-native-sources.sh" --cache /nonexistent "$tmp/unused" /dev/null >/dev/null 2>&1 &&
  fail "empty lock accepted" || ok "empty sources lock refused"
if awk 'index($0, "file=") == 1' "$ROOT_DIR/distribution/native-sources.lock" |
  awk 'NF != 5 || $5 !~ /^https:\/\/snapshot\.ubuntu\.com\// || $4 !~ /^[0-9a-f]{64}$/' | grep -q .; then
  fail "repository native-sources.lock has a malformed entry"
else ok "repository native-sources.lock entries are well-formed snapshot URLs"; fi

# ---------------------------------------------------------------- relink.sh
K="$tmp/x/bpfcompat-validator-relink-kit"
mkdir -p "$tmp/fakecc" "$tmp/mylibs"
cat >"$tmp/fakecc/cc" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$CC_LOG"
out=""
while [[ $# -gt 0 ]]; do [[ "$1" == -o ]] && out="$2"; shift; done
printf 'linked\n' >"$out"
EOF
chmod +x "$tmp/fakecc/cc"
CC_LOG="$tmp/cc.log" PATH="$tmp/fakecc:$PATH" bash "$K/relink.sh" --here --lib-dir "$tmp/mylibs" --out "$tmp/relinked" >/dev/null 2>&1 || true
grep -q -- "main.o -L$tmp/mylibs -o " "$tmp/cc.log" && grep -q -- "-static -lfoo" "$tmp/cc.log" &&
  ok "relink.sh puts --lib-dir ahead of the recorded libraries" || fail "relink.sh link line: $(cat "$tmp/cc.log" 2>/dev/null)"
: >"$tmp/cc.log"
if CC_LOG="$tmp/cc.log" PATH="$tmp/fakecc:$PATH" bash "$K/relink.sh" --here --out "$tmp/relinked2" >/dev/null 2>&1; then
  grep -q -- "main.o -o " "$tmp/cc.log" && ok "relink.sh --here links main.o with the recorded command" || fail "relink.sh default link line"
else fail "relink.sh --here failed"; fi

if [[ "$failures" -gt 0 ]]; then
  echo "[distribution-test] ${failures} failure(s)" >&2
  exit 1
fi
echo "distribution-bundle_test: all checks passed"
