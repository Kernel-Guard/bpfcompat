#!/usr/bin/env bash
# Build twice from fixed source/version/time inputs; never touch the system Go.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
version="${1:?version required}"
out="${2:?absolute output directory required}"
[[ "$version" =~ ^v0\.3\.8(-rc\.[1-9][0-9]*)?$ ]]
[[ "$out" == /* ]]
test "$(go env GOVERSION)" = go1.25.14
test "$(go env GOHOSTARCH)" = amd64
commit="$(git rev-parse HEAD)"
test -z "$(git status --porcelain)"
date="$(git show -s --format=%cI HEAD)"
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export SOURCE_DATE_EPOCH
export LC_ALL=C TZ=UTC
mkdir -p "$out"
while IFS= read -r package; do
  [[ "$package" == \#* || -z "$package" ]] && continue
  name="${package%%=*}"
  expected="${package#*=}"
  test "$(dpkg-query -W -f='${Version}' "$name")" = "$expected"
done <scripts/release-native-packages.txt
compiler_flags="$(pkg-config --cflags libbpf)"
read -r -a bpf_flags <<<"$compiler_flags"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
ldflags="-buildid= -X github.com/kernel-guard/bpfcompat/internal/version.Version=$version -X github.com/kernel-guard/bpfcompat/internal/version.Commit=$commit -X github.com/kernel-guard/bpfcompat/internal/version.BuildDate=$date"
for arch in amd64 arm64; do
  for pass in 1 2; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -mod=vendor -trimpath -buildvcs=false \
      -ldflags "$ldflags" -o "$scratch/$arch-$pass" ./cmd/bpfcompat
  done
  cmp "$scratch/$arch-1" "$scratch/$arch-2"
  cp "$scratch/$arch-1" "$out/bpfcompat-linux-$arch"
done
for pass in 1 2; do
  gcc-13 -O2 -Wall -Wextra -std=c11 -ffile-prefix-map="$root"=. \
    "${bpf_flags[@]}" validator/c-libbpf/src/main.c \
    -o "$scratch/validator-$pass" -static -Wl,-t,-Bstatic -lbpf -lelf -lzstd -lz -pthread >"$scratch/link-$pass.txt"
done
cmp "$scratch/validator-1" "$scratch/validator-2"
file "$scratch/validator-1" | grep -q 'statically linked'
cp "$scratch/validator-1" "$out/bpfcompat-validator-static-linux-amd64"
python3 scripts/native-validator-sbom.py collect "$scratch/link-1.txt" \
  "$out/bpfcompat-validator-static-linux-amd64" "$out/NATIVE-LINK-INPUTS.json"
{
  printf 'commit=%s\nversion=%s\nsource_date_epoch=%s\n' "$commit" "$version" "$SOURCE_DATE_EPOCH"
  printf 'native_snapshot=%s\n' "$(<scripts/release-native-snapshot.txt)"
  go version
  gcc-13 --version
  pkg-config --modversion libbpf libelf zlib libzstd
  while IFS= read -r package; do
    [[ "$package" == \#* || -z "$package" ]] && continue
    printf '%s\n' "$package"
  done <scripts/release-native-packages.txt
} >"$out/BUILD-TOOLS.txt"
(cd "$out"; sha256sum bpfcompat-linux-amd64 bpfcompat-linux-arm64 bpfcompat-validator-static-linux-amd64 BUILD-TOOLS.txt NATIVE-LINK-INPUTS.json >SHA256SUMS)
echo '[maintenance-build] locked native versions and byte-identical repeated builds PASS; cross-runner reproduction NOT VERIFIED by this command'
