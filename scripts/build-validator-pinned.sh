#!/usr/bin/env bash
# Build the shipped static validator from declared, pinned inputs.
#
#   build-validator-pinned.sh <out-binary> <out-build-inputs.json>
#
# The validator statically links distro libbpf/libelf/zlib/zstd/glibc, so the
# runner image used to decide its bytes. This builds it inside the lock's
# digest-pinned builder_image with exactly the lock's package versions (apt
# fails closed if one is unavailable), checks the installed versions, builds
# `make validator-static`'s recipe, proves the binary's libbpf/compiler with
# check-validator-build-inputs.sh, and writes a JSON record of every input.
#
# If validator/c-libbpf is the tree named on the lock's `reproduces=` line, the
# result must be byte-identical to the recorded sha256 (a reproducibility gate:
# same sources + same inputs = same bytes). Otherwise it reports the new
# sha256 so the lock line can be updated together with a new release candidate.
#
# Env: BPFCOMPAT_VALIDATOR_LOCK overrides the lock path (tests).
# Exit 0: built and verified. Exit 1: drift or build failure. Exit 2: usage.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="${BPFCOMPAT_VALIDATOR_LOCK:-$ROOT/validator/build-inputs.lock}"

lock_value() {
  awk -v key="$1" 'index($0, key "=") == 1 { v = substr($0, length(key) + 2); n++ }
    END { if (n == 1) print v; exit n == 1 ? 0 : 1 }' "$LOCK"
}
lock_pkgs() {
  awk 'index($0, "pkg=") == 1 { print substr($0, 5) }' "$LOCK"
}

validate_lock() {
  [[ -f "$LOCK" ]] || { echo "build-validator-pinned: lock $LOCK not found" >&2; return 2; }
  local image pkgs line
  image="$(lock_value builder_image)" ||
    { echo "build-validator-pinned: lock needs exactly one builder_image" >&2; return 2; }
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] ||
    { echo "build-validator-pinned: builder_image must be pinned by @sha256 digest, got '$image'" >&2; return 2; }
  pkgs="$(lock_pkgs)"
  [[ -n "$pkgs" ]] || { echo "build-validator-pinned: lock declares no pkg= lines" >&2; return 2; }
  while IFS= read -r line; do
    [[ "$line" =~ ^[a-z0-9][a-z0-9.+-]*=[A-Za-z0-9.+:~-]+$ ]] ||
      { echo "build-validator-pinned: pkg line must be name=exact-version, got '$line'" >&2; return 2; }
  done <<<"$pkgs"
  # Everything that ends up inside the static binary, plus the compiler.
  local required
  for required in libbpf-dev libelf-dev zlib1g-dev libzstd-dev libc6-dev binutils 'gcc-[0-9]+'; do
    grep -Eq "^${required}=" <<<"$pkgs" ||
      { echo "build-validator-pinned: lock must pin ${required}" >&2; return 2; }
  done
}

# --check-lock: validate the lock's shape only (CI regression test).
if [[ "${1:-}" == "--check-lock" ]]; then
  validate_lock
  reproduces="$(lock_value reproduces)" ||
    { echo "build-validator-pinned: lock needs exactly one reproduces= line" >&2; exit 2; }
  [[ "$reproduces" =~ ^[0-9a-f]{40}\ [0-9a-f]{64}$ ]] ||
    { echo "build-validator-pinned: reproduces= must be '<40-hex tree> <64-hex sha256>'" >&2; exit 2; }
  echo "build-validator-pinned: lock $LOCK is well-formed"
  exit 0
fi

# --inside: runs in the builder container. /src is the read-only repo, /out the
# output directory. Installs the exact packages, verifies them, builds.
if [[ "${1:-}" == "--inside" ]]; then
  validate_lock
  export DEBIAN_FRONTEND=noninteractive
  mapfile -t pkgs < <(lock_pkgs)
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends make "${pkgs[@]}" >/dev/null
  : >/out/installed.txt
  for spec in "${pkgs[@]}"; do
    name="${spec%%=*}"
    want="${spec#*=}"
    have="$(dpkg-query -W -f '${Version}' "$name" 2>/dev/null || true)"
    if [[ "$have" != "$want" ]]; then
      echo "::error::builder has $name=${have:-<none>}, the lock declares $want" >&2
      exit 1
    fi
    echo "$name=$have" >>/out/installed.txt
  done
  mkdir -p /build/validator
  cp -r /src/validator/c-libbpf /build/validator/c-libbpf
  # Same recipe as `make validator-static` in the top-level Makefile.
  make -C /build/validator/c-libbpf clean all LIBBPF_LINK_MODE=static
  cp /build/validator/c-libbpf/bin/bpfcompat-validator /out/bpfcompat-validator
  exit 0
fi

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <out-binary> <out-build-inputs.json>" >&2
  exit 2
fi
out_bin="$1"
out_json="$2"
validate_lock
for tool in docker jq git sha256sum; do
  command -v "$tool" >/dev/null || { echo "build-validator-pinned: $tool is required" >&2; exit 2; }
done

image="$(lock_value builder_image)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

docker run --rm --pull=missing \
  -v "$ROOT:/src:ro" -v "$work:/out" -v "$(cd "$(dirname "$LOCK")" && pwd)/$(basename "$LOCK"):/build-inputs.lock:ro" \
  -e BPFCOMPAT_VALIDATOR_LOCK=/build-inputs.lock \
  "$image" bash /src/scripts/build-validator-pinned.sh --inside

bash "$ROOT/scripts/check-validator-build-inputs.sh" "$work/bpfcompat-validator" "$LOCK"

sha="$(sha256sum "$work/bpfcompat-validator" | awk '{print $1}')"
tree="$(git -C "$ROOT" rev-parse HEAD:validator/c-libbpf)"
dirty="$(git -C "$ROOT" status --porcelain -- validator/c-libbpf)"
reproduces="$(lock_value reproduces || true)"
known_tree="${reproduces%% *}"
known_sha="${reproduces##* }"
reproduction="unrecorded"
if [[ -n "$reproduces" && -z "$dirty" && "$tree" == "$known_tree" ]]; then
  if [[ "$sha" == "$known_sha" ]]; then
    reproduction="byte-identical"
    echo "validator: byte-identical to the recorded build of tree $tree ($sha)"
  else
    echo "::error::validator tree $tree is the recorded one but built $sha, not the recorded $known_sha; a build input drifted" >&2
    exit 1
  fi
else
  echo "::notice::validator tree $tree${dirty:+ (modified)} has no recorded reproduction; built $sha. Record it on the lock's reproduces= line with the next release candidate."
fi

mkdir -p "$(dirname "$out_bin")" "$(dirname "$out_json")"
cp "$work/bpfcompat-validator" "$out_bin"
jq -n \
  --arg image "$image" \
  --arg tree "$tree" \
  --arg sha "$sha" \
  --arg reproduction "$reproduction" \
  --arg lock_sha "$(sha256sum "$LOCK" | awk '{print $1}')" \
  --rawfile installed "$work/installed.txt" '
  {
    schema_version: "v0.1",
    artifact: "bpfcompat-validator-static-linux-amd64",
    sha256: $sha,
    validator_tree: $tree,
    builder_image: $image,
    build_inputs_lock_sha256: $lock_sha,
    packages: ($installed | split("\n") | map(select(length > 0))),
    reproduction: $reproduction
  }' >"$out_json"
echo "validator: $out_bin ($sha), inputs recorded in $out_json"
