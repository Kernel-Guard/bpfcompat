#!/usr/bin/env bash
# Relink the bpfcompat validator from this kit's main.o.
#
#   ./relink.sh [--lib-dir <dir>] [--out <file>] [--here]
#
# Default: runs the link inside the digest-pinned builder image named in
# build/build-inputs.lock, with exactly the locked package versions from its
# fixed snapshot.ubuntu.com state (needs docker and network access), using the
# link command recorded in build/commands.txt. Without --lib-dir the result
# must be byte-identical to the shipped validator (build/validator-build-inputs.json
# sha256), which shows this kit describes that binary.
#
# --lib-dir <dir>: static archives in <dir> (e.g. a modified libelf.a) are
#   searched before the system ones (-L<dir>), so the validator is linked
#   against them instead. The result then differs from the shipped binary.
# --here: use the current machine's compiler and libraries instead of the
#   pinned builder. Byte-identity is then only expected if they are the
#   locked versions.
# --out <file>: where to write the relinked binary (default ./bpfcompat-validator).
set -euo pipefail

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lib_dir=""
out="$PWD/bpfcompat-validator"
here=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lib-dir) lib_dir="$(cd "$2" && pwd)"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --here) here=1; shift ;;
    --inside) shift; break ;;
    *) echo "usage: $0 [--lib-dir <dir>] [--out <file>] [--here]" >&2; exit 2 ;;
  esac
done
lock="$KIT/build/build-inputs.lock"
expected="$(sed -nE 's/.*"sha256": *"([0-9a-f]{64})".*/\1/p' "$KIT/build/validator-build-inputs.json" | head -1)"
# The link line recorded by the build, with its output renamed.
link="$(sed -n '$p' "$KIT/build/commands.txt")"
[[ "$link" == *" main.o -o bpfcompat-validator.relinked "* ]] || { echo "relink: unexpected build/commands.txt" >&2; exit 1; }

do_link() { # <workdir> <libdir or empty> <output>
  local wd="$1" ld="$2" o="$3" cmd
  cmd="${link/ main.o -o bpfcompat-validator.relinked / main.o -o $o }"
  [[ -z "$ld" ]] || cmd="${cmd/ main.o / main.o -L$ld }"
  (cd "$wd" && eval "$cmd")
}

if [[ "${INSIDE:-0}" == "1" ]]; then
  # In the builder: install the locked packages from the snapshot, then link.
  rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
  rm -rf /var/lib/apt/lists/*
  ca=""
  [[ -s /etc/bpfcompat-snapshot-ca.crt ]] && ca=/etc/bpfcompat-snapshot-ca.crt
  BPFCOMPAT_VALIDATOR_LOCK=/kit/build/build-inputs.lock bash /kit/tools/build-validator-pinned.sh --render-apt-config /etc/apt $ca
  apt-get update -qq --error-on=any
  mapfile -t pkgs < <(awk 'index($0, "pkg=") == 1 { print substr($0, 5) }' /kit/build/build-inputs.lock)
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${pkgs[@]}" >/dev/null
  mkdir -p /work && cp /kit/main.o /work/
  do_link /work "${LIBDIR:-}" /work/bpfcompat-validator
  cp /work/bpfcompat-validator /out/bpfcompat-validator
  chown "$(stat -c %u:%g /out)" /out/bpfcompat-validator
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if [[ "$here" == "1" ]]; then
  cp "$KIT/main.o" "$tmp/"
  do_link "$tmp" "$lib_dir" "$tmp/bpfcompat-validator"
else
  command -v docker >/dev/null || { echo "relink: docker is required (or use --here)" >&2; exit 2; }
  image="$(awk -F= '$1 == "builder_image" { print $2 }' "$lock")"
  mounts=(-v "$KIT:/kit:ro" -v "$tmp:/out")
  [[ -z "$lib_dir" ]] || mounts+=(-v "$lib_dir:/libs:ro")
  ca="${BPFCOMPAT_SNAPSHOT_CA_BUNDLE-/etc/ssl/certs/ca-certificates.crt}"
  [[ -n "$ca" && -s "$ca" ]] && mounts+=(-v "$(readlink -f "$ca"):/etc/bpfcompat-snapshot-ca.crt:ro")
  docker run --rm "${mounts[@]}" -e INSIDE=1 -e LIBDIR="$([[ -n "$lib_dir" ]] && echo /libs)" \
    "$image" bash /kit/relink.sh --inside
fi
install -m 0755 "$tmp/bpfcompat-validator" "$out"
have="$(sha256sum "$out" | cut -d' ' -f1)"
if [[ -z "$lib_dir" && "$here" == "0" ]]; then
  if [[ "$have" != "$expected" ]]; then
    echo "relink: $out is $have, not the shipped validator $expected" >&2
    exit 1
  fi
  echo "relink: $out is byte-identical to the shipped validator ($have)"
else
  echo "relink: wrote $out ($have); shipped validator is $expected"
fi
