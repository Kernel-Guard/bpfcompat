#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|aarch64)
    ;;
  *)
    echo "unsupported Firecracker release architecture: ${ARCH}" >&2
    exit 2
    ;;
esac

release_url="https://github.com/firecracker-microvm/firecracker/releases"
latest="$(basename "$(curl -fsSLI -o /dev/null -w '%{url_effective}' "${release_url}/latest")")"
archive="firecracker-${latest}-${ARCH}.tgz"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

curl -fsSL "${release_url}/download/${latest}/${archive}" | tar -xz -C "$tmp_dir"

firecracker_src="$(find "$tmp_dir" -type f -name "firecracker-${latest}-${ARCH}" | head -n1)"
jailer_src="$(find "$tmp_dir" -type f -name "jailer-${latest}-${ARCH}" | head -n1)"
if [[ -z "$firecracker_src" ]]; then
  echo "downloaded Firecracker archive did not contain firecracker binary" >&2
  exit 1
fi

mkdir -p bin
install -m 0755 "$firecracker_src" bin/firecracker
if [[ -n "$jailer_src" ]]; then
  install -m 0755 "$jailer_src" bin/jailer
fi

echo "installed Firecracker ${latest} to ${ROOT_DIR}/bin/firecracker"
if [[ -x bin/jailer ]]; then
  echo "installed jailer ${latest} to ${ROOT_DIR}/bin/jailer"
fi
