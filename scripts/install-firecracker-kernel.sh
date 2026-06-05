#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|aarch64)
    ;;
  *)
    echo "unsupported Firecracker CI kernel architecture: ${ARCH}" >&2
    exit 2
    ;;
esac

OUT_DIR="${BPFCOMPAT_FIRECRACKER_ASSET_DIR:-.bpfcompat/firecracker-assets}"
S3_LIST_BASE="${BPFCOMPAT_FIRECRACKER_CI_LIST_BASE:-http://spec.ccfc.min.s3.amazonaws.com/}"
S3_DOWNLOAD_BASE="${BPFCOMPAT_FIRECRACKER_CI_DOWNLOAD_BASE:-https://s3.amazonaws.com/spec.ccfc.min}"
mkdir -p "$OUT_DIR"

if [[ "${BPFCOMPAT_FIRECRACKER_FORCE_DOWNLOAD:-0}" != "1" ]]; then
  cached_kernel="$(find "$OUT_DIR" -maxdepth 1 -type f -name 'vmlinux-*' ! -name '*.gz' ! -name '*.debug' ! -name '*.config' ! -name '*.id' ! -name '*.map' 2>/dev/null | sort -V | tail -n1 || true)"
  if [[ -n "$cached_kernel" ]]; then
    ln -sf "$(basename "$cached_kernel")" "${OUT_DIR}/vmlinux-current"
    echo "using cached Firecracker CI kernel $(basename "$cached_kernel")"
    echo "$ROOT_DIR/$cached_kernel"
    exit 0
  fi
fi

versions=()
if [[ -n "${BPFCOMPAT_FIRECRACKER_CI_VERSIONS:-}" ]]; then
  read -r -a versions <<<"${BPFCOMPAT_FIRECRACKER_CI_VERSIONS}"
else
  for minor in 16 15 14 13 12; do
    versions+=("v1.${minor}")
  done
fi

find_kernel_key() {
  local version="$1"
  local prefix="firecracker-ci/${version}/${ARCH}/debug/vmlinux-"
  curl -fsSL --connect-timeout 10 --max-time 30 "${S3_LIST_BASE}?prefix=${prefix}" |
    grep -oE '<Key>firecracker-ci/[^<]*vmlinux-[^<]+</Key>' |
    sed -E 's#^<Key>(.*)</Key>$#\1#' |
    grep -E '/vmlinux-[0-9][0-9A-Za-z._-]*$' |
    grep -vE '(\.debug|\.gz|\.id|\.map|\.config)$' |
    sort -V |
    tail -n1
}

selected_key=""
selected_version=""
for version in "${versions[@]}"; do
  key="$(find_kernel_key "$version" || true)"
  if [[ -n "$key" ]]; then
    selected_key="$key"
    selected_version="$version"
    break
  fi
done

if [[ -z "$selected_key" ]]; then
  echo "no Firecracker CI kernel found for ${ARCH}; tried: ${versions[*]}" >&2
  exit 1
fi

kernel_name="$(basename "$selected_key")"
out_path="${OUT_DIR}/${kernel_name}"
if [[ ! -f "$out_path" ]]; then
  curl -fL --retry 2 --connect-timeout 10 --max-time 300 "${S3_DOWNLOAD_BASE}/${selected_key}" -o "$out_path"
  chmod 0644 "$out_path"
fi

ln -sf "$kernel_name" "${OUT_DIR}/vmlinux-current"

echo "installed Firecracker CI kernel ${kernel_name} from ${selected_version}"
echo "$ROOT_DIR/$out_path"
