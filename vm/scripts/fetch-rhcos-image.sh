#!/usr/bin/env bash
# Stage an operator-supplied RHEL CoreOS (OpenShift) qemu image into vm/cache/.
#
# RHCOS boot images are not published at a public cloud-image URL like Ubuntu or
# Fedora CoreOS; they ship with an OpenShift release. The operator obtains the
# qcow for their OpenShift version and points this script at it. Two inputs are
# supported (env vars):
#
#   RHCOS_IMAGE=/path/to/rhcos-qemu.x86_64.qcow2      # a local file
#   RHCOS_IMAGE_URL=https://.../rhcos-...qcow2[.gz|.xz]  # an internal mirror
#
# How to obtain the URL for a given OpenShift version (openshift-install is the
# version-pinned tool; the URLs it prints are on the public RHCOS mirror):
#
#   openshift-install coreos print-stream-json \
#     | jq -r '.architectures.x86_64.artifacts.qemu.formats["qcow2.gz"].disk.location'
#
# Then either download it yourself and pass RHCOS_IMAGE, or pass RHCOS_IMAGE_URL.
# A .gz/.xz image is decompressed automatically.
set -euo pipefail

OUT="${1:-vm/cache/rhcos-4.16.qcow2}"
SRC="${RHCOS_IMAGE:-}"
URL="${RHCOS_IMAGE_URL:-}"

if [[ -f "$OUT" ]]; then
  echo "RHCOS image already present at $OUT (delete it to restage)"
  exit 0
fi
if [[ -z "$SRC" && -z "$URL" ]]; then
  echo "error: set RHCOS_IMAGE=/path/to/image or RHCOS_IMAGE_URL=https://..." >&2
  echo "       (RHCOS images ship with an OpenShift release; see the header of" >&2
  echo "        vm/scripts/fetch-rhcos-image.sh for how to obtain one.)" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUT")"

stage() {
  # $1 = source file (possibly compressed); decompress into $OUT.
  local f="$1"
  case "$f" in
    *.gz)  echo "Decompressing gzip ..."; gzip -dc "$f" > "$OUT" ;;
    *.xz)  echo "Decompressing xz ...";   xz -dc "$f"   > "$OUT" ;;
    *)     if [[ "$f" != "$OUT" ]]; then cp "$f" "$OUT"; fi ;;
  esac
}

if [[ -n "$SRC" ]]; then
  [[ -f "$SRC" ]] || { echo "error: RHCOS_IMAGE not found: $SRC" >&2; exit 2; }
  echo "Staging local image $SRC -> $OUT"
  stage "$SRC"
else
  tmp="$OUT.download"
  echo "Downloading $URL ..."
  curl -fSL "$URL" -o "$tmp"
  # Preserve the URL's extension so stage() can pick the right decompressor.
  case "$URL" in
    *.gz) mv "$tmp" "$tmp.gz"; stage "$tmp.gz"; rm -f "$tmp.gz" ;;
    *.xz) mv "$tmp" "$tmp.xz"; stage "$tmp.xz"; rm -f "$tmp.xz" ;;
    *)    stage "$tmp"; rm -f "$tmp" ;;
  esac
fi

echo "Staged RHCOS image at $OUT"
echo "Now run with: BPFCOMPAT_ENABLE_RHCOS=1 bpfcompat test --runner vm ..."
