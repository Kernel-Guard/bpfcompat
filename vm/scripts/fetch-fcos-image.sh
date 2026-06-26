#!/usr/bin/env bash
# Fetch the current Fedora CoreOS stable qemu image into vm/cache/.
#
# FCOS images are distributed as versioned, xz-compressed qcow2 files referenced
# from the stable stream metadata (there is no stable "latest.qcow2" URL), so we
# resolve the build from the stream JSON, verify the published sha256 of the .xz,
# then decompress. This stages vm/cache/fedora-coreos-stable.qcow2, which the
# fedora-coreos-stable-7.0 profile loads.
set -euo pipefail

OUT="${1:-vm/cache/fedora-coreos-stable.qcow2}"
STREAM_URL="https://builds.coreos.fedoraproject.org/streams/stable.json"

if [[ -f "$OUT" ]]; then
  echo "FCOS image already present at $OUT (delete it to refetch)"
  exit 0
fi

mkdir -p "$(dirname "$OUT")"

echo "Resolving FCOS stable qemu image from $STREAM_URL ..."
read -r URL SHA < <(curl -fsSL "$STREAM_URL" | python3 -c '
import sys, json
d = json.load(sys.stdin)
a = d["architectures"]["x86_64"]["artifacts"]["qemu"]["formats"]["qcow2.xz"]["disk"]
print(a["location"], a.get("sha256", ""))
')
echo "  url: $URL"

tmp_xz="$OUT.xz"
echo "Downloading ..."
curl -fsSL "$URL" -o "$tmp_xz"

if [[ -n "$SHA" ]]; then
  echo "Verifying sha256 ..."
  echo "$SHA  $tmp_xz" | sha256sum -c -
fi

echo "Decompressing ..."
xz -d -T0 "$tmp_xz"
echo "Staged $OUT"
