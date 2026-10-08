#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
for locale in C C.UTF-8 en_US.UTF-8; do
  LC_ALL="$locale" BPFCOMPAT_SUPPORT_MATRIX_OUT="$tmp/$locale.md" bash "$root/scripts/support-matrix.sh" >/dev/null
  if [[ "$locale" != C ]]; then cmp "$tmp/C.md" "$tmp/$locale.md"; fi
done
echo '[support-matrix-test] identical generated documentation across locales PASS'
