#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
# Local-only generated-lane profiles (kernelorg-*, firecracker-*) are
# gitignored. A page generated where they exist must not differ from CI.
planted="$root/vm/profiles/kernelorg-zz-support-matrix-test.yaml"
trap 'rm -rf "$tmp" "$planted"' EXIT
for locale in C C.UTF-8 en_US.UTF-8; do
  LC_ALL="$locale" BPFCOMPAT_SUPPORT_MATRIX_OUT="$tmp/$locale.md" bash "$root/scripts/support-matrix.sh" >/dev/null
  if [[ "$locale" != C ]]; then cmp "$tmp/C.md" "$tmp/$locale.md"; fi
done
echo '[support-matrix-test] identical generated documentation across locales PASS'

git -C "$root" check-ignore -q "$planted"
printf 'id: kernelorg-zz-support-matrix-test\ndistro: upstream-mainline\nversion: lts\nkernel_family: "6.1"\nrunner: virtme-ng\n' >"$planted"
BPFCOMPAT_SUPPORT_MATRIX_OUT="$tmp/planted.md" bash "$root/scripts/support-matrix.sh" >/dev/null
if grep -q kernelorg-zz-support-matrix-test "$tmp/planted.md" || ! cmp -s "$tmp/C.md" "$tmp/planted.md"; then
  echo '[support-matrix-test] FAIL: an untracked local profile changed the generated page' >&2
  exit 1
fi
echo '[support-matrix-test] untracked local profiles are ignored PASS'
