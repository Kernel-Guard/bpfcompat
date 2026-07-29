#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="${ROOT_DIR}/scripts/check-release-state.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "api" ]]
case "${FAKE_RELEASE_STATE:-}" in
  public)
    printf 'false\n'
    ;;
  draft)
    printf 'true\n'
    ;;
  absent)
    echo "gh: Not Found (HTTP 404)" >&2
    exit 1
    ;;
  error)
    echo "gh: upstream unavailable (HTTP 500)" >&2
    exit 1
    ;;
  *)
    exit 2
    ;;
esac
EOF
chmod 0700 "$tmp/gh"

if FAKE_RELEASE_STATE=public PATH="$tmp:$PATH" \
  bash "$checker" Kernel-Guard/bpfcompat v1.2.3 >/dev/null 2>&1; then
  echo "public release unexpectedly allowed mutation" >&2
  exit 1
fi

FAKE_RELEASE_STATE=draft PATH="$tmp:$PATH" \
  bash "$checker" Kernel-Guard/bpfcompat v1.2.3 >/dev/null
FAKE_RELEASE_STATE=absent PATH="$tmp:$PATH" \
  bash "$checker" Kernel-Guard/bpfcompat v1.2.3 >/dev/null

if FAKE_RELEASE_STATE=error PATH="$tmp:$PATH" \
  bash "$checker" Kernel-Guard/bpfcompat v1.2.3 >/dev/null 2>&1; then
  echo "release lookup error did not fail closed" >&2
  exit 1
fi

echo "[release-state-test] PASS"
