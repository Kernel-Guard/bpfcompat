#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${ROOT_DIR}/scripts/check-coverage.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin"
cat >"$tmp/bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" != "tool cover -func="* ]]; then
  exit 2
fi
printf 'total:\t(statements)\t%s%%\n' "$FIXTURE_COVERAGE"
EOF
chmod +x "$tmp/bin/go"
printf 'mode: atomic\n' >"$tmp/coverage.out"

PATH="$tmp/bin:$PATH" FIXTURE_COVERAGE=51.8 \
  bash "$script" "$tmp/coverage.out" 50.0 >"$tmp/pass.log"
grep -Fq '[coverage] PASS total=51.8% minimum=50.0%' "$tmp/pass.log"

if PATH="$tmp/bin:$PATH" FIXTURE_COVERAGE=49.9 \
  bash "$script" "$tmp/coverage.out" 50.0 >"$tmp/fail.log" 2>&1; then
  echo "[coverage-test] accepted coverage below the floor" >&2
  exit 1
fi
grep -Fq 'below required 50.0%' "$tmp/fail.log"

if PATH="$tmp/bin:$PATH" FIXTURE_COVERAGE=invalid \
  bash "$script" "$tmp/coverage.out" 50.0 >/dev/null 2>&1; then
  echo "[coverage-test] accepted invalid coverage output" >&2
  exit 1
fi

if PATH="$tmp/bin:$PATH" FIXTURE_COVERAGE=51.8 \
  bash "$script" "$tmp/coverage.out" invalid >/dev/null 2>&1; then
  echo "[coverage-test] accepted an invalid minimum" >&2
  exit 1
fi

echo "[coverage-test] PASS"
