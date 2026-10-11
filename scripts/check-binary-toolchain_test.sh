#!/usr/bin/env bash
# Regression guard for scripts/check-binary-toolchain.sh.
#
# A go.mod `go` directive only states a minimum; the toolchain that actually
# compiled a shipped binary is what carries (or fixes) stdlib vulnerabilities.
# The check reads the build info Go embeds in every binary -- it survives
# `-s -w -buildid=` -- and must:
#   1. accept a binary compiled by exactly the expected toolchain;
#   2. reject a binary compiled by any other toolchain;
#   3. reject a file that is not a Go binary (no build info) instead of passing;
#   4. reject a missing file and a malformed expectation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/check-binary-toolchain.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cat >"$work/main.go" <<'GO'
package main

func main() {}
GO
printf 'module example.invalid/probe\n\ngo 1.21\n' >"$work/go.mod"
# Build with the same stripping flags as the release/Dockerfile builds.
(cd "$work" && GOFLAGS='' GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -buildid=' -o probe .)
actual="$(GOTOOLCHAIN=local go env GOVERSION)"

fail=0
expect() { # name want_rc args...
  local name="$1" want="$2"; shift 2
  local rc=0
  bash "$SCRIPT" "$@" >"$work/out.txt" 2>&1 || rc=$?
  if [[ "$rc" -eq "$want" ]]; then
    printf 'ok:   %s (rc=%s)\n' "$name" "$rc"
  else
    printf 'FAIL: %s (rc=%s want %s)\n' "$name" "$rc" "$want" >&2
    cat "$work/out.txt" >&2
    fail=1
  fi
}

expect "binary built by the expected toolchain is accepted" 0 "$actual" "$work/probe"
expect "binary built by another toolchain is rejected" 1 "go1.0.0" "$work/probe"
printf 'not a go binary\n' >"$work/plain"
expect "non-Go file is rejected, not passed" 1 "$actual" "$work/plain"
expect "missing file is rejected" 1 "$actual" "$work/does-not-exist"
expect "malformed expectation is a usage error" 2 "1.26.9" "$work/probe"
expect "no binaries is a usage error" 2 "$actual"

if [[ "$fail" -ne 0 ]]; then
  echo "check-binary-toolchain_test: FAILED" >&2
  exit 1
fi
echo "check-binary-toolchain_test: all checks passed"
