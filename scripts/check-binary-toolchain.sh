#!/usr/bin/env bash
# Prove which Go toolchain compiled each binary.
#
#   check-binary-toolchain.sh <goX.Y.Z> <binary> [<binary> ...]
#
# go.mod's `go` directive is only a minimum; automatic toolchain switching,
# a preinstalled runner Go or a builder image decides what actually compiles.
# The stdlib that ships inside a binary is the one from that toolchain, so a
# security toolchain bump is only real once every shipped binary says so.
# This reads the build info Go embeds in every binary (`go version <file>`),
# which survives `-s -w -buildid=` stripping.
#
# Exit 0: every binary was built by exactly <goX.Y.Z>. Exit 1: any binary is
# missing, is not a Go binary, or was built by another toolchain. Exit 2: usage.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <goX.Y.Z> <binary> [<binary> ...]" >&2
  exit 2
fi
expected="$1"
shift
if [[ ! "$expected" =~ ^go[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "check-binary-toolchain: expected toolchain must look like go1.26.9, got '$expected'" >&2
  exit 2
fi
command -v go >/dev/null || { echo "check-binary-toolchain: go is required to read build info" >&2; exit 2; }

fail=0
for bin in "$@"; do
  if [[ ! -f "$bin" ]]; then
    echo "::error::$bin does not exist"
    fail=1
    continue
  fi
  # `go version <file>` prints "<file>: goX.Y.Z" for Go binaries and fails
  # (or prints nothing useful) for anything else.
  if ! line="$(GOTOOLCHAIN=local go version "$bin" 2>/dev/null)"; then
    echo "::error::$bin has no Go build info (not a Go binary?)"
    fail=1
    continue
  fi
  actual="${line##*: }"
  actual="${actual%% *}"
  if [[ "$actual" == "$expected" ]]; then
    echo "$bin: compiled by $actual"
  else
    echo "::error::$bin was compiled by '${actual:-unknown}', expected $expected"
    fail=1
  fi
done
exit "$fail"
