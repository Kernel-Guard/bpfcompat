#!/usr/bin/env bash
# Prove from the binary which build inputs a static validator was linked with.
#
#   check-validator-build-inputs.sh <validator-binary> [<build-inputs.lock>]
#
# The validator links distro libbpf statically and carries no version stamp of
# its own, so the only trustworthy record of what shipped is the binary. This
# reads it with readelf/nm/objdump (it is never executed) and requires:
#   - a static x86-64 executable (no PT_INTERP, no DT_NEEDED);
#   - libbpf_major_version()/libbpf_minor_version() returning the lock's
#     expect_libbpf (e.g. 1.3), i.e. the libbpf that was actually linked;
#   - the .comment compiler record equal to the lock's expect_gcc_comment.
#
# Exit 0: the binary matches the declared inputs. Exit 1: drift or not a static
# validator. Exit 2: usage, bad lock or missing tools.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <validator-binary> [<build-inputs.lock>]" >&2
  exit 2
fi
bin="$1"
lock="${2:-$ROOT/validator/build-inputs.lock}"
for tool in readelf nm objdump awk; do
  command -v "$tool" >/dev/null || { echo "check-validator-build-inputs: $tool is required" >&2; exit 2; }
done
[[ -f "$lock" ]] || { echo "check-validator-build-inputs: lock $lock not found" >&2; exit 2; }

# Exactly one `key=value` line, value printed verbatim.
lock_value() {
  awk -v key="$1" 'index($0, key "=") == 1 { v = substr($0, length(key) + 2); n++ }
    END { if (n == 1) print v; exit n == 1 ? 0 : 1 }' "$lock"
}
expect_libbpf="$(lock_value expect_libbpf)" ||
  { echo "check-validator-build-inputs: lock needs exactly one expect_libbpf" >&2; exit 2; }
expect_gcc="$(lock_value expect_gcc_comment)" ||
  { echo "check-validator-build-inputs: lock needs exactly one expect_gcc_comment" >&2; exit 2; }
[[ "$expect_libbpf" =~ ^[0-9]+\.[0-9]+$ ]] ||
  { echo "check-validator-build-inputs: expect_libbpf must look like 1.3, got '$expect_libbpf'" >&2; exit 2; }

fail=0
err() { echo "::error::$bin: $*"; fail=1; }

if [[ ! -f "$bin" ]]; then
  echo "::error::$bin does not exist"
  exit 1
fi
if ! header="$(readelf -h "$bin" 2>/dev/null)"; then
  echo "::error::$bin is not an ELF file"
  exit 1
fi
grep -q 'Advanced Micro Devices X86-64' <<<"$header" || err "not an x86-64 ELF"
if readelf -l "$bin" 2>/dev/null | grep -q 'INTERP'; then
  err "has a PT_INTERP (dynamically linked); the shipped validator must be static"
fi
if readelf -d "$bin" 2>/dev/null | grep -q 'NEEDED'; then
  err "has DT_NEEDED entries; the shipped validator must be static"
fi

# The constant a libbpf version accessor returns: its `mov $0xN,%eax`.
accessor_value() {
  local sym="$1" addr hex
  addr="$(nm "$bin" 2>/dev/null | awk -v s="$sym" '$3 == s && ($2 == "T" || $2 == "t") { print $1; exit }')"
  [[ -n "$addr" ]] || return 1
  hex="$(objdump -d --start-address="0x$addr" --stop-address="$(printf '0x%x' $((16#$addr + 16)))" "$bin" 2>/dev/null |
    awk 'match($0, /mov[l]? +\$0x[0-9a-f]+,%eax/) { s = substr($0, RSTART, RLENGTH); sub(/.*\$0x/, "", s); sub(/,.*/, "", s); print s; exit }')"
  [[ -n "$hex" ]] || return 1
  echo $((16#$hex))
}
if major="$(accessor_value libbpf_major_version)" && minor="$(accessor_value libbpf_minor_version)"; then
  actual_libbpf="${major}.${minor}"
  if [[ "$actual_libbpf" == "$expect_libbpf" ]]; then
    echo "$bin: links libbpf $actual_libbpf"
  else
    err "links libbpf $actual_libbpf, the lock declares $expect_libbpf"
  fi
else
  err "libbpf_major_version/libbpf_minor_version not found; cannot prove the linked libbpf"
fi

comment="$(readelf -p .comment "$bin" 2>/dev/null | awk '/^ *\[ *[0-9a-f]+\]/ { sub(/^ *\[ *[0-9a-f]+\] +/, ""); print }' | sort -u)"
if [[ -z "$comment" ]]; then
  err "no .comment compiler record"
elif [[ "$comment" == "$expect_gcc" ]]; then
  echo "$bin: compiled by $expect_gcc"
else
  err "compiler record '$(printf '%s' "$comment" | tr '\n' ';')' differs from the lock's '$expect_gcc'"
fi

exit "$fail"
