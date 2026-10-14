#!/usr/bin/env bash
# Regression tests for the validator's handling of untrusted input:
#  - ELF-derived strings (program/section/map names) must reach result.json
#    as valid UTF-8 JSON, with invalid bytes replaced by U+FFFD and valid
#    multi-byte UTF-8 kept as-is;
#  - --set-map-max-entries values with leading zeros must apply exactly the
#    number the caller asked for.
#
# Runs WITHOUT loading anything into the host kernel: the validator is
# rebuilt with -Wl,--wrap so bpf_object__load / bpf_map_create /
# bpf_prog_load / libbpf_probe_bpf_helper / bpf_program__attach resolve to
# tests/input_handling_fake_load.c. What this proves: the validator's own
# parsing and JSON output. What it does NOT prove: real kernel behaviour.
#
# Requires: cc, clang (BPF target), libbpf headers + pkg-config, jq, python3.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="${VALIDATOR_SRC:-$here/../src/main.c}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

CC="${CC:-cc}"
CLANG="${CLANG:-clang}"
# shellcheck disable=SC2207
libbpf_cflags=($(pkg-config --cflags libbpf))
# shellcheck disable=SC2207
libbpf_libs=($(pkg-config --libs libbpf libelf zlib))

# <linux/bpf.h> needs the host multiarch <asm/types.h>.
BPF_ARCH_INCLUDE="${BPF_ARCH_INCLUDE:-/usr/include/$("$CC" -print-multiarch 2>/dev/null || echo x86_64-linux-gnu)}"
"$CLANG" -g -O2 -target bpf -I"$BPF_ARCH_INCLUDE" "${libbpf_cflags[@]}" \
  -c "$here/input_handling.bpf.c" -o "$work/input_handling.bpf.o"

wraps="-Wl,--wrap=bpf_object__load,--wrap=bpf_map_create,--wrap=bpf_prog_load,--wrap=libbpf_probe_bpf_helper,--wrap=bpf_program__attach"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror -std=c11 "${libbpf_cflags[@]}" "$src" "$here/input_handling_fake_load.c" \
  -o "$work/validator" $wraps "${libbpf_libs[@]}"

obj="$work/input_handling.bpf.o"
fail=0
check() { # name, jq expression that must be true, json
  if jq -e "$2" "$3" >/dev/null 2>&1; then
    echo "ok   - $1"
  else
    echo "FAIL - $1"
    fail=1
  fi
}

run() { # want_rc, out, extra args...
  local want="$1" out="$2"
  shift 2
  set +e
  "$work/validator" --artifact "$obj" --out "$out" --attach-mode disabled \
    --probe-features false "$@" >/dev/null 2>"$out.stderr"
  local rc=$?
  set -e
  if [[ $rc -ne $want ]]; then
    echo "FAIL - validator exited $rc (want $want)"
    sed 's/^/    /' "$out.stderr"
    fail=1
  fi
}

# --- ELF-derived strings must be emitted as valid UTF-8 JSON ---------------
j="$work/names.json"
run 0 "$j"
if python3 -I - "$j" <<'EOF'; then
import json, sys
raw = open(sys.argv[1], "rb").read()
doc = json.loads(raw.decode("utf-8"))  # strict: invalid UTF-8 raises
R = "�"
want_p1 = 'p"\\\n\x01\x1f\x7f' + R + "(" + R * 3 + R * 2 + "-é€\U0001F600-" + R * 2
progs = {p["section"]: p for p in doc["discovery"]["programs"]}
names = sorted(p["name"] for p in doc["discovery"]["programs"])
assert names == sorted([want_p1, "p2"]), names
assert 'socket","status":"pass","x":"\\\n\tQQ' in progs, list(progs)
assert doc["status"] == "pass", doc["status"]
assert doc["load"]["status"] == "pass", doc["load"]
want_map = 'm"},{"name":"INJ\\\x01' + R * 2 + "\n"
auto = sorted(m["name"] for m in doc["auto_sized_maps"])
assert auto == sorted([want_map, "runtime_sized"]), auto
EOF
  echo "ok   - result.json is strict UTF-8 JSON; invalid bytes -> U+FFFD, valid UTF-8 and status kept"
else
  echo "FAIL - result.json is strict UTF-8 JSON; invalid bytes -> U+FFFD, valid UTF-8 and status kept"
  fail=1
fi

# --- --set-map-max-entries must apply the parsed number exactly -----------
# The Go manifest side (strconv.ParseUint) accepts leading zeros, so these
# reach the validator verbatim; the value must not be cut to the 16-byte
# text field it used to be stored in.
for spec in "100000:100000" "0000000000100000:100000" "0000000000000001:1" "000000000004294967295:4294967295"; do
  in="${spec%%:*}" want="${spec##*:}"
  j="$work/maxent-$in.json"
  run 0 "$j" --set-map-max-entries "runtime_sized=$in"
  check "max_entries=$in applied as $want" \
    ".map_fixups[0] | .status == \"applied\" and .applied_entries == $want and .max_entries == \"$want\"" "$j"
  check "max_entries=$in: runtime_sized not auto-sized" \
    '[.auto_sized_maps[] | select(.name == "runtime_sized")] | length == 0' "$j"
done
j="$work/maxent-cpus.json"
run 0 "$j" --set-map-max-entries "runtime_sized=cpus"
check "max_entries=cpus still resolves to the CPU count" \
  '.map_fixups[0] | .status == "applied" and .max_entries == "cpus" and .applied_entries > 0' "$j"

if [[ $fail -ne 0 ]]; then
  echo "input_handling_test: FAIL"
  exit 1
fi
echo "input_handling_test: PASS"
