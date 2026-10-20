#!/usr/bin/env bash
# Regression test: trial loads (program_variants trial probes and per-program
# isolated loads) must auto-size runtime-sized maps exactly like the
# whole-object load, and variant trial-probe libbpf output must never reach
# logs.libbpf (the classifier's input for the whole-object verdict).
#
# Runs WITHOUT loading anything into the host kernel: the validator is
# rebuilt with -Wl,--wrap so bpf_object__load / bpf_map_create /
# bpf_prog_load / libbpf_probe_bpf_helper resolve to tests/fake_load.c.
# What this proves: the validator's own control flow (which fixups run before
# each trial load, which print callback is installed, which variant is
# chosen, what lands in the JSON). What it does NOT prove: real kernel
# behaviour; that needs a VM run.
#
# Requires: cc, clang (BPF target), libbpf headers + pkg-config, jq.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/../src/main.c"
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
"$CLANG" -g -O2 -target bpf -I"$BPF_ARCH_INCLUDE" "${libbpf_cflags[@]}" -c "$here/trial_maps.bpf.c" -o "$work/trial_maps.bpf.o"

wraps="-Wl,--wrap=bpf_object__load,--wrap=bpf_map_create,--wrap=bpf_prog_load,--wrap=libbpf_probe_bpf_helper"
"$CC" -O2 -Wall -Wextra -std=c11 "${libbpf_cflags[@]}" "$src" "$here/fake_load.c" \
  -o "$work/validator" $wraps "${libbpf_libs[@]}"

fail=0
check() { # name, jq expression that must be true, json
  if jq -e "$2" "$3" >/dev/null; then
    echo "ok   - $1"
  else
    echo "FAIL - $1"
    fail=1
  fi
}

run() { # probe_features, out
  set +e
  "$work/validator" --artifact "$work/trial_maps.bpf.o" --out "$2" \
    --attach-mode disabled --probe-features "$1" \
    --prog-variants "grp=variant_preferred:trial,variant_fallback" \
    --prog-variants "rej=probe_rejected:trial,probe_rejected_fallback" >/dev/null 2>&1
  local rc=$?
  set -e
  # Exit 2 = validator ran and reported a non-pass status (the fake whole
  # load always fails); anything else is a harness failure.
  if [[ $rc -ne 2 ]]; then
    echo "FAIL - validator exited $rc (want 2)"
    exit 1
  fi
}

# Case 1: variant trial probe only (--probe-features false skips the
# per-program trial loads and every capability probe).
run false "$work/variants.json"
j="$work/variants.json"
check "trial probe auto-sizes maps, preferred variant chosen" \
  '.program_variants[0].chosen == "variant_preferred"' "$j"
check "probe map-create noise absent from logs.libbpf" \
  '(.logs.libbpf | contains("failed to create")) | not' "$j"
check "failing trial probe falls back to the next variant" \
  '.program_variants[1].chosen == "probe_rejected_fallback"' "$j"
check "failing trial probe output absent from logs.libbpf" \
  '(.logs.libbpf | contains("TRIAL-PROBE-ONLY")) | not' "$j"
check "whole-object verifier failure still in logs.libbpf" \
  '.logs.libbpf | contains("R1 invalid mem access")' "$j"
check "auto_sized_maps recorded once (whole-object load only)" \
  '[.auto_sized_maps[] | select(.name == "runtime_sized")] | length == 1' "$j"
check "whole-object load status unchanged (fail)" '.load.status == "fail"' "$j"

# Case 2: per-program isolated trial loads (--probe-features true; the
# capability probes hit the wrapped bpf_map_create/bpf_prog_load).
run true "$work/perprog.json"
j="$work/perprog.json"
check "per-program trial loads auto-size maps (all others pass)" \
  '[.discovery.programs[] | select(.name != "probe_rejected") | .load_status] | all(. == "pass")' "$j"
check "per-program diagnostics still captured for a real trial failure" \
  '.discovery.programs[] | select(.name == "probe_rejected") | .load_status == "fail" and (.load_log | contains("TRIAL-PROBE-ONLY"))' "$j"
check "per-program: no map-create failure in load_log" \
  '[.discovery.programs[].load_log | contains("failed to create")] | any | not' "$j"
check "per-program: logs.libbpf free of trial noise" \
  '(.logs.libbpf | contains("failed to create")) | not' "$j"
check "per-program: auto_sized_maps recorded once" \
  '[.auto_sized_maps[] | select(.name == "runtime_sized")] | length == 1' "$j"

if [[ $fail -ne 0 ]]; then
  echo "trial_probe_maps_test: FAIL"
  exit 1
fi
echo "trial_probe_maps_test: PASS"
