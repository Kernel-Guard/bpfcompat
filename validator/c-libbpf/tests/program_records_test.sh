#!/usr/bin/env bash
# Regression test for the validator's per-program record and link tables:
#  - an object with more programs than the old 64-entry tables (70) gets a
#    record, a per-program trial load and a kept-alive link for every
#    program: no link is destroyed before the functional tests run, and
#    every link is destroyed afterwards;
#  - an object above MAX_PROGRAM_RECORDS (1030 > 1024) stops its records at
#    the bound and says so (attach.records, attach.records_bound), while
#    every whole-object count and every link still covers all programs.
#
# Runs WITHOUT root and WITHOUT loading anything into the host kernel: the
# validator is rebuilt with -Wl,--wrap so bpf_object__load / bpf_map_create /
# bpf_prog_load / libbpf_probe_bpf_helper / bpf_program__attach /
# bpf_link__destroy resolve to tests/runtime_fake_load.c. What this proves:
# the validator's own bookkeeping, table sizing and link lifetime. What it
# does NOT prove: real kernel load/attach behaviour (fd limits, per-
# tracepoint program limits); that needs a VM run with
# examples/attach-coverage/many_programs.bpf.c.
#
# Requires: cc, clang (BPF target), libbpf headers + pkg-config, jq.
# VALIDATOR_SANITIZE=1 builds the validator with ASan/UBSan (LeakSanitizer
# then also checks that the record and link tables are released).
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
san=()
if [[ "${VALIDATOR_SANITIZE:-0}" == "1" ]]; then
  san=(-g "-fsanitize=address,undefined" -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
fi

gen_fixture() { # count, out.c
  {
    echo '#include <linux/bpf.h>'
    echo '#include <bpf/bpf_helpers.h>'
    local i
    for ((i = 0; i < $1; i++)); do
      echo "SEC(\"tracepoint/syscalls/sys_enter_fake$i\") int prog_$i(void *ctx) { return 0; }"
    done
    echo 'char LICENSE[] SEC("license") = "GPL";'
  } >"$2"
}
BPF_ARCH_INCLUDE="${BPF_ARCH_INCLUDE:-/usr/include/$("$CC" -print-multiarch 2>/dev/null || echo x86_64-linux-gnu)}"
for n in 70 1030; do
  gen_fixture "$n" "$work/progs$n.bpf.c"
  "$CLANG" -O2 -target bpf -I"$BPF_ARCH_INCLUDE" "${libbpf_cflags[@]}" \
    -c "$work/progs$n.bpf.c" -o "$work/progs$n.bpf.o"
done

wraps="-Wl,--wrap=bpf_object__load,--wrap=bpf_map_create,--wrap=bpf_prog_load,--wrap=libbpf_probe_bpf_helper,--wrap=bpf_program__attach,--wrap=bpf_link__destroy"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror -std=c11 "${san[@]}" "${libbpf_cflags[@]}" "$src" \
  "$here/runtime_fake_load.c" -o "$work/validator" $wraps "${libbpf_libs[@]}"

fail=0
pass() { echo "ok   - $1"; }
flunk() { echo "FAIL - $1"; fail=1; }
check() { # name, jq expression that must be true, json
  if jq -e "$2" "$3" >/dev/null 2>&1; then pass "$1"; else flunk "$1"; fi
}

# Runs the validator on progs<n>.bpf.o with a functional test that counts
# link destructions while the links should still be alive.
run_many() { # n, probe_features
  local n="$1" links="$work/links$1.log"
  : >"$links"
  # shellcheck disable=SC2016 # $(grep ...) runs later, in the functional test
  printf 'functional_plan.v0.1\nBEGIN\nname=links-alive\ncommand=echo destroyed=$(grep -c destroy %s)\ntimeout_seconds=10\nexpect_exit_code=0\nexpect_stdout_contains=destroyed=0\nEND\n' \
    "$links" >"$work/many$n.plan"
  local rc=0
  set +e
  FAKE_LINK_LOG="$links" "$work/validator" --artifact "$work/progs$n.bpf.o" --out "$work/many$n.json" \
    --probe-features "$2" --functional-plan "$work/many$n.plan" >/dev/null 2>"$work/many$n.stderr"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    pass "$n programs: validator exited 0"
  else
    flunk "$n programs: validator exited $rc (want 0)"
    sed 's/^/    /' "$work/many$n.stderr" | head -20
  fi
  local destroyed attached
  destroyed=$(grep -c destroy "$links" || true)
  attached=$(grep -c attach "$links" || true)
  if [[ "$attached" == "$n" && "$destroyed" == "$n" ]]; then
    pass "$n programs: $n links attached, all $n destroyed after the run"
  else
    flunk "$n programs: attached=$attached destroyed=$destroyed (want $n/$n)"
  fi
  check "$n programs: no link destroyed before the functional test ran" \
    '.functional.status == "pass" and (.functional.tests[0].stdout_tail | contains("destroyed=0"))' "$work/many$n.json"
}

# --- 70 programs: past the old 64-entry tables, below the bound ----------
run_many 70 true
j="$work/many70.json"
check "70 programs: a record for every program" \
  '.discovery.program_count == 70 and (.discovery.programs | length) == 70 and ([.discovery.programs[].name] | unique | length) == 70' "$j"
check "70 programs: records not truncated, bound stated" \
  '.attach.program_count == 70 and .attach.records == 70 and .attach.records_bound == 1024' "$j"
check "70 programs: every program has a per-program trial load result" \
  '[.discovery.programs[] | select(.load_status == "pass")] | length == 70' "$j"
check "70 programs: every program attached and reported as attached" \
  '.attach.status == "pass" and .attach.attempted == 70 and .attach.passed == 70 and .attach.failed == 0 and ([.discovery.programs[] | select(.attach_status == "pass" and .attach_outcome == "attached")] | length == 70)' \
  "$j"

# --- 1030 programs: above MAX_PROGRAM_RECORDS ------------------------------
run_many 1030 true
j="$work/many1030.json"
check "1030 programs: records stop at the bound" \
  '.discovery.program_count == 1030 and (.discovery.programs | length) == 1024 and ([.discovery.programs[].name] | unique | length) == 1024' "$j"
check "1030 programs: truncation is stated, counts cover the whole object" \
  '.attach.program_count == 1030 and .attach.records == 1024 and .attach.records_bound == 1024 and .attach.selected == 1030 and .attach.attachable == 1030' "$j"
check "1030 programs: a trial load result for every record, none past the bound" \
  '[.discovery.programs[] | select(.load_status == "pass")] | length == 1024' "$j"
check "1030 programs: every program attached, including those past the bound" \
  '.attach.status == "pass" and .attach.attempted == 1030 and .attach.passed == 1030 and .attach.failed == 0 and ([.discovery.programs[] | select(.attach_outcome == "attached")] | length == 1024)' \
  "$j"

if grep -l -E "AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:" "$work"/*.stderr >/dev/null 2>&1; then
  flunk "sanitizer reports in validator stderr"
  grep -h -E -A3 "AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:" "$work"/*.stderr | head -40
fi

if [[ $fail -ne 0 ]]; then
  echo "program_records_test: FAIL"
  exit 1
fi
echo "program_records_test: PASS"
