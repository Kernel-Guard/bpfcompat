#!/usr/bin/env bash
# Regression tests for the validator's runtime limits:
#  - functional-test timeouts must hold even when the command leaves
#    descendants holding stdout/stderr open (foreground grandchild,
#    pipeline, background job, process escaped into its own session), and
#    background stragglers must not outlive the test;
#  - objects with more than 64 programs must be reported, trial-loaded and
#    kept attached in full; functional tests beyond the plan cap must be
#    reported, not silently dropped;
#  - --log-dir must never be interpreted by a shell and must not be
#    silently truncated;
#  - a result.json that cannot be written completely must make the
#    validator exit non-zero instead of leaving a truncated file behind.
#
# Runs WITHOUT root and WITHOUT loading anything into the host kernel: the
# validator is rebuilt with -Wl,--wrap so bpf_object__load / bpf_map_create /
# bpf_prog_load / libbpf_probe_bpf_helper / bpf_program__attach /
# bpf_link__destroy resolve to tests/runtime_fake_load.c. What this proves:
# the validator's own process, bookkeeping and output handling. What it does
# NOT prove: real kernel load/attach behaviour; that needs a VM run.
#
# Requires: cc, clang (BPF target), libbpf headers + pkg-config, jq, setsid.
# VALIDATOR_SANITIZE=1 builds the validator with ASan/UBSan.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="${VALIDATOR_SRC:-$here/../src/main.c}"
work="$(mktemp -d)"
# Unique sleep durations so leftover processes can be identified exactly.
tag_fg="8.47311"
tag_pipe="8.47312"
tag_bg="8.47313"
tag_escape="8.47314"
cleanup() {
  local t
  for t in "$tag_fg" "$tag_pipe" "$tag_bg" "$tag_escape"; do
    pkill -KILL -f "sleep $t" 2>/dev/null || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

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

# Fixtures: one auto-attachable program, and 70 of them (> the old 64 cap).
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
for n in 1 70; do
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
expect_rc() { # want, name
  if [[ $rc -eq $1 ]]; then pass "$2: validator exited $1"; else flunk "$2: validator exited $rc (want $1)"; fi
}
check() { # name, jq expression that must be true, json
  if jq -e "$2" "$3" >/dev/null 2>&1; then pass "$1"; else flunk "$1"; fi
}

rc=0
elapsed_ms=0
run() { # out, args...
  local out="$1" start end
  shift
  start=$(date +%s%N)
  set +e
  "$work/validator" --artifact "$work/progs1.bpf.o" --out "$out" "$@" >"$out.stdout" 2>"$out.stderr"
  rc=$?
  set -e
  end=$(date +%s%N)
  elapsed_ms=$(((end - start) / 1000000))
}

plan() { # file, name, command, timeout, expect_exit, expect_stdout
  printf 'functional_plan.v0.1\nBEGIN\nname=%s\ncommand=%s\ntimeout_seconds=%s\nexpect_exit_code=%s\nexpect_stdout_contains=%s\nEND\n' \
    "$2" "$3" "$4" "$5" "$6" >"$1"
}

alive() { pgrep -f "sleep $1" >/dev/null 2>&1; }

# --- VAL-2: functional timeout is enforced on the whole command ----------
fn_case() { # name, command, want_rc, want jq, max_ms
  local j="$work/fn-$1.json"
  plan "$work/fn-$1.plan" "$1" "$2" 1 0 started
  run "$j" --probe-features false --functional-plan "$work/fn-$1.plan"
  if [[ $rc -ne $3 ]]; then
    flunk "$1: validator exited $rc (want $3)"
    sed 's/^/    /' "$j.stderr"
  fi
  check "$1: $4" "$4" "$j"
  if ((elapsed_ms <= $5)); then
    pass "$1: returned in ${elapsed_ms}ms (<= $5ms, timeout_seconds=1)"
  else
    flunk "$1: returned in ${elapsed_ms}ms (want <= $5ms, timeout_seconds=1)"
  fi
}
timed_out='.functional.tests[0] | .status == "fail" and .timed_out == true and .exit_code == 124'
fn_case fg-grandchild "sleep $tag_fg; echo started" 2 "$timed_out" 4000
fn_case pipeline "sleep $tag_pipe | cat" 2 "$timed_out" 4000
fn_case bg-straggler "sleep $tag_bg & echo started" 0 \
  '.functional.tests[0] | .status == "pass" and .timed_out == false and (.stdout_tail | contains("started"))' 4000
if alive "$tag_bg"; then
  flunk "bg-straggler: background process survived the functional test"
else
  pass "bg-straggler: background process killed with the command's process group"
fi
# The escapee signals readiness only after setsid() and sh waits for it, so
# it has really left the group before sh exits (otherwise the group kill
# may take it down first and the case would pass instead of timing out).
ready="$work/escape-ready"
fn_case escaped-session \
  "setsid sh -c 'touch $ready; exec sleep $tag_escape' & while [ ! -e $ready ]; do sleep 0.05; done; echo started" \
  2 "$timed_out" 4000
check "escaped-session: error names the escaped process" \
  '.functional.tests[0].error | contains("outside its process group")' "$work/fn-escaped-session.json"
for t in "$tag_fg" "$tag_pipe"; do
  if alive "$t"; then flunk "timed-out command left 'sleep $t' running"; else pass "timed-out command 'sleep $t' killed"; fi
done

# Control: a well-behaved command keeps its exit code and output.
plan "$work/fn-ok.plan" ok 'echo started; echo oops >&2; exit 3' 5 3 started
run "$work/fn-ok.json" --probe-features false --functional-plan "$work/fn-ok.plan"
check "ok: exit code and both output tails kept" \
  '.status == "pass" and (.functional.tests[0] | .status == "pass" and .exit_code == 3 and .timed_out == false and (.stdout_tail | contains("started")) and (.stderr_tail | contains("oops")))' \
  "$work/fn-ok.json"

# --- VAL-3: no silent 64-item caps ---------------------------------------
links="$work/links.log"
: >"$links"
plan "$work/many.plan" links-alive "echo destroyed=\$(grep -c destroy $links)" 10 0 "destroyed=0"
set +e
FAKE_LINK_LOG="$links" "$work/validator" --artifact "$work/progs70.bpf.o" --out "$work/many.json" \
  --probe-features true --functional-plan "$work/many.plan" >/dev/null 2>"$work/many.stderr"
rc=$?
set -e
expect_rc 0 "70 programs"
check "70 programs: discovery lists every program" \
  '.discovery.program_count == 70 and (.discovery.programs | length) == 70' "$work/many.json"
check "70 programs: every program has a per-program trial load result" \
  '[.discovery.programs[] | select(.load_status == "pass")] | length == 70' "$work/many.json"
check "70 programs: every program reports attach pass" \
  '.attach.status == "pass" and .attach.passed == 70 and ([.discovery.programs[] | select(.attach_status == "pass")] | length == 70)' \
  "$work/many.json"
check "70 programs: no link destroyed before the functional test ran" \
  '.functional.status == "pass" and (.functional.tests[0].stdout_tail | contains("destroyed=0"))' "$work/many.json"
destroyed=$(grep -c destroy "$links" || true)
attached=$(grep -c attach "$links" || true)
if [[ "$attached" == 70 && "$destroyed" == 70 ]]; then
  pass "70 programs: 70 links attached, all 70 destroyed after the run"
else
  flunk "70 programs: attached=$attached destroyed=$destroyed (want 70/70)"
fi

# Functional tests beyond the plan cap must be reported, not dropped.
{
  echo functional_plan.v0.1
  for ((i = 0; i < 65; i++)); do printf 'BEGIN\nname=t%d\ncommand=true\nEND\n' "$i"; done
} >"$work/cap.plan"
run "$work/cap.json" --probe-features false --functional-plan "$work/cap.plan"
check "65 functional tests: overflow reported and fails the plan" \
  '.status == "fail" and .functional.status == "fail" and .functional.truncated == true and .functional.dropped_tests == 1 and (.functional.tests | length) == 64' \
  "$work/cap.json"
expect_rc 2 "65 functional tests"

# --- VAL-4: --log-dir is never passed through a shell --------------------
mkdir -p "$work/fakebin" "$work/inj"
printf '#!/bin/sh\necho "{\\"fake_bpftool\\":true,\\"argv\\":\\"$*\\"}"\n' >"$work/fakebin/bpftool"
chmod +x "$work/fakebin/bpftool"
logdir='d;touch PWNED;#'
mkdir -p "$work/inj/$logdir"
set +e
(cd "$work/inj" && PATH="$work/fakebin:$PATH" "$work/validator" --artifact "$work/progs1.bpf.o" \
  --out "$work/inj.json" --log-dir "$logdir" --attach-mode disabled >/dev/null 2>&1)
rc=$?
set -e
expect_rc 0 "log-dir metacharacters"
if [[ -e "$work/inj/PWNED" ]]; then
  flunk "log-dir metacharacters: shell command injected via --log-dir was executed"
else
  pass "log-dir metacharacters: nothing executed from --log-dir"
fi
check "log-dir metacharacters: bpftool probe ran with fixed argv" \
  '.capabilities.bpftool_available == true and .capabilities.bpftool_probe_ok == true' "$work/inj.json"
if jq -e '.fake_bpftool == true and .argv == "feature probe -j kernel"' \
  "$work/inj/$logdir/bpftool-feature-kernel.json" >/dev/null 2>&1; then
  pass "log-dir metacharacters: probe output written inside --log-dir"
else
  flunk "log-dir metacharacters: probe output missing from --log-dir"
fi

mkdir -p "$work/emptybin" "$work/nobpftool-logs"
set +e
PATH="$work/emptybin" "$work/validator" --artifact "$work/progs1.bpf.o" --out "$work/nobpftool.json" \
  --log-dir "$work/nobpftool-logs" --attach-mode disabled >/dev/null 2>&1
set -e
check "bpftool absent from PATH: reported unavailable, not probed" \
  '.capabilities.bpftool_available == false and .capabilities.bpftool_probe_ok == false' "$work/nobpftool.json"

# A bpftool in the current directory must never run (the validator runs as
# root): empty PATH entries and relative entries are not searched.
mkdir -p "$work/cwd/bin" "$work/cwd-logs"
marker="$work/cwd-bpftool-ran"
# Absolute touch: the PATH under test has no usable system directories.
printf '#!/bin/sh\n%s %s\necho "{}"\n' "$(command -v touch)" "$marker" >"$work/cwd/bpftool"
cp "$work/cwd/bpftool" "$work/cwd/bin/bpftool"
chmod +x "$work/cwd/bpftool" "$work/cwd/bin/bpftool"
for p in "/nonexistent:" ":/nonexistent" "/nonexistent::/nonexistent" "bin" "." "./bin:/nonexistent"; do
  rm -f "$marker"
  set +e
  (cd "$work/cwd" && PATH="$p" "$work/validator" --artifact "$work/progs1.bpf.o" --out "$work/cwd.json" \
    --log-dir "$work/cwd-logs" --attach-mode disabled >/dev/null 2>&1)
  set -e
  if [[ -e "$marker" ]]; then
    flunk "PATH='$p': bpftool from the current directory was executed"
  else
    pass "PATH='$p': bpftool from the current directory not executed"
  fi
  check "PATH='$p': relative/empty PATH entry not treated as bpftool location" \
    '.capabilities.bpftool_available == false' "$work/cwd.json"
done

long="$work/long"
for ((i = 0; i < 6; i++)); do long="$long/$(printf 'x%.0s' {1..200})"; done
mkdir -p "$long"
run "$work/long.json" --log-dir "$long" --attach-mode disabled
if [[ $rc -eq 1 ]] && grep -q -- "--log-dir is too long" "$work/long.json.stderr"; then
  pass "over-long --log-dir rejected instead of silently truncated"
else
  flunk "over-long --log-dir: validator exited $rc (want 1 with a --log-dir error)"
fi

# --- VAL-5: an incomplete result.json is an error ------------------------
mkdir -p "$work/full"
set +e
(trap '' XFSZ; ulimit -f 1; exec "$work/validator" --artifact "$work/progs1.bpf.o" \
  --out "$work/full/result.json" --attach-mode disabled --probe-features false) >/dev/null 2>"$work/full.stderr"
rc=$?
set -e
if [[ $rc -ne 0 && $rc -ne 2 ]]; then
  pass "write failure: validator exited $rc"
else
  flunk "write failure: validator exited $rc (want a hard error, not a verdict)"
fi
left="$(find "$work/full" -mindepth 1 -printf '%f ')"
if [[ -z "$left" ]]; then
  pass "write failure: no partial result.json or temp file left behind"
else
  flunk "write failure: left behind: $left"
fi

if grep -l -E "AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:" "$work"/*.stderr >/dev/null 2>&1; then
  flunk "sanitizer reports in validator stderr"
  grep -h -E -A3 "AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:" "$work"/*.stderr | head -40
fi

if [[ $fail -ne 0 ]]; then
  echo "runtime_limits_test: FAIL"
  exit 1
fi
echo "runtime_limits_test: PASS"
