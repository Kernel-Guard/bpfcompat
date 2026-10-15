#!/usr/bin/env bash
# Regression guard for the GitHub Action's baseline/candidate diff mode
# (scripts/action-diff.sh, issue #141).
#
# Every case runs the real `bpfcompat diff` against self-consistent reports:
# each fixture's run-level summary is computed from its own targets by the
# same rules as pkg/schema RunVerdict / RunComplete, so the differ accepts it
# as evidence and the test exercises the comparison, not the rejection path.
#
# BPFCOMPAT_BIN may point at a built binary; otherwise one is built.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/action-diff.sh"
ACTION="$ROOT/action.yml"

command -v jq >/dev/null || { echo "SKIP: jq required" >&2; exit 0; }

work="$(mktemp -d)"
trap '[[ -n "${KEEP_WORK:-}" ]] || rm -rf "$work"' EXIT

bin="${BPFCOMPAT_BIN:-}"
if [[ -z "$bin" ]]; then
  bin="$work/bpfcompat"
  (cd "$ROOT" && go build -o "$bin" ./cmd/bpfcompat)
fi

fail=0
ok() { printf 'ok:   %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

# target <id> <verdict> <required> [observed-kernel]
# Requested family is 5.15; an observed kernel outside it is a mismatch.
target() {
  local id="$1" verdict="$2" required="$3" observed="${4:-5.15.0-186-generic}"
  jq -nc --arg id "$id" --arg v "$verdict" --argjson r "$required" --arg k "$observed" '
    {COMPATIBLE: "pass", INCOMPATIBLE: "fail", INFRA_ERROR: "infra_error", UNSUPPORTED: "unsupported"}[$v] as $s |
    {profile_id: $id, required: $r, status: $s, verdict: $v,
     environment: {requested_kernel_family: "5.15", observed_kernel: $k,
                   kernel_family_match: ($k | startswith("5.15."))}}'
}

# report <file> <artifact-sha> <target-json>...
# Summary computed exactly as pkg/schema RunVerdict / RunComplete do.
report() {
  local file="$1" sha="$2"; shift 2
  printf '%s\n' "$@" | jq -s --arg sha "$sha" --arg run "$(basename "$file" .json)-$RANDOM$RANDOM" '
    # Not `// true`: jq treats false as missing there, which would read a
    # mismatch as established.
    def established: (.environment.kernel_family_match != false);
    . as $t |
    ([$t[] | select(.required)] ) as $req |
    (if any($req[]; .verdict == "INCOMPATIBLE") then "INCOMPATIBLE"
     elif any($req[]; .verdict == "INFRA_ERROR" or .verdict == "UNSUPPORTED"
                      or (.verdict == "COMPATIBLE" and (established | not))) then "INFRA_ERROR"
     else "COMPATIBLE" end) as $v |
    (all($t[]; (.verdict != "INFRA_ERROR" and .verdict != "UNSUPPORTED") and established)) as $c |
    {schema_version: "v0.1", run: {id: $run}, artifact: {sha256: $sha},
     targets: $t,
     summary: {status: ({COMPATIBLE: "pass", INCOMPATIBLE: "fail", INFRA_ERROR: "error"}[$v]),
               verdict: $v, complete: $c}}' >"$file"
}

ws="$work/ws"
mkdir -p "$ws/reports" "$ws/other"

# run_case <name> [VAR=value ...] -- runs the action script in a fresh output
# context; sets $rc, $out_file (GITHUB_OUTPUT), $sum_file (GITHUB_STEP_SUMMARY).
run_case() {
  local name="$1"; shift
  out_file="$work/$name.output"; sum_file="$work/$name.summary"
  : >"$out_file"; : >"$sum_file"
  set +e
  env -i PATH="$PATH" HOME="$HOME" \
    GITHUB_WORKSPACE="$ws" GITHUB_OUTPUT="$out_file" GITHUB_STEP_SUMMARY="$sum_file" \
    BPFCOMPAT_BIN="$bin" "$@" bash "$SCRIPT" >"$work/$name.log" 2>&1
  rc=$?
  set -e
}
output() { sed -n "s/^$1=//p" "$out_file" | tail -1; }

expect() { # <name> <want-rc> <want-result>
  local name="$1" want_rc="$2" want_result="$3" got_result
  got_result="$(output result)"
  if [[ "$rc" -eq "$want_rc" && "$got_result" == "$want_result" ]]; then
    ok "$name: exit $rc, result $got_result"
  else
    bad "$name: got exit $rc result '$got_result', want exit $want_rc result '$want_result'"
    sed 's/^/    /' "$work/$name.log" >&2
  fi
}

A=reports/base.json
report "$ws/$A" aaa "$(target ub22 COMPATIBLE true)" "$(target deb12 COMPATIBLE true)" "$(target al2 INCOMPATIBLE false)"

# 1. PASS -> PASS
report "$ws/reports/c-same.json" bbb "$(target ub22 COMPATIBLE true)" "$(target deb12 COMPATIBLE true)" "$(target al2 INCOMPATIBLE false)"
run_case pass-pass INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-same.json
expect pass-pass 0 NO_NEW_REGRESSIONS

# 2. PASS -> FAIL on a required target (different artifact bytes, as release
#    N and N+1 always are): a new regression, fails by default.
report "$ws/reports/c-regress.json" ccc "$(target ub22 INCOMPATIBLE true)" "$(target deb12 COMPATIBLE true)" "$(target al2 INCOMPATIBLE false)"
run_case pass-fail INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-regress.json
expect pass-fail 1 NEW_REGRESSIONS
[[ "$(output new-required-regressions)" == 1 ]] && ok "pass-fail: new-required-regressions=1" || bad "pass-fail: new-required-regressions output wrong"
grep -q 'NEW_REGRESSION' "$sum_file" && ok "pass-fail: step summary names NEW_REGRESSION" || bad "pass-fail: step summary does not name the regression"
run_case pass-fail-allowed INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-regress.json INPUT_FAIL_ON_REGRESSION=false
expect pass-fail-allowed 0 NEW_REGRESSIONS

# 3. FAIL -> FAIL is an existing limitation, never a regression.
report "$ws/reports/b-fail.json" aaa "$(target ub22 INCOMPATIBLE true)" "$(target deb12 COMPATIBLE true)"
report "$ws/reports/c-fail.json" bbb "$(target ub22 INCOMPATIBLE true)" "$(target deb12 COMPATIBLE true)"
run_case fail-fail INPUT_BASELINE_REPORT=reports/b-fail.json INPUT_CANDIDATE_REPORT=reports/c-fail.json
expect fail-fail 0 NO_NEW_REGRESSIONS
[[ "$(jq -r .summary.existing_incompatibilities "$ws/reports/bpfcompat-diff.json")" == 1 ]] && ok "fail-fail: counted as an existing incompatibility" || bad "fail-fail: not counted as existing"

# 4. FAIL -> PASS is a fix.
run_case fail-pass INPUT_BASELINE_REPORT=reports/b-fail.json INPUT_CANDIDATE_REPORT=reports/c-same.json
expect fail-pass 0 NO_NEW_REGRESSIONS
[[ "$(jq -r .summary.fixed "$ws/reports/bpfcompat-diff.json")" == 1 ]] && ok "fail-pass: counted as fixed" || bad "fail-pass: not counted as fixed"

# 5. PASS -> INFRA_ERROR is INCONCLUSIVE, never a regression.
report "$ws/reports/c-infra.json" bbb "$(target ub22 INFRA_ERROR true)" "$(target deb12 COMPATIBLE true)" "$(target al2 INCOMPATIBLE false)"
run_case pass-infra INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-infra.json
expect pass-infra 1 INCONCLUSIVE
[[ "$(output new-required-regressions)" == 0 && "$(output inconclusive-required)" -ge 1 ]] \
  && ok "pass-infra: infrastructure error is not reported as a regression" || bad "pass-infra: infra error leaked into regressions"
grep -q 'INCONCLUSIVE' "$sum_file" && ok "pass-infra: step summary says INCONCLUSIVE" || bad "pass-infra: summary hides the inconclusive result"
run_case pass-infra-allowed INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-infra.json INPUT_FAIL_ON_INCOMPLETE=false
expect pass-infra-allowed 0 INCONCLUSIVE

# 6. A required profile missing from the candidate is incomplete coverage.
report "$ws/reports/c-missing-profile.json" bbb "$(target deb12 COMPATIBLE true)" "$(target al2 INCOMPATIBLE false)"
run_case missing-profile INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-missing-profile.json
expect missing-profile 1 INCONCLUSIVE

# 7. A different kernel identity (the guest booted another series) cannot
#    support a claim about the requested one: inconclusive, not a regression.
report "$ws/reports/c-other-kernel.json" bbb "$(target ub22 INCOMPATIBLE true 6.12.0-107.el9uek.x86_64)" "$(target deb12 COMPATIBLE true)" "$(target al2 INCOMPATIBLE false)"
run_case other-kernel INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-other-kernel.json
if [[ "$(output new-required-regressions)" == 0 && "$rc" -eq 1 ]]; then
  ok "other-kernel: a result on a different kernel series is not a regression"
else
  bad "other-kernel: exit $rc, regressions $(output new-required-regressions)"
  sed 's/^/    /' "$work/other-kernel.log" >&2
fi

# 8. A regression together with an inconclusive cell: the regression outranks
#    it in the CLI exit code, but fail-on-incomplete must still be honoured when
#    regressions are allowed.
report "$ws/reports/c-both.json" bbb "$(target ub22 INCOMPATIBLE true)" "$(target deb12 INFRA_ERROR true)" "$(target al2 INCOMPATIBLE false)"
run_case both INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-both.json INPUT_FAIL_ON_REGRESSION=false
expect both 1 NEW_REGRESSIONS
run_case both-allowed INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-both.json INPUT_FAIL_ON_REGRESSION=false INPUT_FAIL_ON_INCOMPLETE=false
expect both-allowed 0 NEW_REGRESSIONS

# 9. Malformed input fails regardless of policy; a stale diff from an earlier
#    step must never be read as this comparison's result.
printf '{"schema_version": "v0.1", "targets": [' >"$ws/reports/malformed.json"
echo '{"schema_version":"bpfcompat.regression-diff.v0.1","summary":{"result":"NO_NEW_REGRESSIONS"}}' >"$ws/reports/bpfcompat-diff.json"
run_case malformed INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/malformed.json INPUT_FAIL_ON_INCOMPLETE=false INPUT_FAIL_ON_REGRESSION=false
expect malformed 1 INVALID_INPUT
[[ ! -e "$ws/reports/bpfcompat-diff.json" ]] && ok "malformed: the stale diff JSON was removed, not reused" || bad "malformed: a stale diff JSON survived"

# 10. Missing report file.
run_case missing-file INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/nope.json
expect missing-file 1 INVALID_INPUT

# 11. Invalid paths: escaping the workspace, a directory, and only one side set.
cp "$ws/reports/c-same.json" "$work/outside.json"
run_case escape INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=../outside.json
expect escape 1 INVALID_INPUT
run_case dir INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports
expect dir 1 INVALID_INPUT
ln -s "$work/outside.json" "$ws/reports/link.json"
run_case symlink-escape INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/link.json
expect symlink-escape 1 INVALID_INPUT
run_case one-side INPUT_BASELINE_REPORT="$A"
expect one-side 1 INVALID_INPUT
run_case out-escape INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-same.json INPUT_DIFF_OUT=../diff.json
expect out-escape 1 INVALID_INPUT

# 11b. An output that is one of the inputs -- directly or through a symlink --
#      is refused before anything is removed: the baseline is often the only
#      copy of what the last release supported.
cp "$ws/$A" "$work/base.keep"; cp "$ws/reports/c-same.json" "$work/cand.keep"
run_case out-is-baseline INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-same.json INPUT_DIFF_OUT="$A"
expect out-is-baseline 1 INVALID_INPUT
cmp -s "$ws/$A" "$work/base.keep" && ok "out-is-baseline: the baseline report is intact" || bad "out-is-baseline: the baseline report was destroyed"
ln -sf c-same.json "$ws/reports/cand-link.md"
run_case md-links-candidate INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-same.json INPUT_DIFF_MARKDOWN=reports/cand-link.md
expect md-links-candidate 1 INVALID_INPUT
cmp -s "$ws/reports/c-same.json" "$work/cand.keep" && ok "md-links-candidate: the candidate report is intact" || bad "md-links-candidate: the candidate report was destroyed"
rm -f "$ws/reports/cand-link.md"

# 11c. Output paths containing a newline would inject extra lines into
#      GITHUB_OUTPUT (e.g. a second result=); they are refused.
run_case newline-out INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-same.json INPUT_DIFF_OUT=$'reports/x\nresult=NO_NEW_REGRESSIONS'
expect newline-out 1 INVALID_INPUT


# 12. Pinned report checksums: a mismatch is refused, a match proceeds.
good_sha="$(sha256sum "$ws/reports/c-same.json" | awk '{print $1}')"
run_case sha-bad INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-same.json \
  INPUT_CANDIDATE_REPORT_SHA256=0000000000000000000000000000000000000000000000000000000000000000
expect sha-bad 1 INVALID_INPUT
run_case sha-good INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-same.json INPUT_CANDIDATE_REPORT_SHA256="$good_sha"
expect sha-good 0 NO_NEW_REGRESSIONS

# 13. Policy inputs are strict booleans.
run_case bad-bool INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-same.json INPUT_FAIL_ON_REGRESSION=yes
expect bad-bool 1 INVALID_INPUT

# 14. Step summary content and outputs.
run_case summary INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-regress.json INPUT_FAIL_ON_REGRESSION=false
if grep -q '^## bpfcompat regression diff' "$sum_file" && grep -q 'NEW_REGRESSIONS' "$sum_file" \
   && grep -q 'fail-on-regression' "$sum_file" && grep -q 'ub22' "$sum_file"; then
  ok "summary: heading, result, policy and the regressed profile are in the step summary"
else
  bad "summary: step summary incomplete"; cat "$sum_file" >&2
fi
[[ "$(output diff-json)" == "$ws/reports/bpfcompat-diff.json" && -f "$(output diff-markdown)" ]] \
  && ok "summary: diff-json and diff-markdown outputs point at the written files" || bad "summary: output paths wrong"

# 14b. Every refusal says why in the step log, not only in the summary.
for c in one-side bad-bool missing-file escape out-is-baseline; do
  if grep -q '::error title=bpfcompat diff::' "$work/$c.log"; then
    ok "$c: the reason is in the step log"
  else
    bad "$c: the step log does not say why it failed"
  fi
done

# 15. Deterministic output: two runs over the same inputs agree except for
#     the generation timestamp.
run_case det1 INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-both.json INPUT_FAIL_ON_REGRESSION=false INPUT_FAIL_ON_INCOMPLETE=false INPUT_DIFF_OUT=reports/d1.json INPUT_DIFF_MARKDOWN=reports/d1.md
run_case det2 INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-both.json INPUT_FAIL_ON_REGRESSION=false INPUT_FAIL_ON_INCOMPLETE=false INPUT_DIFF_OUT=reports/d2.json INPUT_DIFF_MARKDOWN=reports/d2.md
if [[ -s "$ws/reports/d1.json" && -s "$ws/reports/d2.json" && -s "$ws/reports/d1.md" && -s "$ws/reports/d2.md" ]] \
   && diff <(jq -S 'del(.generated_at)' "$ws/reports/d1.json") <(jq -S 'del(.generated_at)' "$ws/reports/d2.json") >/dev/null \
   && diff <(grep -v -i 'generated' "$ws/reports/d1.md") <(grep -v -i 'generated' "$ws/reports/d2.md") >/dev/null; then
  ok "determinism: JSON and Markdown are identical across runs (timestamp aside)"
else
  bad "determinism: outputs differ between identical runs"
fi

# 16. Existing consumers are unaffected: diff mode is opt-in, its inputs
#     default to empty, the policy defaults fail closed, and it refuses to be
#     mixed with the validation modes.
inputs_ok="$(python3 - "$ACTION" <<'PY'
import sys, yaml
a = yaml.safe_load(open(sys.argv[1]))
i = a["inputs"]
want = {"baseline-report": "", "candidate-report": "", "fail-on-regression": "true",
        "fail-on-incomplete": "true", "baseline-report-sha256": "", "candidate-report-sha256": ""}
bad = [k for k, v in want.items() if k not in i or str(i[k].get("default")) != v or i[k].get("required")]
for k in ("artifact", "matrix", "out", "suite", "command"):
    if k not in i or i[k].get("default") != "":
        bad.append(k)
print("ok" if not bad else "bad:" + ",".join(bad))
PY
)"
[[ "$inputs_ok" == ok ]] && ok "action.yml: diff inputs are optional with fail-closed policy defaults; existing inputs unchanged" || bad "action.yml inputs: $inputs_ok"
# Free-text diff inputs reach shell only through env, never inline
# interpolation into a run script (host-side shell injection).
inline="$(grep -nE '\$\{\{ *inputs\.(baseline-report|candidate-report|fail-on-|diff-)' "$ACTION" \
  | grep -vE '^[0-9]+: +INPUT_[A-Z0-9_]+: \$\{\{ inputs\.[a-z0-9-]+ \}\}$' \
  | grep -vE '^[0-9]+: +value: ' || true)"
[[ -z "$inline" ]] && ok "action.yml: diff inputs reach the shell only through env" || bad "action.yml interpolates diff inputs inline: $inline"
run_case mixed INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-same.json INPUT_ARTIFACT=x.bpf.o
expect mixed 1 INVALID_INPUT

# 17. require-gate through the real action.yml "Run bpfcompat" step.
#     The step is rendered the way the runner does it -- every
#     ${{ inputs.<name> }} replaced by the caller's value or the input's
#     default -- and executed with bash. Test, command and suite modes use a
#     recording stand-in binary (no VMs); diff mode runs the real binary
#     through scripts/action-diff.sh.
render_run_step() { # <out-script> <out-env> [name=value ...]
  python3 - "$ACTION" "$@" <<'PY'
import re, shlex, sys, yaml
action, script_out, env_out, *pairs = sys.argv[1:]
spec = yaml.safe_load(open(action))
given = dict(p.split("=", 1) for p in pairs)
inputs = {k: str(v.get("default", "")) for k, v in spec["inputs"].items()}
for k in given:
    if k not in inputs:
        sys.exit(f"unknown action input {k}")
inputs.update(given)
step = next(s for s in spec["runs"]["steps"] if s.get("id") == "run")
expr = re.compile(r"\$\{\{\s*inputs\.([a-z0-9-]+)\s*\}\}")
render = lambda text: expr.sub(lambda m: inputs[m.group(1)], text)
open(script_out, "w").write(render(step["run"]))
with open(env_out, "w") as f:
    for k, v in step.get("env", {}).items():
        f.write(f"{k}={shlex.quote(render(str(v)))}\n")
PY
}

fake="$work/fake-bpfcompat"
cat >"$fake" <<'SH'
#!/usr/bin/env bash
# Records its argv (one argument per line) and exits with $FAKE_EXIT.
[[ "${1:-}" == report-summary ]] && { echo "fake summary"; exit 0; }
printf '%s\n' "$@" >"$FAKE_LOG"
exit "${FAKE_EXIT:-0}"
SH
chmod +x "$fake"
mkdir -p "$ws/gate"
: >"$ws/gate/probe.bpf.o"
printf 'name: m\nprofiles:\n  - id: p\n    required: false\n' >"$ws/gate/m.yaml"
printf 'name: s\ncases:\n  - name: c\n    artifact: probe.bpf.o\n    matrix: m.yaml\n' >"$ws/gate/suite.yaml"

# run_step <name> <fake-exit> [input=value ...]: sets $rc, $argv_file.
run_step() {
  local name="$1" fexit="$2"; shift 2
  local script="$work/$name.step.sh" envf="$work/$name.step.env"
  argv_file="$work/$name.argv"; out_file="$work/$name.output"; sum_file="$work/$name.summary"
  : >"$argv_file"; : >"$out_file"; : >"$sum_file"
  if ! render_run_step "$script" "$envf" "$@"; then
    bad "$name: could not render the action's run step"
    rc=99
    return 0
  fi
  set +e
  (
    set -a; source "$envf"; set +a
    env PATH="$PATH" HOME="$HOME" GITHUB_WORKSPACE="$ws" GITHUB_ACTION_PATH="$ROOT" \
      GITHUB_OUTPUT="$out_file" GITHUB_STEP_SUMMARY="$sum_file" \
      FAKE_LOG="$argv_file" FAKE_EXIT="$fexit" bash -e "$script"
  ) >"$work/$name.log" 2>&1
  rc=$?
  set -e
}
has_flag() { grep -qx -- '--require-gate' "$argv_file"; }

test_inputs=(binary="$fake" artifact=gate/probe.bpf.o matrix=gate/m.yaml out=gate/out.json)
cmd_inputs=(binary="$fake" command='$BPFCOMPAT_BIN' matrix=gate/m.yaml out=gate/out.json)
suite_inputs=(binary="$fake" suite=gate/suite.yaml)

for mode in test cmd suite; do
  declare -n in_ref="${mode}_inputs"
  # Default (input omitted) and explicit false run the identical command.
  run_step "$mode-default" 0 "${in_ref[@]}"; cp "$argv_file" "$work/$mode-default.keep"
  if [[ "$rc" -eq 0 ]] && ! has_flag && [[ -s "$argv_file" ]]; then ok "$mode: default leaves require-gate off"; else bad "$mode: default run rc=$rc"; sed 's/^/    /' "$work/$mode-default.log" >&2; fi
  run_step "$mode-false" 0 "${in_ref[@]}" require-gate=false
  cmp -s "$argv_file" "$work/$mode-default.keep" && ok "$mode: require-gate=false is byte-identical to the default invocation" || bad "$mode: require-gate=false changed the invocation"
  # true reaches the CLI as --require-gate, and the CLI's exit is the step's.
  run_step "$mode-true" 1 "${in_ref[@]}" require-gate=true
  if [[ "$rc" -eq 1 ]] && has_flag; then ok "$mode: require-gate=true passes --require-gate and propagates its exit 1"; else bad "$mode: require-gate=true rc=$rc flag=$(has_flag && echo yes || echo no)"; fi
  run_step "$mode-true-2" 2 "${in_ref[@]}" require-gate=true
  [[ "$rc" -eq 2 ]] && ok "$mode: a required failure still exits 2 under require-gate" || bad "$mode: required failure rc=$rc"
  # Strict boolean, refused before the CLI runs.
  run_step "$mode-bad" 0 "${in_ref[@]}" require-gate=yes
  if [[ "$rc" -eq 1 && ! -s "$argv_file" ]] && grep -q 'require-gate must be true or false' "$work/$mode-bad.log"; then
    ok "$mode: require-gate=yes is refused before running"
  else
    bad "$mode: require-gate=yes rc=$rc"
  fi
  unset -n in_ref
done

# Diff mode through the real step and the real binary: two optional-only
# reports, optional target COMPATIBLE -> INCOMPATIBLE.
report "$ws/reports/g-base.json" aaa "$(target al2 COMPATIBLE false)"
report "$ws/reports/g-cand.json" bbb "$(target al2 INCOMPATIBLE false)"
diff_inputs=(binary="$bin" baseline-report=reports/g-base.json candidate-report=reports/g-cand.json)
run_step diff-default 0 "${diff_inputs[@]}"
expect diff-default 0 NO_NEW_REGRESSIONS
[[ "$(output gate)" == none ]] && ok "diff-default: diff-gate output is none" || bad "diff-default: gate output '$(output gate)'"
run_step diff-require 0 "${diff_inputs[@]}" require-gate=true
expect diff-require 1 NO_NEW_REGRESSIONS
grep -q 'diagnostic diff, not a gate, and require-gate is true' "$work/diff-require.log" && ok "diff-require: the step log says why" || bad "diff-require: no reason in the log"
run_step diff-require-gated 0 binary="$bin" baseline-report="$A" candidate-report=reports/c-same.json require-gate=true
expect diff-require-gated 0 NO_NEW_REGRESSIONS
run_step diff-bad-bool 0 "${diff_inputs[@]}" require-gate=1
expect diff-bad-bool 1 INVALID_INPUT

# Missing gate evidence never passes require-gate: a diff JSON without
# summary.gate (an older binary) is treated as no gate.
nogate="$work/nogate-bpfcompat"
cat >"$nogate" <<SH
#!/usr/bin/env bash
"$bin" "\$@"; st=\$?
for a in "\$@"; do [[ "\$prev" == --out ]] && out="\$a"; prev="\$a"; done
[[ -n "\${out:-}" && -f "\$out" ]] && jq 'del(.summary.gate)' "\$out" >"\$out.tmp" && mv "\$out.tmp" "\$out"
exit \$st
SH
chmod +x "$nogate"
run_case diff-nogate INPUT_BASELINE_REPORT="$A" INPUT_CANDIDATE_REPORT=reports/c-same.json INPUT_REQUIRE_GATE=true BPFCOMPAT_BIN="$nogate"
expect diff-nogate 1 NO_NEW_REGRESSIONS

# The new input is opt-in and reaches the shell only through env.
inline_gate="$(grep -nE '\$\{\{ *inputs\.require-gate' "$ACTION" | grep -vE '^[0-9]+: +INPUT_REQUIRE_GATE: \$\{\{ inputs\.require-gate \}\}$' || true)"
[[ -z "$inline_gate" ]] && ok "action.yml: require-gate reaches the shell only through env" || bad "action.yml interpolates require-gate inline: $inline_gate"
python3 - "$ACTION" <<'PY' && ok "action.yml: require-gate is optional and defaults to false" || bad "action.yml: require-gate default is not false"
import sys, yaml
i = yaml.safe_load(open(sys.argv[1]))["inputs"]["require-gate"]
sys.exit(0 if str(i.get("default")) == "false" and not i.get("required") else 1)
PY

if [[ "$fail" -ne 0 ]]; then
  echo "action-diff_test: FAILED" >&2
  exit 1
fi
echo "action-diff_test: all checks passed"
