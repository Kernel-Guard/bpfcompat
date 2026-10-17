#!/usr/bin/env bash
# End-to-end injection regression for the composite action's `Run bpfcompat`
# step.
#
# It renders the real action.yml step the way the Actions runner does --
# `${{ inputs.X }}` substituted as plain text into `run:` and evaluated into
# `env:` values -- then executes the rendered script with bash against a stub
# bpfcompat binary that records its argv. Every input is given, one at a time,
# hostile values (quote breakout, $(...), backticks, newline) that would
# create a PWNED marker file if any shell ever parsed them as code.
#
# Each case must: create no marker, reach the binary, and hand it the hostile
# value byte-for-byte. Hermetic: no network, no VM, no real bpfcompat.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="${1:-$ROOT/action.yml}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 - "$ACTION" "$tmp" <<'PY'
import os
import re
import shutil
import subprocess
import sys

import yaml

action_path, tmp = sys.argv[1], sys.argv[2]
with open(action_path, encoding="utf-8") as fh:
    action = yaml.safe_load(fh)
defaults = {k: str(v.get("default", "")) for k, v in action["inputs"].items()}
step = next(s for s in action["runs"]["steps"] if s.get("id") == "run")

EXPR = re.compile(r"\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}")
# Outputs of the prebuilt step render empty here: these cases model a run with
# no resolved prebuilt binaries (scripts/action-validator-pin_test.sh covers
# the resolved path).
STEP_OUTPUT = re.compile(r"\$\{\{\s*steps\.prebuilt\.outputs\.[A-Za-z0-9_-]+\s*\}\}")


def render(text, inputs):
    out = EXPR.sub(lambda m: inputs.get(m.group(1), ""), text)
    out = STEP_OUTPUT.sub("", out)
    if "${{" in out:
        raise SystemExit(f"unrenderable expression left in: {out!r}")
    return out


# Payloads deliberately contain no "/" so a file can carry the same name and
# path-valued inputs still reach the binary. Each would `touch PWNED*` in
# whatever directory the shell is in if it were ever executed.
PAYLOADS = [
    'x"; touch PWNED_q; : "',
    "$(touch PWNED_s)",
    "`touch PWNED_b`",
    "x\ntouch PWNED_n",  # no trailing newline: $(...) strips it from any path
    "x' ; touch PWNED_sq ; '",
]

STUB = """#!/usr/bin/env bash
printf '%s\\0' "$@" >"$ARGV_LOG"
exit 0
"""

# input -> (how to set up the case, flag the binary must receive)
#   kind "file":   the value names a file in the workspace (resolved path)
#   kind "dir":    the value is a path the step creates/forwards (resolved)
#   kind "plain":  the value is forwarded verbatim
#   kind "binary": the value names the executable stub itself
CASES = {
    "artifact": ("file", "--artifact"),
    "matrix": ("file", "--matrix"),
    "manifest": ("dir", "--manifest"),
    "out": ("dir", "--out"),
    "markdown": ("dir", "--markdown"),
    "workdir": ("dir", "--workdir"),
    "timeout": ("plain", "--timeout"),
    "concurrency": ("plain", "--concurrency"),
    "disk-resize": ("plain", "--disk-resize"),
    "validation-mode": ("plain", "--validation-mode"),
    "command": ("plain", "--command"),
    "command-expect-exit": ("plain", "--command-expect-exit"),
    "command-binary": ("file", "--command-binary"),
    "binary": ("binary", None),
    "suite": ("file", "--suite"),
    "suite-out": ("dir", "--out"),
    "suite-markdown": ("dir", "--markdown"),
    "keep-vm-on-failure": ("bool", None),
}

failures = []
n = 0
for name, (kind, flag) in CASES.items():
    for payload in PAYLOADS:
        n += 1
        case = os.path.join(tmp, f"c{n}")
        ws, root = os.path.join(case, "ws"), os.path.join(case, "action")
        os.makedirs(os.path.join(root, "bin"))
        os.makedirs(ws)
        stub = os.path.join(root, "bin", "bpfcompat")
        with open(stub, "w") as fh:
            fh.write(STUB)
        os.chmod(stub, 0o755)
        with open(os.path.join(ws, "matrix.yaml"), "w") as fh:
            fh.write("targets: []\n")

        inputs = dict(defaults)
        inputs.update({"artifact": "probe.bpf.o", "matrix": "matrix.yaml",
                       "out": "reports/out.json", "binary": "bin/bpfcompat"})
        open(os.path.join(ws, "probe.bpf.o"), "w").close()
        if name.startswith("command"):
            inputs["artifact"] = ""
            inputs["command"] = "true"
        if name.startswith("suite"):
            inputs["suite"] = "suite.yaml"
            open(os.path.join(ws, "suite.yaml"), "w").close()
        inputs[name] = payload
        if kind == "file":
            open(os.path.join(ws, payload), "w").close()
        elif kind == "binary":
            shutil.copy(stub, os.path.join(ws, payload))
            os.chmod(os.path.join(ws, payload), 0o755)

        argv_log = os.path.join(case, "argv")
        script = os.path.join(case, "run.sh")
        with open(script, "w") as fh:
            fh.write(render(step["run"], inputs))
        env = {"PATH": os.environ["PATH"], "HOME": case,
               "GITHUB_WORKSPACE": ws, "GITHUB_ACTION_PATH": root,
               "GITHUB_OUTPUT": os.path.join(case, "gh_output"),
               "ARGV_LOG": argv_log}
        for key, val in (step.get("env") or {}).items():
            env[key] = render(str(val), inputs)
        res = subprocess.run(["bash", script], cwd=ws, env=env,
                             capture_output=True, text=True, timeout=60)

        label = f"{name}={payload!r}"
        pwned = [os.path.join(d, f) for d, _, fs in os.walk(case)
                 for f in fs if f.startswith("PWNED")]
        if pwned:
            failures.append(f"{label}: COMMAND EXECUTED -> {pwned}")
            continue
        if res.returncode != 0 or not os.path.exists(argv_log):
            failures.append(f"{label}: step did not reach the binary "
                            f"(rc={res.returncode}): {res.stderr.strip()[-300:]}")
            continue
        with open(argv_log, "rb") as fh:
            argv = fh.read().split(b"\0")[:-1]
        argv = [a.decode() for a in argv]

        if kind == "bool":
            if "--keep-vm-on-failure=true" in argv:
                failures.append(f"{label}: non-'true' value enabled keep-vm")
            continue
        if kind == "binary":
            continue  # reaching the stub under its hostile name is the proof
        want = payload if kind == "plain" else os.path.join(ws, payload)
        if flag not in argv or argv[argv.index(flag) + 1] != want:
            failures.append(f"{label}: {flag} not forwarded verbatim; argv={argv}")

if failures:
    for f in failures:
        print(f"FAIL: {f}", file=sys.stderr)
    print(f"action input-injection regression: {len(failures)}/{n} cases FAILED",
          file=sys.stderr)
    sys.exit(1)
print(f"action input-injection regression: all {n} hostile cases inert and forwarded verbatim")
PY
