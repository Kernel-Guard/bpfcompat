#!/usr/bin/env bash
# Regression for the composite action's validator identity (F4a) and its
# source-build fallback warnings (F4b).
#
# It renders the real action.yml "Download prebuilt binaries" and
# "Run bpfcompat" steps the way the Actions runner does and executes them with
# bash against stubs (curl, gh, uname, verify-release-assets.sh, bpfcompat).
# Hermetic: no network, no VM, no real release assets.
#
# Contract checked:
#   - When the prebuilt release assets were downloaded and verified, the run
#     step points the CLI at exactly that validator (BPFCOMPAT_VALIDATOR_BIN)
#     and pins its verified digest (BPFCOMPAT_VALIDATOR_SHA256), so a
#     validator installed elsewhere on the runner (/usr/local/libexec,
#     /usr/libexec) cannot be selected instead.
#   - A caller that sets BPFCOMPAT_VALIDATOR_BIN or BPFCOMPAT_VALIDATOR_SHA256
#     itself keeps its settings unchanged, and the run says (::warning::) that
#     it is not pinned to the attested release validator.
#   - When an action pinned to a release falls back to a source build, the
#     fallback is a ::warning:: annotation, not a plain log line. A ref that
#     is not a release keeps its documented, unannotated source build.
#   - Without resolved prebuilt binaries the run step does not invent a pin.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="${1:-$ROOT/action.yml}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 - "$ACTION" "$tmp" <<'PY'
import hashlib
import os
import re
import subprocess
import sys

import yaml

action_path, tmp = sys.argv[1], sys.argv[2]
with open(action_path, encoding="utf-8") as fh:
    action = yaml.safe_load(fh)
defaults = {k: str(v.get("default", "")) for k, v in action["inputs"].items()}
steps = action["runs"]["steps"]
prebuilt = next(s for s in steps if s.get("id") == "prebuilt")
run_step = next(s for s in steps if s.get("id") == "run")

INPUT_EXPR = re.compile(r"\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}")
OUTPUT_EXPR = re.compile(r"\$\{\{\s*steps\.prebuilt\.outputs\.([A-Za-z0-9_-]+)\s*\}\}")
GITHUB_EXPR = re.compile(r"\$\{\{\s*github\.([A-Za-z0-9_]+)\s*\}\}")


def render(text, inputs, outputs, github):
    out = INPUT_EXPR.sub(lambda m: inputs.get(m.group(1), ""), text)
    out = OUTPUT_EXPR.sub(lambda m: outputs.get(m.group(1), ""), out)
    out = GITHUB_EXPR.sub(lambda m: github.get(m.group(1), ""), out)
    if "${{" in out:
        raise SystemExit(f"unrenderable expression left in: {out!r}")
    return out


def write_exec(path, body):
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o755)


VALIDATOR_BYTES = b"release-validator-bytes\n"
CLI_BYTES = b"#!/usr/bin/env bash\nexit 0\n"
VALIDATOR_SHA = hashlib.sha256(VALIDATOR_BYTES).hexdigest()
TAG_COMMIT = "a" * 40


def run_prebuilt(case, ref, curl_fail="", gh_ok=True, machine="x86_64", sums_sha=VALIDATOR_SHA):
    """Execute the prebuilt step; return (rc, stdout+stderr, outputs dict, action_root)."""
    root = os.path.join(case, "action")
    os.makedirs(os.path.join(root, "scripts"))
    write_exec(os.path.join(root, "scripts", "verify-release-assets.sh"),
               "#!/usr/bin/env bash\nexit 0\n")
    stubs = os.path.join(case, "stubs")
    os.makedirs(stubs)
    # curl: serve release assets and the tags API from fixtures.
    write_exec(os.path.join(stubs, "curl"), f"""#!/usr/bin/env bash
out=""; url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -H|--retry|--connect-timeout|--max-time) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
name="${{url##*/}}"
if [[ -n "{curl_fail}" && "$name" == "{curl_fail}" ]]; then exit 22; fi
case "$url" in
  */tags\\?per_page=100) printf '[{{"name":"v9.9.9","commit":{{"sha":"{TAG_COMMIT}"}}}}]' ;;
  */bpfcompat-linux-amd64) printf '%s' '{CLI_BYTES.decode().replace(chr(10), "\\n")}' | sed 's/\\\\n/\\n/g' >"$out" ;;
  */bpfcompat-validator-static-linux-amd64) printf 'release-validator-bytes\\n' >"$out" ;;
  */SHA256SUMS) printf '%s  bpfcompat-validator-static-linux-amd64\\n0000  bpfcompat-linux-amd64\\n' '{sums_sha}' >"$out" ;;
  *) exit 22 ;;
esac
""")
    write_exec(os.path.join(stubs, "gh"),
               "#!/usr/bin/env bash\nexit %d\n" % (0 if gh_ok else 1))
    write_exec(os.path.join(stubs, "uname"),
               f"#!/usr/bin/env bash\nif [[ \"$1\" == -m ]]; then echo {machine}; else /bin/uname \"$@\"; fi\n")
    outputs_file = os.path.join(case, "prebuilt_output")
    open(outputs_file, "w").close()
    script = os.path.join(case, "prebuilt.sh")
    github = {"action_ref": ref, "token": "t"}
    with open(script, "w") as fh:
        fh.write(render(prebuilt["run"], dict(defaults), {}, github))
    env = {"PATH": stubs + ":" + os.environ["PATH"], "HOME": case,
           "GITHUB_ACTION_PATH": root, "GITHUB_OUTPUT": outputs_file}
    for key, val in (prebuilt.get("env") or {}).items():
        env[key] = render(str(val), dict(defaults), {}, github)
    res = subprocess.run(["bash", script], cwd=case, env=env,
                         capture_output=True, text=True, timeout=60)
    outputs = {}
    with open(outputs_file) as fh:
        for line in fh:
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                outputs[k] = v
    return res.returncode, res.stdout + res.stderr, outputs, root


def run_main(case, root, outputs, caller_env=None):
    """Execute the run step against a stub bpfcompat that records its validator env."""
    ws = os.path.join(case, "ws")
    os.makedirs(ws, exist_ok=True)
    os.makedirs(os.path.join(root, "bin"), exist_ok=True)
    env_log = os.path.join(case, "validator_env")
    write_exec(os.path.join(root, "bin", "bpfcompat"),
               "#!/usr/bin/env bash\n"
               "printf 'BIN=%s\\nSHA=%s\\n' \"${BPFCOMPAT_VALIDATOR_BIN-<unset>}\" "
               "\"${BPFCOMPAT_VALIDATOR_SHA256-<unset>}\" >\"$ENV_LOG\"\nexit 0\n")
    with open(os.path.join(ws, "matrix.yaml"), "w") as fh:
        fh.write("targets: []\n")
    open(os.path.join(ws, "probe.bpf.o"), "w").close()
    inputs = dict(defaults)
    inputs.update({"artifact": "probe.bpf.o", "matrix": "matrix.yaml",
                   "out": "reports/out.json"})
    script = os.path.join(case, "run.sh")
    with open(script, "w") as fh:
        fh.write(render(run_step["run"], inputs, outputs, {}))
    env = {"PATH": os.environ["PATH"], "HOME": case, "GITHUB_WORKSPACE": ws,
           "GITHUB_ACTION_PATH": root,
           "GITHUB_OUTPUT": os.path.join(case, "run_output"),
           "GITHUB_STEP_SUMMARY": os.path.join(case, "summary"),
           "ENV_LOG": env_log}
    env.update(caller_env or {})
    for key, val in (run_step.get("env") or {}).items():
        env[key] = render(str(val), inputs, outputs, {})
    res = subprocess.run(["bash", script], cwd=ws, env=env,
                         capture_output=True, text=True, timeout=60)
    logged = {}
    if os.path.exists(env_log):
        with open(env_log) as fh:
            for line in fh:
                k, v = line.rstrip("\n").split("=", 1)
                logged[k] = v
    return res.returncode, res.stdout + res.stderr, logged


failures = []


def check(cond, label):
    if not cond:
        failures.append(label)
    print(("ok:   " if cond else "FAIL: ") + label)


n = 0


def new_case():
    global n
    n += 1
    path = os.path.join(tmp, f"c{n}")
    os.makedirs(path)
    return path


# 1. Release tag, every asset verified: the run pins exactly that validator.
case = new_case()
rc, log, outs, root = run_prebuilt(case, "v9.9.9")
want_bin = os.path.join(root, "validator", "c-libbpf", "bin", "bpfcompat-validator")
check(rc == 0 and outs.get("resolved") == "true", "release tag: prebuilt resolved")
check(outs.get("validator-bin") == want_bin, "release tag: prebuilt step outputs the installed validator path")
check(outs.get("validator-sha256") == VALIDATOR_SHA, "release tag: prebuilt step outputs the verified validator digest")
rc, log, got = run_main(case, root, outs)
check(rc == 0 and got.get("BIN") == want_bin, "release tag: run sets BPFCOMPAT_VALIDATOR_BIN to the verified validator")
check(got.get("SHA") == VALIDATOR_SHA, "release tag: run pins BPFCOMPAT_VALIDATOR_SHA256 to the verified digest")
check("::warning::" not in log, "release tag: no warning when the attested validator is used")

# 1b. An installed validator that does not match its SHA256SUMS entry stops
#     the step (defence in depth behind verify-release-assets.sh).
case = new_case()
rc, log, outs, root = run_prebuilt(case, "v9.9.9", sums_sha="0" * 64)
check(rc != 0 and "::error::" in log and outs.get("resolved") != "true",
      "release tag: validator not matching SHA256SUMS fails the step")

# 2. Commit SHA that resolves to a release tag behaves like the tag.
case = new_case()
rc, log, outs, root = run_prebuilt(case, TAG_COMMIT)
check(rc == 0 and outs.get("resolved") == "true" and outs.get("validator-sha256") == VALIDATOR_SHA,
      "release commit SHA: prebuilt resolved and validator digest output")

# 3. Caller-provided validator is kept, and the run says it is not the release validator.
case = new_case()
rc, log, outs, root = run_prebuilt(case, "v9.9.9")
mine = os.path.join(case, "my-validator")
open(mine, "w").close()
rc, log, got = run_main(case, root, outs, {"BPFCOMPAT_VALIDATOR_BIN": mine})
check(rc == 0 and got.get("BIN") == mine, "caller validator: BPFCOMPAT_VALIDATOR_BIN set by the caller is kept")
check("::warning::" in log and "attested" in log, "caller validator: run warns that the attested release validator is not used")

# 3b. A caller that pins only a digest keeps exactly its own settings (no new
#     failure mode for workflows that already set BPFCOMPAT_VALIDATOR_SHA256).
case = new_case()
rc, log, outs, root = run_prebuilt(case, "v9.9.9")
mine_sha = "1" * 64
rc, log, got = run_main(case, root, outs, {"BPFCOMPAT_VALIDATOR_SHA256": mine_sha})
check(rc == 0 and got.get("BIN") == "<unset>" and got.get("SHA") == mine_sha,
      "caller digest: BPFCOMPAT_VALIDATOR_SHA256 set by the caller is kept and no path is forced")
check("::warning::" in log and "attested" in log, "caller digest: run warns that the attested release validator is not pinned")

# 4. No resolved prebuilt: the run step does not set a validator pin.
case = new_case()
root = os.path.join(case, "action")
os.makedirs(root)
rc, log, got = run_main(case, root, {"resolved": "false"})
check(rc == 0 and got.get("BIN") == "<unset>" and got.get("SHA") == "<unset>",
      "no prebuilt: run leaves BPFCOMPAT_VALIDATOR_BIN/SHA256 unset")

# 5. Fallbacks while pinned to a release are annotated as warnings.
for label, kwargs in [
    ("asset download fails", {"curl_fail": "bpfcompat-validator-static-linux-amd64"}),
    ("gh attestation unavailable", {"gh_ok": False}),
    ("non-x86_64 runner", {"machine": "aarch64"}),
]:
    case = new_case()
    rc, log, outs, root = run_prebuilt(case, "v9.9.9", **kwargs)
    check(rc == 0 and outs.get("resolved") == "false", f"release tag, {label}: falls back to a source build")
    check("::warning::" in log, f"release tag, {label}: fallback is a ::warning:: annotation")
    check("validator-sha256" not in outs, f"release tag, {label}: no validator digest output")

# 6. A commit SHA the action cannot map to a release is warned about, too.
case = new_case()
rc, log, outs, root = run_prebuilt(case, "b" * 40)
check(rc == 0 and outs.get("resolved") == "false" and "::warning::" in log,
      "unresolvable commit SHA: source build with a ::warning::")

# 7. A non-release ref keeps the documented source build without an annotation.
case = new_case()
rc, log, outs, root = run_prebuilt(case, "main")
check(rc == 0 and outs.get("resolved") == "false" and "::warning::" not in log,
      "branch ref: documented source build, no warning")

if failures:
    print(f"action validator-pin regression: {len(failures)} check(s) FAILED", file=sys.stderr)
    sys.exit(1)
print("action validator-pin regression: all checks pass")
PY
