#!/usr/bin/env bash
# Regression for the composite action's validator identity (F4a) and its
# source-build fallback warnings (F4b).
#
# It renders the real action.yml "Download prebuilt binaries" and
# "Run bpfcompat" steps the way the Actions runner does and executes them with
# bash against stubs (curl, gh, git, uname, verify-release-assets.sh,
# bpfcompat). Hermetic: no network, no VM, no real release assets.
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
#   - Prebuilt assets are verified for exactly the pinned release: its tag ref
#     and the commit it was built from (a SHA pin is that commit; a tag pin is
#     resolved with git ls-remote, peeled when annotated). Assets attested by
#     another release's run are a hard error. When the commit cannot be
#     resolved, or gh cannot bind attestations to a ref and commit (gh older
#     than 2.68.0), the run takes the warned source build, never an unbound
#     prebuilt install and never a job failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="${1:-$ROOT/action.yml}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 - "$ACTION" "$tmp" <<'PY'
import hashlib
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
CLI_SHA = hashlib.sha256(CLI_BYTES).hexdigest()
TAG_COMMIT = "a" * 40
TAG_OBJECT = "d" * 40
OTHER_COMMIT = "e" * 40
REAL_GIT = shutil.which("git") or "/usr/bin/git"
REAL_VERIFIER = os.path.join(os.path.dirname(os.path.abspath(action_path)), "scripts", "verify-release-assets.sh")
# git ls-remote of an annotated release tag: the tag object, then the commit.
ANNOTATED = f"{TAG_OBJECT}\trefs/tags/v9.9.9\n{TAG_COMMIT}\trefs/tags/v9.9.9^{{}}\n"
GH_FLAGS = {
    "--signer-workflow": "      --signer-workflow string       Enforce that the workflow that signed the attestation matches the provided value ([host/]<owner>/<repo>/<path>/<to>/<workflow>)",
    "--source-digest": "      --source-digest string         Enforce that the digest associated with the source repository matches the provided value",
    "--source-ref": "      --source-ref string            Enforce that the git ref associated with the source repository matches the provided value",
}
# What the last run_prebuilt saw: the verifier's environment (None if it was
# not called), and every git invocation.
LAST = {}


def gh_help(lacks, extra=""):
    """`gh attestation verify --help` FLAGS, after gh 2.102.0, minus `lacks`."""
    lines = ["Verify the integrity and provenance of an artifact using its associated",
             "cryptographically signed attestations.", "", "FLAGS",
             "  -o, --owner string                 GitHub organization to scope attestation lookup by",
             "  -R, --repo string                  Repository name in the format <owner>/<repo>",
             "      --signer-digest string         Enforce that the digest associated with the signer workflow matches the provided value"]
    lines += [line for flag, line in GH_FLAGS.items() if flag not in lacks]
    if extra:
        lines.append(extra)
    return "\n".join(lines) + "\n"


def run_prebuilt(case, ref, curl_fail="", gh_ok=True, machine="x86_64", sums_sha=VALIDATOR_SHA,
                 gh_lacks=(), gh_help_extra="", gh_help_fails=False, ls_remote=ANNOTATED,
                 verifier="stub", attested=("refs/tags/v9.9.9", TAG_COMMIT)):
    """Execute the prebuilt step; return (rc, stdout+stderr, outputs dict, action_root).

    ls_remote is what `git ls-remote` prints (None: it fails like a network
    error). verifier "stub" records the identity the step passes; "real" runs
    this checkout's scripts/verify-release-assets.sh against a gh whose assets
    carry the release-workflow attestation `attested` (source ref, commit)."""
    root = os.path.join(case, "action")
    os.makedirs(os.path.join(root, "scripts"))
    verifier_log = os.path.join(case, "verifier_env")
    if verifier == "real":
        shutil.copy(REAL_VERIFIER, os.path.join(root, "scripts", "verify-release-assets.sh"))
    else:
        write_exec(os.path.join(root, "scripts", "verify-release-assets.sh"),
                   "#!/usr/bin/env bash\n"
                   "printf 'SHA=%s\\nREF=%s\\nARGS=%s\\n' \"${BPFCOMPAT_EXPECTED_SOURCE_SHA-<unset>}\" "
                   f"\"${{BPFCOMPAT_EXPECTED_SOURCE_REF-<unset>}}\" \"$*\" >'{verifier_log}'\nexit 0\n")
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
  */SHA256SUMS) printf '%s  bpfcompat-validator-static-linux-amd64\\n%s  bpfcompat-linux-amd64\\n' '{sums_sha}' '{CLI_SHA}' >"$out" ;;
  *) exit 22 ;;
esac
""")
    # gh: `gh attestation verify --help` lists the flags this gh has; verify
    # checks the assets' attestation `attested` like gh does (an absent or
    # empty --source-ref / --source-digest accepts any value).
    help_file = os.path.join(case, "gh_help")
    with open(help_file, "w") as fh:
        fh.write(gh_help(gh_lacks, gh_help_extra))
    write_exec(os.path.join(stubs, "gh"), f"""#!/usr/bin/env bash
{"exit 1" if not gh_ok else ""}
if [[ "$1 ${{2:-}} ${{3:-}}" == "attestation verify --help" ]]; then
  {"exit 1" if gh_help_fails else ""}
  cat '{help_file}'
  exit 0
fi
[[ "$1 ${{2:-}}" == "attestation --help" ]] && exit 0
[[ "$1 ${{2:-}}" == "attestation verify" ]] || exit 0
shift 2
ref="" src=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) [[ "$2" == Kernel-Guard/bpfcompat ]] || exit 1; shift 2 ;;
    --signer-workflow) [[ "$2" == Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml ]] || exit 1; shift 2 ;;
    --source-ref) ref="$2"; shift 2 ;;
    --source-digest) src="$2"; shift 2 ;;
    --*) echo "unknown flag: $1" >&2; exit 1 ;;
    *) shift ;;
  esac
done
[[ -z "$ref" || "$ref" == '{attested[0]}' ]] || {{ echo "stub gh: expected SourceRepositoryRef $ref, got {attested[0]}" >&2; exit 1; }}
[[ -z "$src" || "$src" == '{attested[1]}' ]] || {{ echo "stub gh: expected SourceRepositoryDigest $src, got {attested[1]}" >&2; exit 1; }}
exit 0
""")
    git_log = os.path.join(case, "git_calls")
    ls_file = os.path.join(case, "ls_remote")
    with open(ls_file, "w") as fh:
        fh.write(ls_remote or "")
    write_exec(os.path.join(stubs, "git"), f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >>'{git_log}'
if [[ "${{1:-}}" == ls-remote ]]; then
  {"echo 'fatal: unable to access https://github.com/Kernel-Guard/bpfcompat.git/: Could not resolve host: github.com' >&2; exit 128" if ls_remote is None else ""}
  cat '{ls_file}'
  exit 0
fi
exec '{REAL_GIT}' "$@"
""")
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
    LAST["verifier"] = None
    if os.path.exists(verifier_log):
        with open(verifier_log) as fh:
            LAST["verifier"] = dict(l.rstrip("\n").split("=", 1) for l in fh if "=" in l)
    LAST["git"] = open(git_log).read().splitlines() if os.path.exists(git_log) else []
    LAST["installed"] = os.path.exists(os.path.join(root, "bin", "bpfcompat"))
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

# 8. Tag pin: verification is bound to the tag ref and the commit the
#    annotated tag points at (the peeled ^{} line, not the tag object).
case = new_case()
rc, log, outs, root = run_prebuilt(case, "v9.9.9")
got = LAST["verifier"] or {}
check(rc == 0 and outs.get("resolved") == "true", "tag pin: prebuilt resolved")
check(got.get("REF") == "refs/tags/v9.9.9", "tag pin: verifier bound to refs/tags/v9.9.9")
check(got.get("SHA") == TAG_COMMIT, "tag pin: verifier bound to the tag's peeled commit")
check(any(c.startswith("ls-remote ") and "refs/tags/v9.9.9" in c for c in LAST["git"]),
      "tag pin: the tag is resolved with git ls-remote")

# 8b. A lightweight tag has no ^{} line: its own line is the commit.
case = new_case()
rc, log, outs, root = run_prebuilt(case, "v9.9.9", ls_remote=f"{TAG_COMMIT}\trefs/tags/v9.9.9\n")
check(rc == 0 and (LAST["verifier"] or {}).get("SHA") == TAG_COMMIT,
      "lightweight tag pin: verifier bound to the tag's commit")

# 8c. ls-remote patterns match ref tails, so other refs ending in the tag name
#     may be listed too (sorted after it); only refs/tags/<tag> counts.
case = new_case()
rc, log, outs, root = run_prebuilt(
    case, "v9.9.9",
    ls_remote=ANNOTATED + f"{OTHER_COMMIT}\trefs/tags/x/refs/tags/v9.9.9\n{OTHER_COMMIT}\trefs/tags/x/refs/tags/v9.9.9^{{}}\n")
check(rc == 0 and (LAST["verifier"] or {}).get("SHA") == TAG_COMMIT,
      "tag pin: refs that merely end in the tag name are ignored")

# 8d. SHA pin: the pinned commit itself, and the release tag it maps to.
case = new_case()
rc, log, outs, root = run_prebuilt(case, TAG_COMMIT)
got = LAST["verifier"] or {}
check(rc == 0 and outs.get("resolved") == "true" and got.get("SHA") == TAG_COMMIT
      and got.get("REF") == "refs/tags/v9.9.9", "SHA pin: verifier bound to the pinned commit and its release tag")
check(not any(c.startswith("ls-remote") for c in LAST["git"]), "SHA pin: no git ls-remote")

# 9. The tag cannot be resolved to a commit: warned source build, not a job
#    failure and not an unbound prebuilt install.
for label, listing in [("git ls-remote fails", None),
                       ("git ls-remote lists no such tag", ""),
                       ("git ls-remote lists only other refs", f"{OTHER_COMMIT}\trefs/tags/x/refs/tags/v9.9.9\n")]:
    case = new_case()
    rc, log, outs, root = run_prebuilt(case, "v9.9.9", ls_remote=listing)
    check(rc == 0 and outs.get("resolved") == "false" and "::warning::" in log,
          f"tag pin, {label}: warned source build")
    check(LAST["verifier"] is None and not LAST["installed"] and "validator-sha256" not in outs,
          f"tag pin, {label}: nothing verified or installed")

# 10. A gh that cannot bind attestations to a ref and commit (older than
#     2.68.0), or whose help cannot be read: warned source build that names
#     what is missing, never an unbound verification.
for label, kwargs, needle in [
    ("gh 2.51-2.67 (no --source-ref/--source-digest)", {"gh_lacks": ("--source-ref", "--source-digest")}, "--source-ref"),
    ("gh 2.49-2.50 (no --signer-workflow either)",
     {"gh_lacks": ("--signer-workflow", "--source-ref", "--source-digest")}, "--signer-workflow"),
    ("gh without --source-digest", {"gh_lacks": ("--source-digest",)}, "--source-digest"),
    ("help names only a longer flag", {"gh_lacks": ("--source-ref",),
     "gh_help_extra": "      --source-ref-name string       (not the flag)"}, "--source-ref"),
    ("gh attestation verify --help fails", {"gh_help_fails": True}, "gh >= 2.68.0"),
]:
    case = new_case()
    rc, log, outs, root = run_prebuilt(case, "v9.9.9", **kwargs)
    check(rc == 0 and outs.get("resolved") == "false" and "::warning::" in log and needle in log,
          f"{label}: warned source build naming {needle}")
    check(LAST["verifier"] is None and not LAST["installed"], f"{label}: nothing verified or installed")

# 11. The real verifier: assets attested for exactly this release are used;
#     another release's genuine, attested assets are a hard error.
case = new_case()
rc, log, outs, root = run_prebuilt(case, "v9.9.9", verifier="real")
check(rc == 0 and outs.get("resolved") == "true" and LAST["installed"],
      "real verifier: assets attested for v9.9.9 at its commit are used")
for label, ref, attested in [
    ("tag pin, assets of another tag's release run", "v9.9.9", ("refs/tags/v9.9.8", OTHER_COMMIT)),
    ("tag pin, another tag's run at the same commit", "v9.9.9", ("refs/tags/v9.9.8", TAG_COMMIT)),
    ("SHA pin, the tag's ref built from another commit", TAG_COMMIT, ("refs/tags/v9.9.9", OTHER_COMMIT)),
]:
    case = new_case()
    rc, log, outs, root = run_prebuilt(case, ref, verifier="real", attested=attested)
    check(rc != 0 and outs.get("resolved") != "true" and not LAST["installed"]
          and "stub gh: expected SourceRepository" in log,
          f"real verifier, {label}: hard error, nothing installed")

if failures:
    print(f"action validator-pin regression: {len(failures)} check(s) FAILED", file=sys.stderr)
    sys.exit(1)
print("action validator-pin regression: all checks pass")
PY
