#!/usr/bin/env bash
# Regression for the composite action's third-party license bundle delivery.
#
# Renders the real action.yml "Download prebuilt binaries" step the way the
# Actions runner does and runs it with bash against stubs (curl, gh, git,
# uname, verify-release-assets.sh). Hermetic: no network, no real release
# assets. The gh and git stubs only let the step bind verification to the
# pinned release (scripts/action-validator-pin_test.sh covers that binding).
#
# Contract checked:
#   - A release whose SHA256SUMS lists bpfcompat-third-party-licenses.tar.gz:
#     the bundle is downloaded, verified in the same verify-release-assets.sh
#     call as the binaries, and unpacked to <action>/share/doc/bpfcompat.
#   - A release that does not list it (older releases) resolves as before and
#     says where the repository's notices are.
#   - Listed but unavailable: the documented source-build fallback warning.
#   - Listed but failing verification, or not shaped like a bundle: hard error,
#     prebuilt binaries not used.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="${1:-$ROOT/action.yml}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 - "$ACTION" "$tmp" <<'PY'
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile

import yaml

action_path, tmp = sys.argv[1], sys.argv[2]
action = yaml.safe_load(open(action_path, encoding="utf-8"))
defaults = {k: str(v.get("default", "")) for k, v in action["inputs"].items()}
prebuilt = next(s for s in action["runs"]["steps"] if s.get("id") == "prebuilt")
EXPR = re.compile(r"\$\{\{\s*(inputs|github)\.([A-Za-z0-9_-]+)\s*\}\}")


def render(text, github):
    out = EXPR.sub(lambda m: (defaults if m.group(1) == "inputs" else github).get(m.group(2), ""), text)
    if "${{" in out:
        raise SystemExit(f"unrenderable expression: {out!r}")
    return out


def write_exec(path, body):
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o755)


def bundle_bytes(with_inventory=True):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        files = {"bpfcompat-third-party-licenses/go/toolchain/LICENSE": b"Go license\n"}
        if with_inventory:
            files["bpfcompat-third-party-licenses/INVENTORY.json"] = b'{"schema_version": "v1"}\n'
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


VALIDATOR = b"release-validator-bytes\n"
failures = 0


def case(name, listed=True, available=True, verify_ok=True, inventory=True, star=False):
    d = os.path.join(tmp, name)
    root = os.path.join(d, "action")
    stubs = os.path.join(d, "stubs")
    assets = os.path.join(d, "assets")
    for p in (os.path.join(root, "scripts"), stubs, assets):
        os.makedirs(p)
    open(os.path.join(assets, "bpfcompat-linux-amd64"), "wb").write(b"#!/bin/sh\nexit 0\n")
    open(os.path.join(assets, "bpfcompat-validator-static-linux-amd64"), "wb").write(VALIDATOR)
    sums = f"{hashlib.sha256(VALIDATOR).hexdigest()}  bpfcompat-validator-static-linux-amd64\n"
    if listed:
        b = bundle_bytes(inventory)
        if available:
            open(os.path.join(assets, "bpfcompat-third-party-licenses.tar.gz"), "wb").write(b)
        sums += f"{hashlib.sha256(b).hexdigest()} {'*' if star else ' '}bpfcompat-third-party-licenses.tar.gz\n"
    open(os.path.join(assets, "SHA256SUMS"), "w").write(sums)
    verify_log = os.path.join(d, "verify.log")
    write_exec(os.path.join(root, "scripts", "verify-release-assets.sh"),
               f"#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >>'{verify_log}'\nexit {0 if verify_ok else 1}\n")
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
f='{assets}'/"${{url##*/}}"
[[ -f "$f" ]] || exit 22
cp "$f" "$out"
""")
    # A gh that can bind attestations to a source ref and commit (>= 2.68.0).
    write_exec(os.path.join(stubs, "gh"), """#!/usr/bin/env bash
if [[ "$1 ${2:-} ${3:-}" == "attestation verify --help" ]]; then
  echo '      --signer-workflow string       Enforce that the workflow that signed the attestation matches the provided value'
  echo '      --source-digest string         Enforce that the digest associated with the source repository matches the provided value'
  echo '      --source-ref string            Enforce that the git ref associated with the source repository matches the provided value'
fi
exit 0
""")
    # git ls-remote resolves the pinned tag v9.9.9 to its commit.
    write_exec(os.path.join(stubs, "git"), f"""#!/usr/bin/env bash
if [[ "${{1:-}}" == ls-remote ]]; then
  printf '%s\\trefs/tags/v9.9.9\\n%s\\trefs/tags/v9.9.9^{{}}\\n' {"d" * 40} {"a" * 40}
  exit 0
fi
exec '{shutil.which("git") or "/usr/bin/git"}' "$@"
""")
    write_exec(os.path.join(stubs, "uname"),
               "#!/usr/bin/env bash\nif [[ \"$1\" == -m ]]; then echo x86_64; else /bin/uname \"$@\"; fi\n")
    outputs = os.path.join(d, "outputs")
    open(outputs, "w").close()
    github = {"action_ref": "v9.9.9", "token": "t"}
    script = os.path.join(d, "prebuilt.sh")
    open(script, "w").write(render(prebuilt["run"], github))
    env = {"PATH": stubs + ":" + os.environ["PATH"], "HOME": d,
           "GITHUB_ACTION_PATH": root, "GITHUB_OUTPUT": outputs}
    for k, v in (prebuilt.get("env") or {}).items():
        env[k] = render(str(v), github)
    r = subprocess.run(["bash", script], cwd=d, env=env, capture_output=True, text=True, timeout=60)
    out = dict(l.rstrip("\n").split("=", 1) for l in open(outputs) if "=" in l)
    verified = open(verify_log).read() if os.path.exists(verify_log) else ""
    return r.returncode, r.stdout + r.stderr, out, root, verified


def check(cond, msg, log=""):
    global failures
    if cond:
        print(f"[action-license-test] ok: {msg}")
    else:
        failures += 1
        print(f"[action-license-test] FAIL: {msg}\n{log}", file=sys.stderr)


rc, log, out, root, ver = case("listed")
doc = os.path.join(root, "share", "doc", "bpfcompat")
check(rc == 0 and out.get("resolved") == "true" and os.path.isfile(os.path.join(doc, "INVENTORY.json"))
      and os.path.isfile(os.path.join(doc, "go", "toolchain", "LICENSE")),
      "listed bundle unpacked to <action>/share/doc/bpfcompat", log)
check("bpfcompat-third-party-licenses.tar.gz" in ver and "bpfcompat-validator-static-linux-amd64" in ver
      and ver.count("\n") == 1, "bundle verified in the same call as the binaries", ver)

rc, log, out, root, ver = case("star", star=True)
check(rc == 0 and os.path.isfile(os.path.join(root, "share", "doc", "bpfcompat", "INVENTORY.json")),
      "binary-mode SHA256SUMS line ('*name') is recognised", log)

rc, log, out, root, ver = case("old", listed=False)
check(rc == 0 and out.get("resolved") == "true" and not os.path.exists(os.path.join(root, "share"))
      and "publishes no third-party license bundle" in log and "third-party-licenses" not in ver,
      "release without a bundle resolves as before and points to the repository notices", log)

rc, log, out, root, ver = case("unavailable", available=False)
check(rc == 0 and out.get("resolved") == "false" and "::warning::Release asset bpfcompat-third-party-licenses.tar.gz not available" in log,
      "listed but unavailable bundle: source-build fallback warning", log)

rc, log, out, root, ver = case("badverify", verify_ok=False)
check(rc != 0 and out.get("resolved") == "false" and not os.path.exists(os.path.join(root, "share")),
      "bundle failing verification: hard error, prebuilt not used", log)

rc, log, out, root, ver = case("badlayout", inventory=False)
check(rc != 0 and out.get("resolved") == "false" and "does not have the expected layout" in log,
      "verified archive that is not a license bundle: hard error", log)

if failures:
    print(f"[action-license-test] {failures} failure(s)", file=sys.stderr)
    sys.exit(1)
print("action-license-bundle_test: all checks passed")
PY
