#!/usr/bin/env bash
# Least-privilege GITHUB_TOKEN permissions for every workflow.
#
#   check-workflow-permissions.sh
#
# 1. Every workflow declares top-level `permissions:` and that block is
#    read-only: `{}`, `read-all`, or a mapping whose values are all `read` or
#    `none`. A top-level grant applies to every job, including jobs added
#    later, so a write there is never least privilege (OpenSSF Scorecard
#    Token-Permissions, topLevel).
# 2. No job uses `write-all`.
# 3. Every job-level `write` is listed in
#    scripts/workflow-write-permissions.allow as
#    `<workflow-file> <job-id> <permission> <justification...>`, so a new
#    write grant needs a reviewed change to that file. An allowlist entry that
#    no longer matches a grant fails too, so the list cannot drift into a
#    blanket exemption.
#
# Overridable for the regression suite only: BPFCOMPAT_WORKFLOWS_DIR,
# BPFCOMPAT_WORKFLOW_WRITE_ALLOWLIST.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflows_dir="${BPFCOMPAT_WORKFLOWS_DIR:-$ROOT/.github/workflows}"
allowlist="${BPFCOMPAT_WORKFLOW_WRITE_ALLOWLIST:-$ROOT/scripts/workflow-write-permissions.allow}"

[[ -d "$workflows_dir" ]] || { echo "[workflow-permissions] missing workflows dir: $workflows_dir" >&2; exit 2; }
[[ -f "$allowlist" ]] || { echo "[workflow-permissions] missing allowlist: $allowlist" >&2; exit 2; }

python3 - "$workflows_dir" "$allowlist" <<'PY'
import os
import sys

import yaml

workflows_dir, allowlist_path = sys.argv[1], sys.argv[2]
READ_ONLY = {"read", "none"}
failures = []


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last."""


def _no_duplicates(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates)


def fail(msg):
    failures.append(msg)
    print(f"[workflow-permissions] FAIL: {msg}", file=sys.stderr)


allowed = set()
with open(allowlist_path, encoding="utf-8") as handle:
    for lineno, raw in enumerate(handle, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 4 or not parts[3].strip():
            fail(f"{allowlist_path}:{lineno}: expected '<workflow> <job> <permission> <justification>'")
            continue
        key = tuple(parts[:3])
        if key in allowed:
            fail(f"{allowlist_path}:{lineno}: duplicate entry {' '.join(key)}")
        allowed.add(key)

granted = set()
files = sorted(
    f for f in os.listdir(workflows_dir) if f.lower().endswith((".yml", ".yaml"))
)
if not files:
    fail(f"no workflow files under {workflows_dir}")

for name in files:
    path = os.path.join(workflows_dir, name)
    with open(path, encoding="utf-8") as handle:
        try:
            wf = yaml.load(handle, Loader=StrictLoader)
        except yaml.YAMLError as err:
            fail(f"{name}: invalid or ambiguous YAML: {err}")
            continue
    if not isinstance(wf, dict):
        fail(f"{name}: not a workflow mapping")
        continue

    if "permissions" not in wf:
        fail(f"{name}: no top-level permissions; the default token may be read-write")
    else:
        top = wf["permissions"]
        if top in ({}, "read-all"):
            pass
        elif isinstance(top, dict):
            for perm, level in top.items():
                if str(level) not in READ_ONLY:
                    fail(f"{name}: top-level permission '{perm}: {level}' grants write to every job; move it to the job that needs it")
        else:
            fail(f"{name}: top-level permissions '{top}' is not read-only ({{}}, read-all, or read/none values)")

    for job_id, job in (wf.get("jobs") or {}).items():
        if not isinstance(job, dict) or "permissions" not in job:
            continue
        perms = job["permissions"]
        if perms in ({}, "read-all"):
            continue
        if not isinstance(perms, dict):
            fail(f"{name}/{job_id}: job permissions '{perms}' is not allowed (write-all and other shorthands are rejected)")
            continue
        for perm, level in perms.items():
            level = str(level)
            if level in READ_ONLY:
                continue
            if level != "write":
                fail(f"{name}/{job_id}: unknown permission level '{perm}: {level}'")
                continue
            key = (name, str(job_id), str(perm))
            granted.add(key)
            if key not in allowed:
                fail(f"{name}/{job_id}: job-level '{perm}: write' is not in {os.path.basename(allowlist_path)}")

for key in sorted(allowed - granted):
    fail(f"stale allowlist entry (no such job-level write grant): {' '.join(key)}")

if failures:
    print(f"[workflow-permissions] {len(failures)} failure(s)", file=sys.stderr)
    sys.exit(1)
print(f"[workflow-permissions] PASS: {len(files)} workflows, top-level read-only, {len(granted)} allowlisted job-level write grant(s)")
PY
