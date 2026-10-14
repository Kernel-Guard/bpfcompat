#!/usr/bin/env bash
# No caller-controlled expression may be interpolated into a `run:` script.
#
#   check-action-input-interpolation.sh [--strict] [action.yml]
#
# The Actions runner substitutes `${{ ... }}` into a `run:` script as plain
# text BEFORE the shell parses it. An action input (or event data such as a
# PR branch name) placed there is therefore shell source, not a value: a
# consumer that passes `artifact: x"; curl ... "$GITHUB_TOKEN"; : "` gets
# arbitrary commands in its own job, with its own token. Quoting does not
# help -- the payload simply closes the quotes.
#
# Such values must reach the script through the step's `env:` block and be
# read as quoted shell variables. Expressions in `env:`, `with:` and `if:` are
# evaluated by the runner, never by a shell, so they are allowed.
#
# Flagged inside any step's `run:` (case-insensitive, any expression that
# merely mentions them as a whole word, e.g. format(..., inputs.x)):
#   inputs (inputs.x, inputs[...], toJSON(inputs), bare inputs)
#   env    (env.X, env[...]): indirect -- read $X from the environment instead
#   github.event.*, github.head_ref, and bare github (toJSON(github), which
#          embeds the whole event payload); other github.<prop> are allowed
# Expressions are scanned from `${{` to the first `}}` outside a single-quoted
# string literal ('' escapes a quote), so format('}}', inputs.x) cannot hide
# the tainted part; an unterminated `${{` is flagged as well.
#
# --strict (used for workflows by check-workflow-expression-interpolation.sh)
# is default-deny: EVERY expression in a run: script is flagged unless its
# whole body is exactly one of the run-identity values in SAFE below. A
# workflow's matrix, step and job outputs can carry event data (a matrix built
# by fromJSON(needs.x.outputs.y), a step that echoes a PR title), so they are
# not provably safe and must use env: as well.
#
# Defaults to the repository's action.yml. Exits 0 on PASS, 1 on a finding,
# 2 on an unreadable/invalid file.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
strict=0
if [[ "${1:-}" == "--strict" ]]; then
  strict=1
  shift
fi
action="${1:-$ROOT/action.yml}"

[[ -f "$action" ]] || { echo "[action-input-interpolation] missing file: $action" >&2; exit 2; }

python3 - "$action" "$strict" <<'PY'
import re
import sys

import yaml

path = sys.argv[1]
strict = sys.argv[2] == "1"
try:
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
except (OSError, yaml.YAMLError) as exc:
    print(f"[action-input-interpolation] cannot parse {path}: {exc}", file=sys.stderr)
    sys.exit(2)

if not isinstance(doc, dict):
    print(f"[action-input-interpolation] {path}: not a mapping", file=sys.stderr)
    sys.exit(2)

WORD = r"(?<![\w.-])"   # not a property of something else (steps.x.inputs)
END = r"(?![\w-])"
TAINTED = re.compile(
    WORD + r"(inputs|env)" + END
    + "|" + WORD + r"github" + END + r"(?!\s*[.\[])"            # bare github
    + "|" + WORD + r"github\s*\.\s*(event|head_ref)" + END
    # github[...] passes only as a quoted literal naming a safe property, so a
    # computed index (github[format(...)]) cannot reach event data.
    + "|" + WORD + r"github\s*\[(?!\s*'(?!(event|head_ref)')[\w-]+'\s*\])",
    re.I,
)

# --strict allowlist: values fixed by the runner for this run, never derived
# from event payloads, inputs or refs. Matched against the WHOLE expression
# body, so wrapping (format(...), a || b) is not allowed.
SAFE = re.compile(
    r"\s*(github\.(sha|run_id|run_number|run_attempt)|runner\.(os|arch))\s*"
)


def flagged(expr):
    body = expr[3:]
    if not strict:
        return bool(TAINTED.search(body))
    # An unterminated expression is never provably safe.
    return not (body.endswith("}}") and SAFE.fullmatch(body[:-2]))


def expressions(script):
    """Yield (offset, text) for each ${{ ... }} in script.

    The closing }} is the first one outside a single-quoted string literal
    ('' is an escaped quote inside one). An unterminated expression runs to
    the end of the script, so it is still scanned rather than skipped.
    """
    i = 0
    while True:
        start = script.find("${{", i)
        if start < 0:
            return
        j, in_str = start + 3, False
        while j < len(script):
            c = script[j]
            if in_str:
                if c == "'":
                    if script.startswith("''", j):
                        j += 2
                        continue
                    in_str = False
            elif c == "'":
                in_str = True
            elif script.startswith("}}", j):
                break
            j += 1
        yield start, script[start:j + 2]
        i = j + 2


def steps_of(doc):
    """Yield (label, step) for composite-action steps and workflow job steps."""
    runs = doc.get("runs")
    if isinstance(runs, dict):
        for i, step in enumerate(runs.get("steps") or []):
            yield f"runs.steps[{i}]", step
    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if isinstance(job, dict):
                for i, step in enumerate(job.get("steps") or []):
                    yield f"jobs.{job_id}.steps[{i}]", step


findings = []
for label, step in steps_of(doc):
    if not isinstance(step, dict):
        continue
    script = step.get("run")
    if not isinstance(script, str):
        continue
    name = step.get("name") or step.get("id") or ""
    for start, expr in expressions(script):
        if flagged(expr):
            lineno = script.count("\n", 0, start) + 1
            findings.append(f"{label} ({name}) run line {lineno}: {expr.strip()}")

if findings:
    for f in findings:
        print(f"[action-input-interpolation] FAIL: {path}: {f}", file=sys.stderr)
    print("[action-input-interpolation] pass the value through the step's env: "
          "block and read it as a quoted shell variable", file=sys.stderr)
    sys.exit(1)
print(f"[action-input-interpolation] PASS: {path}")
PY
