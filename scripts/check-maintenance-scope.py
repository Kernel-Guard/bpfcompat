#!/usr/bin/env python3
"""Machine-verified maintenance scope (R1).

A maintenance release may use the narrowed tech gate only if every change
since the PUBLISHED stable release (release.yaml stable_commit) falls into an
allowed class and every runtime change is explicitly declared, targeted and
exercised. Anything else makes the release ineligible for the maintenance
path; it then needs the full stable gate.

Classes:
  S1-profile          vm/profiles/*.yaml, Makefile. Every changed profile must
                      be booted by scripts/maintenance-vm-gate.sh.
  S2-runtime          non-test Go under cmd/, internal/, pkg/. Each file must
                      be declared in docs/releases/v<release>-scope.yaml with
                      its functions, the VM-gate profiles that exercise them and
                      tests that reference every function. Every changed line
                      must lie inside a declared top-level function.
  S3-release-tooling  workflows, scripts/, action.yml, Dockerfile*,
                      release.yaml. action.yml inputs/outputs must not change.
  S5-docs-tests       docs/, *.md, *_test.{go,py,sh}.
  FORBIDDEN           go.mod, go.sum, vendor/, validator/, pkg/schema/,
                      research/, scripts/research/ -- dependency, validator,
                      report-schema and frozen-research changes are never
                      maintenance scope.
  UNCLASSIFIED        anything else; fails closed.

Toolchain (S4): if the build toolchain differs from the baseline, the
declaration must name from/to exactly and cite GO-YYYY-NNNN advisories; a
declaration without an actual change is rejected as stale.

Usage: check-maintenance-scope.py [--json] [--out FILE]
Exit 0 eligible, 1 ineligible, 2 usage/environment error.
"""
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = 'bpfcompat.maintenance-scope.v1'
ADVISORY = re.compile(r'GO-\d{4}-\d{4,}')

FORBIDDEN = ['go.mod', 'go.sum', 'vendor/*', 'validator/*', 'pkg/schema/*',
             'research/*', 'scripts/research/*']
TESTS = ['*_test.go', '*_test.py', '*_test.sh']
DOCS = ['docs/*', '*.md']
PROFILE = ['vm/profiles/*.yaml', 'Makefile']
RUNTIME = ['cmd/*.go', 'internal/*.go', 'pkg/*.go']
TOOLING = ['.github/workflows/*', 'scripts/*', 'action.yml', 'Dockerfile',
           'Dockerfile.release', 'release.yaml']


def _match(path, patterns):
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)


def classify(path):
    if _match(path, FORBIDDEN):
        return 'FORBIDDEN'
    if _match(Path(path).name, TESTS):
        return 'S5-docs-tests'
    if _match(path, DOCS):
        return 'S5-docs-tests'
    if _match(path, PROFILE):
        return 'S1-profile'
    if _match(path, RUNTIME):
        return 'S2-runtime'
    if _match(path, TOOLING):
        return 'S3-release-tooling'
    return 'UNCLASSIFIED'


FUNC = re.compile(r'^func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*[\[(]')
# Attached doc comments are `// text` or a bare `//`. Anything else directly
# after the slashes (`//go:`, `//export`, `//line`, `//extern`, ...) is a
# compiler/linker directive: it changes build semantics and is never part of
# the function below it.
DOC_LINE = re.compile(r'^//( |$)')


def _func_key(receiver, name):
    """Methods are keyed Type.Name so same-named methods never collide."""
    if not receiver:
        return name
    rtype = receiver.split()[-1].lstrip('*').split('[')[0]
    return '%s.%s' % (rtype, name)


def _body_end(lines, start):
    """0-based index of the line where the declaration starting at `start`
    closes. Braces inside strings, runes, raw strings and comments are
    ignored. A declaration ends on the line where its brace depth returns to
    zero with no further `{` on that line, so one-line bodies and brace-using
    signatures such as `func f() interface{} {` are both handled."""
    depth = 0
    opened = False
    in_block = False
    in_raw = False
    for j in range(start, len(lines)):
        line = lines[j]
        k = 0
        closed_here = False
        while k < len(line):
            c = line[k]
            if in_block:
                if line.startswith('*/', k):
                    in_block = False
                    k += 2
                    continue
                k += 1
                continue
            if in_raw:
                if c == '`':
                    in_raw = False
                k += 1
                continue
            if line.startswith('//', k):
                break
            if line.startswith('/*', k):
                in_block = True
                k += 2
                continue
            if c == '`':
                in_raw = True
            elif c in '"\'':
                quote = c
                k += 1
                while k < len(line) and line[k] != quote:
                    k += 2 if line[k] == '\\' else 1
            elif c == '{':
                depth += 1
                opened = True
                closed_here = False
            elif c == '}':
                depth -= 1
                if opened and depth == 0:
                    closed_here = True
            k += 1
        if closed_here and depth == 0:
            return j
        if not opened and j > start and not in_block and not in_raw and line.strip() == '':
            return j - 1  # bodiless declaration (assembly stub)
    return len(lines) - 1


def function_spans(source):
    """Top-level func key -> (first line, last line), 1-based. Methods are
    keyed Type.Name. The span includes the attached `// ` doc comment."""
    spans = {}
    lines = source.splitlines()
    i = 0
    while i < len(lines):
        m = FUNC.match(lines[i])
        if m:
            k = i
            while k > 0 and DOC_LINE.match(lines[k - 1]):
                k -= 1
            end = _body_end(lines, i)
            spans[_func_key(m.group(1), m.group(2))] = (k + 1, end + 1)
            i = end + 1
            continue
        i += 1
    return spans


def evaluate(changed_paths, declaration, read_head, read_base, changed_head_lines,
             vm_gate_profiles, base_toolchain, head_toolchain, changed_base_lines=None):
    violations = []
    classes = {}
    runtime_report = []
    declared = {}

    if not isinstance(declaration, dict) or declaration.get('schema') != SCHEMA:
        violations.append('scope declaration schema must be %s' % SCHEMA)
        declaration = declaration if isinstance(declaration, dict) else {}
    for entry in declaration.get('runtime_changes') or []:
        declared[entry.get('path')] = entry

    for path in sorted(changed_paths):
        cls = classify(path)
        classes.setdefault(cls, []).append(path)
        if cls in ('FORBIDDEN', 'UNCLASSIFIED'):
            violations.append('%s: %s change is not maintenance scope' % (path, cls))
        elif cls == 'S1-profile' and path.startswith('vm/profiles/'):
            profile = Path(path).stem
            if profile not in vm_gate_profiles:
                violations.append('%s: changed profile is not booted by the maintenance VM gate' % path)
        elif cls == 'S2-runtime':
            entry = declared.get(path)
            if entry is None:
                violations.append('%s: runtime change is not declared in the scope file' % path)
                continue
            source = read_head(path) or ''
            spans = function_spans(source)
            source_lines = source.splitlines()
            allowed = entry.get('functions') or []
            touched, outside = set(), []
            for line in changed_head_lines(path):
                # Whitespace-only lines carry no semantics.
                if 1 <= line <= len(source_lines) and not source_lines[line - 1].strip():
                    continue
                owner = next((name for name, (a, b) in spans.items() if a <= line <= b), None)
                if owner is None or owner not in allowed:
                    outside.append(line)
                else:
                    touched.add(owner)
            # Removed lines are judged in the BASELINE file: deleting an
            # init(), a package-level var or an undeclared function changes the
            # binary even though no line of the new file shows it.
            base_source = read_base(path) or ''
            base_spans = function_spans(base_source)
            base_lines_src = base_source.splitlines()
            removed_outside = []
            for line in (changed_base_lines(path) if changed_base_lines else []):
                if 1 <= line <= len(base_lines_src) and not base_lines_src[line - 1].strip():
                    continue
                owner = next((name for name, (a, b) in base_spans.items() if a <= line <= b), None)
                if owner is None or owner not in allowed:
                    removed_outside.append(line)
                else:
                    touched.add(owner)
            if outside:
                violations.append('%s: lines %s change code outside the declared functions %s'
                                  % (path, outside, allowed))
            if removed_outside:
                violations.append('%s: removed baseline lines %s lie outside the declared functions %s'
                                  % (path, removed_outside, allowed))
            for profile in entry.get('exercised_by') or []:
                if profile not in vm_gate_profiles:
                    violations.append('%s: exercised_by profile %s is not in the maintenance VM gate'
                                      % (path, profile))
            if not entry.get('exercised_by'):
                violations.append('%s: no VM-gate profile exercises the runtime change' % path)
            tests = entry.get('tests') or []
            if not tests:
                violations.append('%s: no tests declared for the runtime change' % path)
            for fn in allowed:
                if not any(fn in (read_head(t) or '') for t in tests):
                    violations.append('%s: no declared test references %s' % (path, fn))
            runtime_report.append({'path': path, 'changed_functions': sorted(touched),
                                   'exercised_by': entry.get('exercised_by') or [], 'tests': tests})
        if path == 'action.yml':
            base = yaml.safe_load(read_base(path) or '{}') or {}
            head = yaml.safe_load(read_head(path) or '{}') or {}
            for key in ('inputs', 'outputs'):
                if sorted((base.get(key) or {}).keys()) != sorted((head.get(key) or {}).keys()):
                    violations.append('action.yml: %s changed; the Action interface is not maintenance scope' % key)

    for path in declared:
        if path not in changed_paths:
            violations.append('%s: declared runtime change has no corresponding diff' % path)

    toolchain = declaration.get('toolchain')
    if base_toolchain != head_toolchain:
        if not isinstance(toolchain, dict):
            violations.append('toolchain changed %s -> %s without an advisory declaration'
                              % (base_toolchain, head_toolchain))
        else:
            if toolchain.get('from') != base_toolchain or toolchain.get('to') != head_toolchain:
                violations.append('toolchain declaration %s -> %s does not match actual %s -> %s'
                                  % (toolchain.get('from'), toolchain.get('to'), base_toolchain, head_toolchain))
            advisories = toolchain.get('advisories') or []
            if not advisories or not all(ADVISORY.fullmatch(str(a)) for a in advisories):
                violations.append('toolchain change must cite GO-YYYY-NNNN advisories')
    elif toolchain:
        violations.append('toolchain declaration is stale: the build toolchain did not change')

    return {
        'schema': 'bpfcompat.maintenance-scope-result.v1',
        'eligible': not violations,
        'violations': violations,
        'classes': {k: sorted(v) for k, v in sorted(classes.items())},
        'runtime_changes': runtime_report,
        'toolchain': {'baseline': base_toolchain, 'head': head_toolchain},
    }


def _git(*args):
    return subprocess.run(['git', *args], cwd=ROOT, text=True, capture_output=True)


def _changed_lines(base, path):
    """(head lines added/changed, baseline lines removed/changed), 1-based,
    for the committed diff base..HEAD. Rename detection is off so a moved
    file is a deletion plus an addition, never a silent path change."""
    out = _git('diff', '-U0', '--no-renames', base, 'HEAD', '--', path).stdout
    head, removed = [], []
    for m in re.finditer(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', out, re.M):
        b_start, b_count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
        h_start, h_count = int(m.group(3)), int(m.group(4) if m.group(4) is not None else 1)
        removed.extend(range(b_start, b_start + b_count))
        head.extend(range(h_start, h_start + h_count))
    return head, removed


def main(argv):
    metadata = yaml.safe_load((ROOT / 'release.yaml').read_text())
    base = str(metadata['stable_commit'])
    release = str(metadata['release_version']).split('-')[0]
    decl_path = ROOT / 'docs' / 'releases' / ('v%s-scope.yaml' % release)
    declaration = yaml.safe_load(decl_path.read_text()) if decl_path.exists() else None
    # The release is a commit: judge exactly base..HEAD. Untracked files
    # (build output such as dist/) are not part of it; uncommitted changes to
    # tracked files cannot be judged, so they are an error, never ignored.
    dirty = _git('status', '--porcelain', '--untracked-files=no').stdout.strip()
    if dirty:
        print('uncommitted changes to tracked files; commit them before checking scope:\n' + dirty,
              file=sys.stderr)
        sys.exit(2)
    diff = _git('diff', '--name-only', '--no-renames', base, 'HEAD')
    if diff.returncode != 0:
        print('cannot diff against stable_commit %s: %s' % (base, diff.stderr.strip()), file=sys.stderr)
        sys.exit(2)
    changed = sorted({p for p in diff.stdout.splitlines() if p})

    def read_head(path):
        p = ROOT / path
        return p.read_text() if p.is_file() else None

    def read_base(path):
        r = _git('show', '%s:%s' % (base, path))
        return r.stdout if r.returncode == 0 else None

    gate = (ROOT / 'scripts' / 'maintenance-vm-gate.sh').read_text()
    m = re.search(r'^profiles=\(([^)]*)\)', gate, re.M)
    gate_profiles = m.group(1).split() if m else []
    base_ci = read_base('.github/workflows/ci.yml') or ''
    m = re.search(r'^  GO_VERSION: "([^"]+)"', base_ci, re.M)
    base_toolchain = m.group(1) if m else ''
    head_toolchain = str(metadata.get('minimum_go', ''))

    report = evaluate(changed, declaration or {}, read_head, read_base,
                      lambda p: _changed_lines(base, p)[0], gate_profiles,
                      base_toolchain, head_toolchain,
                      changed_base_lines=lambda p: _changed_lines(base, p)[1])
    report['baseline'] = base
    report['declaration'] = str(decl_path.relative_to(ROOT))
    if '--out' in argv:
        Path(argv[argv.index('--out') + 1]).write_text(json.dumps(report, indent=2) + '\n')
    if '--json' in argv:
        print(json.dumps(report, indent=2))
    else:
        state = 'ELIGIBLE' if report['eligible'] else 'NOT ELIGIBLE'
        print('[maintenance-scope] %s baseline=%s toolchain=%s->%s' % (state, base, base_toolchain, head_toolchain))
        for v in report['violations']:
            print('  - ' + v)
    return report


if __name__ == '__main__':
    result = main(sys.argv[1:])
    sys.exit(0 if result['eligible'] else 1)
