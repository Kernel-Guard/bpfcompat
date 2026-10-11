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


FUNC = re.compile(r'^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*[\[(]')


def function_spans(source):
    """Top-level func name -> (first line, closing-brace line), 1-based."""
    spans = {}
    lines = source.splitlines()
    i = 0
    while i < len(lines):
        m = FUNC.match(lines[i])
        if m:
            # The doc comment directly attached above a function belongs to
            # it. A `//go:` directive never does: it changes build or link
            # semantics, so it must stay outside and be judged on its own.
            k = i
            while k > 0 and lines[k - 1].startswith('//') and not lines[k - 1].startswith('//go:'):
                k -= 1
            start = k + 1
            j = i
            while j < len(lines) and lines[j] != '}':
                j += 1
            spans[m.group(1)] = (start, j + 1)
            i = j + 1
            continue
        i += 1
    return spans


def evaluate(changed_paths, declaration, read_head, read_base, changed_head_lines,
             vm_gate_profiles, base_toolchain, head_toolchain):
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
            if outside:
                violations.append('%s: lines %s change code outside the declared functions %s'
                                  % (path, outside, allowed))
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
    out = _git('diff', '-U0', base, '--', path).stdout
    lines = []
    for m in re.finditer(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', out, re.M):
        start, count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
        if count == 0:
            # Pure deletion after line `start`: both neighbours must be owned.
            lines.extend([max(start, 1), start + 1])
        else:
            lines.extend(range(start, start + count))
    return lines


def main(argv):
    metadata = yaml.safe_load((ROOT / 'release.yaml').read_text())
    base = str(metadata['stable_commit'])
    release = str(metadata['release_version']).split('-')[0]
    decl_path = ROOT / 'docs' / 'releases' / ('v%s-scope.yaml' % release)
    declaration = yaml.safe_load(decl_path.read_text()) if decl_path.exists() else None
    diff = _git('diff', '--name-only', base)
    if diff.returncode != 0:
        print('cannot diff against stable_commit %s: %s' % (base, diff.stderr.strip()), file=sys.stderr)
        sys.exit(2)
    changed = [p for p in diff.stdout.splitlines() if p]
    changed += [p for p in _git('ls-files', '--others', '--exclude-standard').stdout.splitlines()
                if p and classify(p) != 'S5-docs-tests' or p.endswith('_test.go')]
    changed = sorted(set(changed))

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
                      lambda p: _changed_lines(base, p), gate_profiles,
                      base_toolchain, head_toolchain)
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
