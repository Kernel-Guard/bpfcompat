"""Real-git regression tests for scripts/check-maintenance-scope.py.

Each case builds a throwaway repository containing the in-tree checker, a
stable baseline commit and one change, then runs the checker exactly as the
release gate does. The unit tests in check-maintenance-scope_test.py inject
the diff; these cover what main() derives from git itself (deletions,
renames, untracked build output, function boundaries).
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = (ROOT / 'scripts' / 'check-maintenance-scope.py').read_text()

BASE_GO = '''package vm

var insecure = false

// A doc
func A() int {
\treturn 1
}

func init() {
\tinsecure = true
}

func B() int {
\treturn 2
}

func C() int { return 3 }

var timeout = 10

func D() int {
\treturn timeout
}

type X struct{}
type Y struct{}

func (x *X) Run() int {
\treturn 1
}

func (y Y) Run() int {
\treturn 2
}

//export Exported
func E() int {
\treturn 5
}
'''

GUARD_GO = '''package vm

func init() {
\tinsecure = true
}
'''


def git(repo, *args):
    r = subprocess.run(['git', '-C', repo, *args], text=True, capture_output=True)
    if r.returncode != 0:
        raise AssertionError('git %s failed: %s' % (args, r.stderr))
    return r.stdout.strip()


def write(repo, path, text):
    p = Path(repo) / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


class RepoScope(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp(prefix='scope-repo-test-')
        self.addCleanup(shutil.rmtree, self.repo)

    def baseline(self, declared):
        repo = self.repo
        git(repo, 'init', '-q')
        git(repo, 'config', 'user.email', 'test@example.invalid')
        git(repo, 'config', 'user.name', 'test')
        write(repo, 'scripts/check-maintenance-scope.py', CHECKER)
        write(repo, 'scripts/maintenance-vm-gate.sh', 'profiles=(p1)\n')
        write(repo, '.github/workflows/ci.yml', 'env:\n  GO_VERSION: "1.26.9"\n')
        write(repo, 'release.yaml', 'stable_commit: TBD\nrelease_version: 0.3.8-rc.1\nminimum_go: 1.26.9\n')
        write(repo, 'internal/vm/qemu.go', BASE_GO)
        write(repo, 'internal/vm/guard.go', GUARD_GO)
        write(repo, 'internal/vm/qemu_test.go', '// ' + ' '.join(declared) + '\n')
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'base')
        base = git(repo, 'rev-parse', 'HEAD')
        write(repo, 'release.yaml', 'stable_commit: %s\nrelease_version: 0.3.8-rc.1\nminimum_go: 1.26.9\n' % base)
        write(repo, 'docs/releases/v0.3.8-scope.yaml',
              'schema: bpfcompat.maintenance-scope.v1\nruntime_changes:\n'
              '  - path: internal/vm/qemu.go\n    functions: [%s]\n    exercised_by: [p1]\n'
              '    tests: [internal/vm/qemu_test.go]\n' % ', '.join(declared))

    def check(self, commit=True):
        if commit:
            git(self.repo, 'add', '-A')
            git(self.repo, 'commit', '-qm', 'change')
        r = subprocess.run([sys.executable, '-I', str(Path(self.repo) / 'scripts/check-maintenance-scope.py')],
                           cwd=self.repo, text=True, capture_output=True)
        return r.returncode, r.stdout + r.stderr

    def assertEligible(self, commit=True):
        rc, out = self.check(commit)
        self.assertEqual(rc, 0, out)

    def assertIneligible(self, commit=True):
        rc, out = self.check(commit)
        self.assertEqual(rc, 1, out)
        self.assertIn('NOT ELIGIBLE', out)

    def test_change_inside_declared_function_is_eligible(self):
        self.baseline(['A'])
        write(self.repo, 'internal/vm/qemu.go', BASE_GO.replace('return 1', 'return 11', 1))
        self.assertEligible()

    def test_deleting_undeclared_init_between_declared_functions(self):
        self.baseline(['A', 'B'])
        src = BASE_GO.replace('func init() {\n\tinsecure = true\n}\n\n', '').replace('return 1', 'return 11', 1)
        write(self.repo, 'internal/vm/qemu.go', src)
        self.assertIneligible()

    def test_deleting_package_var_above_declared_doc_comment(self):
        self.baseline(['A'])
        src = BASE_GO.replace('var insecure = false\n\n', '').replace('return 1', 'return 11', 1)
        write(self.repo, 'internal/vm/qemu.go', src)
        self.assertIneligible()

    def test_one_line_function_does_not_swallow_following_code(self):
        self.baseline(['C'])
        write(self.repo, 'internal/vm/qemu.go', BASE_GO.replace('var timeout = 10', 'var timeout = 0'))
        self.assertIneligible()

    def test_change_inside_one_line_declared_function_is_eligible(self):
        self.baseline(['C'])
        write(self.repo, 'internal/vm/qemu.go', BASE_GO.replace('{ return 3 }', '{ return 4 }'))
        self.assertEligible()

    def test_method_declaration_is_receiver_qualified(self):
        self.baseline(['X.Run'])
        write(self.repo, 'internal/vm/qemu.go', BASE_GO.replace('\treturn 2\n}\n\n//export', '\treturn 3\n}\n\n//export'))
        self.assertIneligible()

    def test_change_inside_declared_method_is_eligible(self):
        self.baseline(['X.Run'])
        write(self.repo, 'internal/vm/qemu.go', BASE_GO.replace('func (x *X) Run() int {\n\treturn 1',
                                                                 'func (x *X) Run() int {\n\treturn 7'))
        self.assertEligible()

    def test_directive_above_declared_function_is_not_part_of_it(self):
        self.baseline(['E'])
        write(self.repo, 'internal/vm/qemu.go', BASE_GO.replace('//export Exported', '//export Renamed'))
        self.assertIneligible()

    def test_rename_of_runtime_file_to_test_file(self):
        self.baseline(['A'])
        write(self.repo, 'internal/vm/qemu.go', BASE_GO.replace('return 1', 'return 11', 1))
        git(self.repo, 'mv', 'internal/vm/guard.go', 'internal/vm/guard_test.go')
        self.assertIneligible()

    def test_rename_of_runtime_file_into_docs(self):
        self.baseline(['A'])
        write(self.repo, 'internal/vm/qemu.go', BASE_GO.replace('return 1', 'return 11', 1))
        git(self.repo, 'mv', 'internal/vm/guard.go', 'docs/releases/guard.go')
        self.assertIneligible()

    def test_untracked_build_output_does_not_change_the_verdict(self):
        self.baseline(['A'])
        write(self.repo, 'internal/vm/qemu.go', BASE_GO.replace('return 1', 'return 11', 1))
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-qm', 'eligible')
        write(self.repo, 'dist/bpfcompat-linux-amd64', 'binary')
        write(self.repo, 'dist/SHA256SUMS', 'x')
        self.assertEligible(commit=False)

    def test_uncommitted_tracked_change_cannot_be_assessed(self):
        self.baseline(['A'])
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-qm', 'declare')
        write(self.repo, 'internal/vm/guard.go', GUARD_GO.replace('true', 'false'))
        rc, out = self.check(commit=False)
        self.assertEqual(rc, 2, out)


if __name__ == '__main__':
    unittest.main()
