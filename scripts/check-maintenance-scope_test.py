import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('scope', ROOT / 'scripts/check-maintenance-scope.py')
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)

QEMU = '''package vm

func helper() int {
	return 1
}

func guestKernelInstallCmdRHEL(release string) string {
	return release
}

func isCentOS725SignedPackageSet(release string) bool {
	return true
}

func unrelated() {
}
'''
ADVISORIES = ['GO-2026-6610']
DECLARATION = {
    'schema': 'bpfcompat.maintenance-scope.v1',
    'runtime_changes': [{
        'path': 'internal/vm/qemu.go',
        'functions': ['guestKernelInstallCmdRHEL', 'isCentOS725SignedPackageSet'],
        'exercised_by': ['centos-stream-9-5.14-k5.14.0-725.el9'],
        'tests': ['internal/vm/centos725_restriction_test.go'],
    }],
    'toolchain': {'from': '1.25.14', 'to': '1.26.9', 'advisories': ADVISORIES},
}
NO_RUNTIME = {k: v for k, v in DECLARATION.items() if k != 'runtime_changes'}
TEST_FILE = 'func TestX() { guestKernelInstallCmdRHEL(""); isCentOS725SignedPackageSet("") }'
GATE = ['centos-stream-9-5.14', 'centos-stream-10-6.12', 'centos-stream-9-5.14-k5.14.0-725.el9']
ACTION = 'inputs:\n  artifact: {}\n  matrix: {}\noutputs: {}\nruns: {using: composite}\n'


class FakeRepo:
    """Injected view of baseline/HEAD: files, changed paths, changed HEAD lines."""

    def __init__(self, changed, head_files=None, base_files=None, changed_lines=None,
                 base_go='1.25.14', head_go='1.26.9'):
        self.changed = changed
        self.head_files = {'internal/vm/qemu.go': QEMU,
                           'internal/vm/centos725_restriction_test.go': TEST_FILE,
                           'action.yml': ACTION}
        self.head_files.update(head_files or {})
        self.base_files = {'action.yml': ACTION}
        self.base_files.update(base_files or {})
        self.changed_lines = changed_lines or {}
        self.base_go = base_go
        self.head_go = head_go


def run(repo, declaration=None):
    return scope.evaluate(
        changed_paths=repo.changed,
        declaration=copy.deepcopy(DECLARATION if declaration is None else declaration),
        read_head=repo.head_files.get,
        read_base=repo.base_files.get,
        changed_head_lines=lambda path: repo.changed_lines.get(path, []),
        vm_gate_profiles=GATE,
        base_toolchain=repo.base_go,
        head_toolchain=repo.head_go,
    )


class Classification(unittest.TestCase):
    def test_classes(self):
        cases = {
            'vm/profiles/centos-stream-9-5.14.yaml': 'S1-profile',
            'Makefile': 'S1-profile',
            'internal/vm/qemu.go': 'S2-runtime',
            'cmd/bpfcompat/main.go': 'S2-runtime',
            '.github/workflows/release-artifacts.yml': 'S3-release-tooling',
            'scripts/maintenance-vm-gate.sh': 'S3-release-tooling',
            'action.yml': 'S3-release-tooling',
            'release.yaml': 'S3-release-tooling',
            'Dockerfile.release': 'S3-release-tooling',
            'internal/vm/centos_urls_test.go': 'S5-docs-tests',
            'scripts/x_test.py': 'S5-docs-tests',
            'docs/releases/v0.3.8.md': 'S5-docs-tests',
            'CHANGELOG.md': 'S5-docs-tests',
            'go.mod': 'FORBIDDEN',
            'go.sum': 'FORBIDDEN',
            'vendor/github.com/x/y.go': 'FORBIDDEN',
            'validator/c-libbpf/src/main.c': 'FORBIDDEN',
            'pkg/schema/report_v0_1.go': 'FORBIDDEN',
            'research/data/v1/SHA256SUMS': 'FORBIDDEN',
            'scripts/research/materialize-v1.sh': 'FORBIDDEN',
            'some/new/thing.bin': 'UNCLASSIFIED',
        }
        for path, want in cases.items():
            with self.subTest(path=path):
                self.assertEqual(scope.classify(path), want)


class Eligibility(unittest.TestCase):
    def test_declared_targeted_runtime_change_is_eligible(self):
        report = run(FakeRepo(['internal/vm/qemu.go', 'release.yaml'],
                              changed_lines={'internal/vm/qemu.go': [8, 12]}))
        self.assertTrue(report['eligible'], report['violations'])
        self.assertEqual(report['runtime_changes'][0]['changed_functions'],
                         ['guestKernelInstallCmdRHEL', 'isCentOS725SignedPackageSet'])

    def test_forbidden_path_is_ineligible(self):
        for path in ['go.sum', 'validator/c-libbpf/src/main.c', 'pkg/schema/report_v0_1.go',
                     'research/data/v1/SHA256SUMS']:
            with self.subTest(path=path):
                report = run(FakeRepo([path]))
                self.assertFalse(report['eligible'])

    def test_unclassified_path_is_ineligible(self):
        self.assertFalse(run(FakeRepo(['some/new/thing.bin']))['eligible'])

    def test_undeclared_runtime_file_is_ineligible(self):
        report = run(FakeRepo(['internal/runner/runner.go'],
                              head_files={'internal/runner/runner.go': 'package runner\n\nfunc Run() {\n}\n'},
                              changed_lines={'internal/runner/runner.go': [3]}))
        self.assertFalse(report['eligible'])

    def test_change_outside_declared_functions_is_ineligible(self):
        for line, label in [(3, 'helper'), (16, 'unrelated'), (1, 'package clause')]:
            with self.subTest(where=label):
                report = run(FakeRepo(['internal/vm/qemu.go'],
                                      changed_lines={'internal/vm/qemu.go': [line]}))
                self.assertFalse(report['eligible'], label)

    def test_runtime_change_must_be_exercised_by_the_vm_gate(self):
        declaration = copy.deepcopy(DECLARATION)
        declaration['runtime_changes'][0]['exercised_by'] = ['ubuntu-22.04-5.15']
        report = run(FakeRepo(['internal/vm/qemu.go'], changed_lines={'internal/vm/qemu.go': [8]}),
                     declaration)
        self.assertFalse(report['eligible'])

    def test_runtime_change_must_name_tests_that_reference_each_function(self):
        repo = FakeRepo(['internal/vm/qemu.go'], changed_lines={'internal/vm/qemu.go': [8]},
                        head_files={'internal/vm/centos725_restriction_test.go': 'func TestX() {}'})
        self.assertFalse(run(repo)['eligible'])
        declaration = copy.deepcopy(DECLARATION)
        declaration['runtime_changes'][0]['tests'] = ['internal/vm/missing_test.go']
        repo = FakeRepo(['internal/vm/qemu.go'], changed_lines={'internal/vm/qemu.go': [8]})
        self.assertFalse(run(repo, declaration)['eligible'])

    def test_changed_profile_must_be_booted_by_the_vm_gate(self):
        self.assertTrue(run(FakeRepo(['vm/profiles/centos-stream-10-6.12.yaml']), NO_RUNTIME)['eligible'])
        self.assertFalse(run(FakeRepo(['vm/profiles/ubuntu-22.04-5.15.yaml']), NO_RUNTIME)['eligible'])

    def test_action_inputs_and_outputs_must_not_change(self):
        changed = ACTION.replace('  matrix: {}\n', '  matrix: {}\n  new-input: {}\n')
        self.assertFalse(run(FakeRepo(['action.yml'], head_files={'action.yml': changed}))['eligible'])
        steps_only = ACTION.replace('runs: {using: composite}', 'runs: {using: composite, steps: []}')
        self.assertTrue(run(FakeRepo(['action.yml'], head_files={'action.yml': steps_only}), NO_RUNTIME)['eligible'])

    def test_toolchain_change_requires_matching_advisory_declaration(self):
        self.assertTrue(run(FakeRepo(['release.yaml']), NO_RUNTIME)['eligible'])
        for key, value in [('to', '1.27.0'), ('from', '1.25.12'), ('advisories', []),
                           ('advisories', ['not-an-id'])]:
            with self.subTest(**{key: value}):
                declaration = copy.deepcopy(NO_RUNTIME)
                declaration['toolchain'][key] = value
                self.assertFalse(run(FakeRepo(['release.yaml']), declaration)['eligible'])
        declaration = copy.deepcopy(NO_RUNTIME)
        del declaration['toolchain']
        self.assertFalse(run(FakeRepo(['release.yaml']), declaration)['eligible'])

    def test_stale_toolchain_declaration_is_rejected(self):
        report = run(FakeRepo(['release.yaml'], base_go='1.26.9', head_go='1.26.9'), NO_RUNTIME)
        self.assertFalse(report['eligible'])

    def test_declared_runtime_change_without_a_diff_is_stale(self):
        report = run(FakeRepo(['release.yaml']))
        self.assertFalse(report['eligible'])
        self.assertTrue(any('no corresponding diff' in v for v in report['violations']))

    def test_wrong_schema_is_rejected(self):
        declaration = copy.deepcopy(DECLARATION)
        declaration['schema'] = 'something-else'
        self.assertFalse(run(FakeRepo(['CHANGELOG.md']), declaration)['eligible'])


DOC = '''package vm

// isCentOS725SignedPackageSet limits the exception.
// Second doc line.
func isCentOS725SignedPackageSet(release string) bool {
	return true
}

// A detached comment about nothing in particular.

//go:noinline
func guestKernelInstallCmdRHEL(release string) string {
	return release
}
'''


class CommentsAndBlankLines(unittest.TestCase):
    def check(self, lines):
        repo = FakeRepo(['internal/vm/qemu.go'], head_files={'internal/vm/qemu.go': DOC},
                        changed_lines={'internal/vm/qemu.go': lines})
        return run(repo)

    def test_attached_doc_comment_belongs_to_its_function(self):
        self.assertTrue(self.check([3, 4, 6])['eligible'])

    def test_blank_separator_lines_are_inert(self):
        self.assertTrue(self.check([8])['eligible'])

    def test_detached_comment_is_outside_any_function(self):
        self.assertFalse(self.check([9])['eligible'])

    def test_go_directive_is_never_inert(self):
        # A //go: line changes build/link semantics even above a declared function.
        self.assertFalse(self.check([11])['eligible'])


class FunctionSpans(unittest.TestCase):
    def test_spans(self):
        spans = scope.function_spans(QEMU)
        self.assertEqual(spans['helper'], (3, 5))
        self.assertEqual(spans['guestKernelInstallCmdRHEL'], (7, 9))
        self.assertEqual(spans['unrelated'], (15, 16))


class RepositoryState(unittest.TestCase):
    def test_committed_maintenance_scope_is_eligible(self):
        report = scope.main(['--json'])
        self.assertTrue(report['eligible'], report['violations'])


if __name__ == '__main__':
    unittest.main()
