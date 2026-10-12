"""Tests for scripts/maintenance-evidence-summary.py (R3).

The summary is the attested subject of one maintenance-evidence run (E0 or
E1). It must refuse to produce evidence -- never "failed" evidence a later
step could mistake for a pass -- whenever the run is not bound to the exact
candidate or any acceptance criterion fails.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('summary', ROOT / 'scripts' / 'maintenance-evidence-summary.py')
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)

COMMIT = 'c' * 40
TAG = 'v0.3.8-rc.1'
DIGEST = 'sha256:' + 'd' * 64
BASELINE = '179ff612ed2b5d1afb16dd9c282752028d47c415'
K725 = 'centos-stream-9-5.14-k5.14.0-725.el9'
PROFILES = ['centos-stream-9-5.14', 'centos-stream-10-6.12', K725]


def target(profile, status, load):
    kernel = '5.14.0-725.el9.x86_64' if profile == K725 else '5.14.0-500.el9.x86_64'
    return {'profile_id': profile, 'required': True, 'status': status,
            'host': {'kernel': kernel}, 'validation': {'load_status': load}}


def inputs():
    return {
        'milestone': 'e0', 'repository': 'Kernel-Guard/bpfcompat',
        'workflow_ref': 'Kernel-Guard/bpfcompat/.github/workflows/maintenance-evidence.yml@refs/tags/' + TAG,
        'run_id': 42, 'run_attempt': 1, 'started_at': '2026-10-13T10:00:00Z',
        'completed_at': '2026-10-13T11:00:00Z',
        'candidate': {'tag': TAG, 'commit_sha': COMMIT, 'image_digest': DIGEST,
                      'checksums_sha256': 'e' * 64, 'evidence_sha256': 'f' * 64},
        'scope': {'schema': 'bpfcompat.maintenance-scope-result.v1', 'eligible': True,
                  'violations': [], 'baseline': BASELINE},
        'identity': {'source_commit': COMMIT, 'positive_exit': 0, 'negative_exit': 2,
                     'cli_sha256': '1' * 64, 'validator_sha256': '2' * 64},
        'positive': {'schema_version': 'v0.1', 'summary': {'status': 'pass'},
                     'targets': [target(p, 'pass', 'pass') for p in PROFILES]},
        'negative': {'schema_version': 'v0.1', 'summary': {'status': 'fail'},
                     'targets': [target(p, 'fail', 'fail') for p in PROFILES]},
        'canary': {
            'clean-install': {'check': 'clean-install', 'status': 'pass', 'version': TAG, 'commit': COMMIT},
            'candidate-action': {'check': 'candidate-action', 'status': 'pass', 'version': TAG, 'commit': COMMIT},
            'container': {'check': 'container', 'status': 'pass', 'version': TAG, 'commit': COMMIT, 'digest': DIGEST},
        },
    }


class Summary(unittest.TestCase):
    def assertRejected(self, data, fragment):
        evidence, violations = summary.build(data)
        self.assertIsNone(evidence)
        self.assertTrue(any(fragment in v for v in violations), violations)

    def test_accepts_bound_passing_run(self):
        evidence, violations = summary.build(inputs())
        self.assertEqual(violations, [])
        self.assertEqual(evidence['marker'], '[bpfcompat-maintenance-evidence:v1]')
        self.assertEqual(evidence['tag'], TAG)
        self.assertEqual(evidence['commit_sha'], COMMIT)
        self.assertEqual(evidence['image_digest'], DIGEST)
        self.assertEqual(evidence['acceptance']['status'], 'pass')
        self.assertEqual(evidence['scope']['baseline'], BASELINE)
        self.assertNotIn('attested', evidence)

    def test_rejects_unknown_milestone(self):
        data = inputs(); data['milestone'] = 'e2'
        self.assertRejected(data, 'milestone')

    def test_rejects_non_rc_tag(self):
        data = inputs(); data['candidate']['tag'] = 'v0.3.8'
        self.assertRejected(data, 'tag')

    def test_rejects_third_party_repository(self):
        data = inputs(); data['repository'] = 'falcosecurity/libs'
        self.assertRejected(data, 'repository')

    def test_rejects_foreign_workflow(self):
        data = inputs(); data['workflow_ref'] = data['workflow_ref'].replace('maintenance-evidence', 'ci')
        self.assertRejected(data, 'workflow')

    def test_rejects_workflow_on_other_ref(self):
        data = inputs(); data['workflow_ref'] = data['workflow_ref'].replace('refs/tags/' + TAG, 'refs/heads/main')
        self.assertRejected(data, 'workflow')

    def test_rejects_ineligible_scope(self):
        data = inputs(); data['scope']['eligible'] = False
        self.assertRejected(data, 'scope')

    def test_rejects_vm_run_on_other_commit(self):
        data = inputs(); data['identity']['source_commit'] = 'a' * 40
        self.assertRejected(data, 'commit')

    def test_rejects_positive_failure(self):
        data = inputs(); data['positive']['targets'][0]['status'] = 'fail'
        self.assertRejected(data, 'positive')

    def test_rejects_positive_infra_error(self):
        data = inputs(); data['positive']['targets'][1]['infra_error'] = 'boot timeout'
        self.assertRejected(data, 'infra')

    def test_rejects_missing_exact_kernel_725(self):
        data = inputs(); data['positive']['targets'][2]['host']['kernel'] = '5.14.0-726.el9.x86_64'
        self.assertRejected(data, '725')

    def test_rejects_rubber_stamp_negative(self):
        # A negative control that passes proves nothing.
        data = inputs(); data['negative']['targets'][0]['status'] = 'pass'
        self.assertRejected(data, 'negative')

    def test_rejects_negative_infra_error(self):
        data = inputs(); data['negative']['targets'][0]['infra_error'] = 'qemu died'
        self.assertRejected(data, 'infra')

    def test_rejects_missing_canary_check(self):
        data = inputs(); del data['canary']['container']
        self.assertRejected(data, 'container')

    def test_rejects_canary_bound_to_other_candidate(self):
        data = inputs(); data['canary']['container']['digest'] = 'sha256:' + '0' * 64
        self.assertRejected(data, 'container')

    def test_rejects_failed_canary(self):
        data = inputs(); data['canary']['clean-install']['status'] = 'fail'
        self.assertRejected(data, 'clean-install')

    def test_rejects_completion_before_start(self):
        data = inputs(); data['completed_at'] = '2026-10-13T09:00:00Z'
        self.assertRejected(data, 'completed_at')

    def test_main_writes_nothing_on_rejection(self):
        data = inputs(); data['negative']['summary']['status'] = 'pass'
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'in.json'; out = Path(tmp) / 'out.json'
            src.write_text(json.dumps(data))
            self.assertEqual(summary.main([str(src), str(out)]), 1)
            self.assertFalse(out.exists())

    def test_main_writes_evidence_on_acceptance(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'in.json'; out = Path(tmp) / 'out.json'
            src.write_text(json.dumps(inputs()))
            self.assertEqual(summary.main([str(src), str(out)]), 0)
            self.assertEqual(json.loads(out.read_text())['milestone'], 'e0')


if __name__ == '__main__':
    unittest.main()
