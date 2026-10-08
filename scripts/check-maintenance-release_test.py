import copy
import importlib.util
import unittest
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('guard', ROOT / 'scripts/check-maintenance-release.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

class MaintenanceIdentity(unittest.TestCase):
    def setUp(self):
        self.metadata = yaml.safe_load((ROOT / 'release.yaml').read_text())
        self.sha = 'a' * 40
        self.baseline = '179ff612ed2b5d1afb16dd9c282752028d47c415'

    def test_preparation_without_future_tag(self):
        guard.validate(self.metadata, 'refs/heads/release/v0.3.8-centos-hotfix', self.sha, self.baseline)

    def test_exact_candidate_tag(self):
        guard.validate(self.metadata, 'refs/tags/v' + self.metadata['release_version'], self.sha, self.baseline)

    def test_wrong_tag(self):
        with self.assertRaises(ValueError):
            guard.validate(self.metadata, 'refs/tags/v0.3.8-rc.999', self.sha, self.baseline)

    def test_no_premature_stable_or_schema_changes(self):
        for key, value in [('stable_version', '0.3.8'), ('stable_commit', self.sha),
                           ('report_schema', 'v0.2'), ('release_channel', 'stable')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                metadata = copy.deepcopy(self.metadata)
                metadata[key] = value
                guard.validate(metadata, '', self.sha, self.baseline)

if __name__ == '__main__':
    unittest.main()
