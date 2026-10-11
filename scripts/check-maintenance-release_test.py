import copy
import importlib.util
import unittest
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('guard', ROOT / 'scripts/check-maintenance-release.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

STABLE = '179ff612ed2b5d1afb16dd9c282752028d47c415'
HEAD = 'a' * 40
OTHER = 'b' * 40


def tags(mapping):
    """Fake tag resolver: tag name -> peeled commit, None when absent."""
    return lambda name: mapping.get(name)


def ancestry(pairs):
    """Fake ancestry check: (ancestor, descendant) pairs that hold."""
    return lambda a, d: (a, d) in pairs


class MaintenanceIdentity(unittest.TestCase):
    def setUp(self):
        self.metadata = yaml.safe_load((ROOT / 'release.yaml').read_text())
        self.resolve = tags({'v0.3.7': STABLE})
        self.is_ancestor = ancestry({(STABLE, HEAD)})

    def run_validate(self, metadata=None, ref='', head=HEAD, resolve=None, is_ancestor=None):
        guard.validate(metadata or self.metadata, ref, head,
                       resolve or self.resolve, is_ancestor or self.is_ancestor)

    # --- positive -----------------------------------------------------------
    def test_preparation_without_future_tag(self):
        self.run_validate(ref='refs/heads/release/v0.3.8-centos-hotfix')

    def test_exact_candidate_tag(self):
        self.run_validate(ref='refs/tags/v' + self.metadata['release_version'])

    def test_generalized_next_maintenance_cycle(self):
        # No version constants: the next cycle (stable 0.3.8 -> 0.3.9-rc.1)
        # validates with only release.yaml and the published tag changed.
        metadata = copy.deepcopy(self.metadata)
        metadata.update(stable_version='0.3.8', stable_commit=OTHER,
                        release_version='0.3.9-rc.1', release_channel='prerelease')
        self.run_validate(metadata=metadata, resolve=tags({'v0.3.8': OTHER}),
                          is_ancestor=ancestry({(OTHER, HEAD)}))

    def test_stable_maintenance_target(self):
        metadata = copy.deepcopy(self.metadata)
        metadata.update(release_version='0.3.8', release_channel='stable')
        self.run_validate(metadata=metadata, ref='refs/tags/v0.3.8')

    # --- negative: published stable identity --------------------------------
    def test_stable_commit_must_match_published_tag(self):
        with self.assertRaisesRegex(ValueError, 'published stable tag'):
            self.run_validate(resolve=tags({'v0.3.7': OTHER}))

    def test_stable_tag_must_exist(self):
        with self.assertRaisesRegex(ValueError, 'is not published'):
            self.run_validate(resolve=tags({}))

    def test_stable_commit_must_be_ancestor_of_head(self):
        with self.assertRaisesRegex(ValueError, 'ancestor'):
            self.run_validate(is_ancestor=ancestry(set()))

    def test_stable_version_must_be_plain_semver(self):
        for bad in ['0.3', '0.3.7-rc.1', 'v0.3.7', '0.3.07', '']:
            with self.subTest(stable_version=bad), self.assertRaises(ValueError):
                metadata = copy.deepcopy(self.metadata)
                metadata['stable_version'] = bad
                self.run_validate(metadata=metadata, resolve=tags({'v' + bad: STABLE}))

    def test_stable_commit_must_be_full_sha(self):
        metadata = copy.deepcopy(self.metadata)
        metadata['stable_commit'] = STABLE[:12]
        with self.assertRaises(ValueError):
            self.run_validate(metadata=metadata, resolve=tags({'v0.3.7': STABLE[:12]}))

    # --- negative: maintenance scope ----------------------------------------
    def test_release_must_be_next_patch_of_stable(self):
        for bad in ['0.3.7', '0.3.7-rc.1', '0.3.9', '0.4.0-rc.1', '1.0.0', '0.3.6']:
            with self.subTest(release_version=bad), self.assertRaises(ValueError):
                metadata = copy.deepcopy(self.metadata)
                metadata['release_version'] = bad
                metadata['release_channel'] = 'prerelease' if '-rc.' in bad else 'stable'
                self.run_validate(metadata=metadata)

    def test_channel_must_match_release_version(self):
        metadata = copy.deepcopy(self.metadata)
        metadata['release_channel'] = 'stable'
        with self.assertRaises(ValueError):
            self.run_validate(metadata=metadata)

    def test_wrong_tag(self):
        with self.assertRaisesRegex(ValueError, 'tag does not match'):
            self.run_validate(ref='refs/tags/v0.3.8-rc.999')

    def test_fixed_policy_fields(self):
        for key, value in [('report_schema', 'v0.2'), ('minimum_go', '1.25.12'),
                           ('release_operator', 'someone-else'), ('approval_mode', 'two-person')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                metadata = copy.deepcopy(self.metadata)
                metadata[key] = value
                self.run_validate(metadata=metadata)

    def test_head_must_be_full_sha(self):
        with self.assertRaises(ValueError):
            self.run_validate(head='abc')


class CanaryStablePin(unittest.TestCase):
    def test_single_matching_pin(self):
        text = 'uses: Kernel-Guard/bpfcompat@%s # v0.3.7; bpfcompat-pin: stable\n' % STABLE
        guard.check_canary_pin(text, '0.3.7', STABLE)

    def test_pin_must_name_stable_commit(self):
        text = 'uses: Kernel-Guard/bpfcompat@%s # v0.3.7; bpfcompat-pin: stable\n' % OTHER
        with self.assertRaisesRegex(ValueError, 'consumer pin'):
            guard.check_canary_pin(text, '0.3.7', STABLE)

    def test_pin_comment_must_name_stable_version(self):
        text = 'uses: Kernel-Guard/bpfcompat@%s # v0.3.6; bpfcompat-pin: stable\n' % STABLE
        with self.assertRaisesRegex(ValueError, 'consumer pin'):
            guard.check_canary_pin(text, '0.3.7', STABLE)

    def test_exactly_one_stable_pin(self):
        line = 'uses: Kernel-Guard/bpfcompat@%s # v0.3.7; bpfcompat-pin: stable\n' % STABLE
        for text in ['', line * 2]:
            with self.subTest(count=text.count('\n')), self.assertRaises(ValueError):
                guard.check_canary_pin(text, '0.3.7', STABLE)


class RepositoryState(unittest.TestCase):
    def test_committed_metadata_and_canary_pass(self):
        # The real release.yaml + consumer-canary.yml + v0.3.7 tag in this clone.
        guard.main()


if __name__ == '__main__':
    unittest.main()
