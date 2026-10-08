"""Offline workflow wiring tests: no GitHub writes or real publication."""
import copy
import re
import unittest
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent

def workflow(name):
    # BaseLoader keeps GitHub's `on` as a key instead of YAML 1.1 boolean True.
    return yaml.load((ROOT / '.github/workflows' / name).read_text(), Loader=yaml.BaseLoader)

def check(stage, promotion, preview):
    def require(condition):
        if not condition:
            raise ValueError('unsafe release workflow wiring')
    jobs = stage['jobs']
    require(jobs['build-and-sign']['permissions']['contents'] == 'read')
    sbom = next(s for s in jobs['build-and-sign']['steps'] if s.get('name') == 'Generate SBOM')
    require(sbom['with']['path'] == 'dist')
    require(sbom['with']['syft-version'] == 'v1.54.1')
    draft = jobs['stage-draft-release']
    require(set(draft['needs']) == {'build-and-sign', 'assemble-candidate-evidence'})
    upload = next(s for s in draft['steps'] if s.get('uses', '').startswith('softprops/action-gh-release@'))
    require(upload['with']['draft'] == 'true')
    require(upload['with']['make_latest'] == 'false')
    require(upload['with']['fail_on_unmatched_files'] == 'true')
    require(set(jobs['build-candidate-image']['needs']) == {'build-and-sign', 'candidate-vm-gate', 'candidate-arm64-cli-gate'})
    image = next(s for s in jobs['build-candidate-image']['steps'] if s.get('uses', '').startswith('docker/build-push-action@'))
    require(image['with']['context'] == 'dist')
    require(image['with']['tags'] == '${{ env.IMAGE }}:candidate-${{ github.sha }}')
    require(set(promotion['on']) == {'workflow_dispatch'})
    require(promotion['jobs']['promote']['environment']['name'] == 'production-release')
    require(promotion['concurrency']['group'] == 'production-release-promotion')
    require(set(preview['on']) == {'workflow_dispatch'})
    tags = next(s for s in preview['jobs']['image']['steps'] if s.get('id') == 'docker_meta')['with']['tags'].strip()
    require(tags == 'type=raw,value=preview-${{ github.sha }}')
    for document in (stage, promotion, preview):
        for job in document['jobs'].values():
            for step in job.get('steps', []):
                action = step.get('uses', './')
                require(action.startswith('./') or re.fullmatch(r'[^@]+@[0-9a-f]{40}', action))

class ReleaseControls(unittest.TestCase):
    def setUp(self):
        self.stage = workflow('release-artifacts.yml')
        self.promotion = workflow('promote-release.yml')
        self.preview = workflow('ghcr-image.yml')

    def test_controls(self):
        check(self.stage, self.promotion, self.preview)

    def test_public_staging_rejected(self):
        stage = copy.deepcopy(self.stage)
        for step in stage['jobs']['stage-draft-release']['steps']:
            if step.get('uses', '').startswith('softprops/'):
                step['with']['draft'] = 'false'
        with self.assertRaises(ValueError):
            check(stage, self.promotion, self.preview)

    def test_bypass_vm_gate_rejected(self):
        stage = copy.deepcopy(self.stage)
        stage['jobs']['build-candidate-image']['needs'].remove('candidate-vm-gate')
        with self.assertRaises(ValueError):
            check(stage, self.promotion, self.preview)

    def test_preview_production_alias_rejected(self):
        preview = copy.deepcopy(self.preview)
        for step in preview['jobs']['image']['steps']:
            if step.get('id') == 'docker_meta':
                step['with']['tags'] = 'type=raw,value=latest'
        with self.assertRaises(ValueError):
            check(self.stage, self.promotion, preview)

    def test_no_new_runtime_fields_or_attestation_bypass(self):
        source = (ROOT / '.github/workflows/release-artifacts.yml').read_text()
        self.assertNotIn('.validator.sha256', source)
        self.assertNotIn('SKIP_READINESS_ATTESTATION', (ROOT / 'scripts/production-readiness-report.sh').read_text())
        self.assertNotIn('gh release create', (ROOT / '.github/workflows/compatibility-matrix-publish.yml').read_text())
        self.assertIn("'.release_version == $version and .gate_status ==", source)
        promotion = (ROOT / '.github/workflows/promote-release.yml').read_text()
        self.assertIn("'.release_version == $version and .gate_status ==", promotion)

if __name__ == '__main__':
    unittest.main()
