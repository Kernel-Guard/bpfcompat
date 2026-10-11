"""Offline workflow wiring tests: no GitHub writes or real publication."""
import copy
import os
import re
import subprocess
import tempfile
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
    steps = jobs['build-and-sign']['steps']
    supplement = next(i for i, s in enumerate(steps) if s.get('name') == 'Supplement actual native validator linker inputs')
    checksums = next(i for i, s in enumerate(steps) if s.get('name') == 'Compute checksums')
    require(supplement < checksums)
    require('NATIVE-LINK-INPUTS.json' in steps[checksums]['run'])
    quality = next(s for s in steps if s.get('name') == 'Release quality gates')['run']
    # R1: the maintenance tech gate (machine-verified scope) is mandatory, and
    # the inherited history-based gate is replaced, not silently dropped.
    require('make maintenance-tech-check' in quality)
    require('make production-tech-check' not in quality)
    native = next(s for s in steps if s.get('name') == 'Install native build dependencies')['run']
    require('release-native-snapshot.txt' in native and '--snapshot "$snapshot"' in native)
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

    def test_maintenance_tech_gate_cannot_be_dropped(self):
        stage = copy.deepcopy(self.stage)
        for step in stage['jobs']['build-and-sign']['steps']:
            if step.get('name') == 'Release quality gates':
                step['run'] = step['run'].replace('make maintenance-tech-check', 'true')
        with self.assertRaises(ValueError):
            check(stage, self.promotion, self.preview)

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

    def test_vm_evidence_paths_and_executable_payload(self):
        steps = self.stage['jobs']['candidate-vm-gate']['steps']
        upload = next(s for s in steps if s.get('name') == 'Upload release-gate evidence')
        self.assertEqual(upload['with']['path'], 'release-evidence/')
        retain = next(s for s in steps if s.get('name') == 'Retain incomplete VM evidence')['run']
        self.assertIn('release-evidence/reports', retain)
        self.assertIn('$GITHUB_WORKSPACE/release-evidence/', retain)
        self.assertNotIn('id_ed25519', retain)
        self.assertIn('COPY --chmod=0755', (ROOT / 'Dockerfile.release').read_text())

    def test_incomplete_evidence_retention_excludes_keys(self):
        steps = self.stage['jobs']['candidate-vm-gate']['steps']
        command = next(s for s in steps if s.get('name') == 'Retain incomplete VM evidence')['run']
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workspace = base / 'workspace'
            workspace.mkdir()
            source = base / 'maintenance-1-1'
            target = source / 'positive-work/runs/fixture/targets/centos'
            target.mkdir(parents=True)
            (target / 'serial.log').write_text('fixture diagnostic')
            (target / 'id_ed25519').write_text('fixture must not be retained')
            (source / 'reports').mkdir()
            (source / 'reports/release-positive.json').write_text('{}')
            env = dict(os.environ, RUNNER_TEMP=tmp, GITHUB_WORKSPACE=str(workspace), GITHUB_RUN_ID='1', GITHUB_RUN_ATTEMPT='1')
            subprocess.run(['bash', '-c', command], cwd=workspace, env=env, check=True)
            retained = workspace / 'release-evidence'
            self.assertTrue((retained / 'reports/release-positive.json').exists())
            self.assertTrue((retained / 'positive-work/runs/fixture/targets/centos/serial.log').exists())
            self.assertEqual(list(retained.rglob('id_ed25519')), [])

if __name__ == '__main__':
    unittest.main()
