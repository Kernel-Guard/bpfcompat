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
    # Called directly, not via make: a Makefile change is a profile-class
    # change in the scope check and must not be able to redefine the gate.
    require(re.search(r'^\s*bash scripts/maintenance-tech-check\.sh\s*$', quality, re.M))
    require('make maintenance-tech-check' not in quality)
    require('make production-tech-check' not in quality)
    # Readiness verifies attestations and runs with gh: it needs a token.
    readiness = next(s for s in steps if s.get('name') == 'Stage production readiness evidence')
    require(readiness['env'].get('GH_TOKEN') == '${{ github.token }}')
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

WRITE_SCOPES = ('id-token', 'attestations')


def check_maintenance_evidence(doc):
    """R3: producer evidence is dispatch-only, rc-tag-bound and least-privilege."""
    def require(condition):
        if not condition:
            raise ValueError('unsafe maintenance-evidence wiring')
    require(set(doc['on']) == {'workflow_dispatch'})
    require(doc['permissions'] == {'contents': 'read'})
    jobs = doc['jobs']
    for name, job in jobs.items():
        for scope, level in (job.get('permissions') or {}).items():
            if level == 'write':
                require(name == 'attest' and scope in WRITE_SCOPES)
    guard = next(s for s in jobs['bind']['steps'] if s.get('id') == 'guard')['run']
    require(r'^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*$' in guard)
    require('"$GITHUB_SHA" == "$EXPECTED_COMMIT"' in guard)
    bind = '\n'.join(s.get('run', '') for s in jobs['bind']['steps'])
    require('scripts/verify-release-assets.sh' in bind and 'gh attestation verify' in bind)
    require('scripts/check-maintenance-scope.py' in bind)
    require(set(jobs['attest']['needs']) == {'bind', 'vm', 'clean-install', 'candidate-action', 'container'})
    require('scripts/maintenance-vm-gate.sh' in '\n'.join(s.get('run', '') for s in jobs['vm']['steps']))
    # The installer re-downloads by tag; release assets are mutable, so the
    # installed bytes must equal the bind job's attestation-verified assets.
    install = jobs['clean-install']
    require('bind' in install['needs'])
    require(any(s.get('uses', '').startswith('actions/download-artifact@') and
                s['with']['name'].startswith('maintenance-candidate-') for s in install['steps']))
    install_run = '\n'.join(s.get('run', '') for s in install['steps'])
    require('cmp "$root/bin/bpfcompat" "$RUNNER_TEMP/candidate/bpfcompat-linux-amd64"' in install_run)
    require('cmp "$root/libexec/bpfcompat-validator" "$RUNNER_TEMP/candidate/bpfcompat-validator-static-linux-amd64"' in install_run)
    attest = jobs['attest']['steps']
    require(any('scripts/maintenance-evidence-summary.py' in s.get('run', '') for s in attest))
    require(any(s.get('uses', '').startswith('actions/attest-build-provenance@') and
                'evidence/maintenance-evidence.json' in s['with']['subject-path'] for s in attest))
    for job in jobs.values():
        for step in job.get('steps', []):
            action = step.get('uses', './')
            require(action.startswith('./') or re.fullmatch(r'[^@]+@[0-9a-f]{40}', action))


def check_rollback_drill(doc):
    """P4: the drill writes only GHCR, only from the maintenance branch, behind
    the protected environment, and always attempts restoration."""
    def require(condition):
        if not condition:
            raise ValueError('unsafe rollback-drill wiring')
    require(set(doc['on']) == {'workflow_dispatch'})
    require(doc['permissions'] == {'contents': 'read'})
    require(doc['concurrency']['group'] == 'production-rollback-drill')
    require(doc['env']['IMAGE'] == 'ghcr.io/kernel-guard/bpfcompat')
    require(doc['env']['DRILL_ALLOWED_REF'] == 'refs/heads/release/v0.3.8-centos-hotfix')
    require(set(doc['jobs']) == {'rollback'})
    job = doc['jobs']['rollback']
    require(job['environment']['name'] == 'production-drill')
    require(job['permissions'] == {'contents': 'read', 'packages': 'write'})
    steps = job['steps']
    runs = [s.get('run', '') for s in steps]
    order = [next(i for i, r in enumerate(runs) if 'rollback-drill.sh ' + sub in r)
             for sub in ('validate', 'verify', 'drill', 'verify-evidence')]
    require(order == sorted(order))
    login = next(i for i, s in enumerate(steps) if s.get('uses', '').startswith('docker/login-action@'))
    require(order[0] < login)
    restore = next(s for s in steps if 'rollback-drill.sh restore' in s.get('run', ''))
    require('failure()' in restore.get('if', '') and 'cancelled()' in restore.get('if', ''))
    for step in steps:
        require('gh release' not in step.get('run', '') and 'git push' not in step.get('run', ''))
        action = step.get('uses', './')
        require(action.startswith('./') or re.fullmatch(r'[^@]+@[0-9a-f]{40}', action))


class ReleaseControls(unittest.TestCase):
    def setUp(self):
        self.stage = workflow('release-artifacts.yml')
        self.promotion = workflow('promote-release.yml')
        self.preview = workflow('ghcr-image.yml')

    def test_controls(self):
        check(self.stage, self.promotion, self.preview)

    def test_maintenance_evidence_controls(self):
        check_maintenance_evidence(workflow('maintenance-evidence.yml'))

    def test_maintenance_evidence_push_trigger_rejected(self):
        doc = workflow('maintenance-evidence.yml')
        doc['on']['push'] = {'branches': ['main']}
        with self.assertRaises(ValueError):
            check_maintenance_evidence(doc)

    def test_maintenance_evidence_write_scope_rejected(self):
        doc = workflow('maintenance-evidence.yml')
        doc['jobs']['bind']['permissions']['contents'] = 'write'
        with self.assertRaises(ValueError):
            check_maintenance_evidence(doc)

    def test_maintenance_evidence_without_vm_gate_rejected(self):
        doc = workflow('maintenance-evidence.yml')
        doc['jobs']['attest']['needs'].remove('vm')
        with self.assertRaises(ValueError):
            check_maintenance_evidence(doc)

    def test_maintenance_evidence_clean_install_byte_binding_required(self):
        doc = workflow('maintenance-evidence.yml')
        for step in doc['jobs']['clean-install']['steps']:
            if 'run' in step:
                step['run'] = '\n'.join(l for l in step['run'].splitlines() if not l.strip().startswith('cmp '))
        with self.assertRaises(ValueError):
            check_maintenance_evidence(doc)

    def test_maintenance_evidence_ref_guard_cannot_be_dropped(self):
        doc = workflow('maintenance-evidence.yml')
        for step in doc['jobs']['bind']['steps']:
            if step.get('id') == 'guard':
                step['run'] = 'true'
        with self.assertRaises(ValueError):
            check_maintenance_evidence(doc)

    def test_scope_check_command_is_never_overridden_in_workflows(self):
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            self.assertNotIn('BPFCOMPAT_SCOPE_CHECK_CMD', path.read_text(), path.name)

    def test_rollback_drill_controls(self):
        check_rollback_drill(workflow('rollback-drill.yml'))

    def test_rollback_drill_from_main_rejected(self):
        doc = workflow('rollback-drill.yml')
        doc['env']['DRILL_ALLOWED_REF'] = 'refs/heads/main'
        with self.assertRaises(ValueError):
            check_rollback_drill(doc)

    def test_rollback_drill_without_environment_rejected(self):
        doc = workflow('rollback-drill.yml')
        del doc['jobs']['rollback']['environment']
        with self.assertRaises(KeyError):
            check_rollback_drill(doc)

    def test_rollback_drill_extra_write_scope_rejected(self):
        doc = workflow('rollback-drill.yml')
        doc['jobs']['rollback']['permissions']['contents'] = 'write'
        with self.assertRaises(ValueError):
            check_rollback_drill(doc)

    def test_rollback_drill_restore_on_cancel_cannot_be_dropped(self):
        doc = workflow('rollback-drill.yml')
        for step in doc['jobs']['rollback']['steps']:
            if 'rollback-drill.sh restore' in step.get('run', ''):
                step['if'] = 'failure()'
        with self.assertRaises(ValueError):
            check_rollback_drill(doc)

    def test_rollback_drill_validation_before_registry_login(self):
        doc = workflow('rollback-drill.yml')
        steps = doc['jobs']['rollback']['steps']
        validate = next(s for s in steps if 'rollback-drill.sh validate' in s.get('run', ''))
        steps.remove(validate)
        steps.append(validate)
        with self.assertRaises(ValueError):
            check_rollback_drill(doc)

    def test_maintenance_tech_gate_cannot_be_dropped(self):
        stage = copy.deepcopy(self.stage)
        for step in stage['jobs']['build-and-sign']['steps']:
            if step.get('name') == 'Release quality gates':
                step['run'] = step['run'].replace('bash scripts/maintenance-tech-check.sh', 'true')
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
