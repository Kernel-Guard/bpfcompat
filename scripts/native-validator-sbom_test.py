"""Offline native SBOM wiring and fail-closed identity fixtures."""
import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('native', Path(__file__).with_name('native-validator-sbom.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class NativeSBOM(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.validator = Path(self.tmp.name) / 'validator'
        self.validator.write_bytes(b'fixture static validator')
        self.bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.7', 'components': []}
        names = ['libbpf.a', 'libelf.a', 'libzstd.a', 'libz.a', 'libc.a', 'libgcc.a', 'libgcc_eh.a']
        self.inventory = {'schema_version': 'v0.1', 'validator_sha256': native.digest(self.validator),
                          'source_commit': 'a' * 40, 'source_sha256': 'b' * 64,
                          'inputs': [{'path': '/usr/lib/' + name, 'package': 'fixture-dev:amd64',
                                      'version': '1:2.3-4', 'sha256': 'c' * 64} for name in names]}

    def test_exact_native_files_and_package_relationships(self):
        bom = native.supplement(self.bom, self.inventory, self.validator)
        files = [c for c in bom['components'] if c.get('bom-ref', '').startswith('bpfcompat:native-file:')]
        self.assertEqual(len(files), 7)
        self.assertEqual(len([c for c in bom['components'] if c['type'] == 'library']), 1)
        dep = next(d for d in bom['dependencies'] if d['ref'].startswith('bpfcompat:static-validator:'))
        self.assertEqual(len(dep['dependsOn']), 7)
        self.assertIn('fixture-dev@1%3A2.3-4', bom['components'][1]['purl'])

    def test_wrong_artifact_and_missing_library_rejected(self):
        for mutation in ('hash', 'missing', 'native-hash', 'duplicate', 'source'):
            inventory = copy.deepcopy(self.inventory)
            if mutation == 'hash':
                inventory['validator_sha256'] = '0' * 64
            elif mutation == 'missing':
                inventory['inputs'].pop()
            elif mutation == 'native-hash':
                inventory['inputs'][0]['sha256'] = ''
            elif mutation == 'duplicate':
                inventory['inputs'].append(inventory['inputs'][0])
            else:
                inventory['source_commit'] = ''
            with self.assertRaises(ValueError):
                native.supplement(copy.deepcopy(self.bom), inventory, self.validator)

    def test_duplicate_supplement_rejected(self):
        native.supplement(self.bom, self.inventory, self.validator)
        with self.assertRaises(ValueError):
            native.supplement(self.bom, self.inventory, self.validator)


if __name__ == '__main__':
    unittest.main()
