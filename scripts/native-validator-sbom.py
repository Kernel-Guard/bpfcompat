#!/usr/bin/env python3
"""Record actual static linker inputs, then supplement the release CycloneDX BOM.

Archive hashes identify linker inputs, not a claim that every archive member is
reachable. Generated compilation objects are covered by source/binary identity.
No network access, package installation, or reconstruction from package names.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def collect(trace, validator):
    locks = dict(line.split('=', 1) for line in
                 (ROOT / 'scripts/release-native-packages.txt').read_text().splitlines()
                 if line and not line.startswith('#'))
    inputs = []
    paths = sorted({str(Path(line).resolve()) for line in Path(trace).read_text().splitlines()
                    if line.startswith('/usr/') and Path(line).suffix in ('.a', '.o')})
    for path in paths:
        owner = subprocess.check_output(['dpkg-query', '-S', path], text=True).strip()
        package, owned_path = owner.split(': ', 1)
        if owned_path != path or package not in locks:
            raise ValueError(f'unlocked or ambiguous native linker input: {path}')
        version = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', package], text=True)
        if version != locks[package]:
            raise ValueError(f'native package version mismatch: {package}')
        inputs.append(dict(path=path, package=package, version=version, sha256=digest(path)))
    required = {'libbpf.a', 'libelf.a', 'libzstd.a', 'libz.a', 'libc.a', 'libgcc.a', 'libgcc_eh.a'}
    if not required.issubset({Path(item['path']).name for item in inputs}):
        raise ValueError('native linker trace is incomplete')
    return dict(schema_version='v0.1', source_commit=subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        validator_sha256=digest(validator), source_sha256=digest(ROOT / 'validator/c-libbpf/src/main.c'),
        inputs=inputs)


def supplement(bom, inventory, validator):
    if bom.get('bomFormat') != 'CycloneDX' or not isinstance(bom.get('components'), list):
        raise ValueError('expected a CycloneDX component inventory')
    if inventory.get('schema_version') != 'v0.1' or inventory.get('validator_sha256') != digest(validator):
        raise ValueError('native inventory does not identify this validator')
    required = {'libbpf.a', 'libelf.a', 'libzstd.a', 'libz.a', 'libc.a', 'libgcc.a', 'libgcc_eh.a'}
    inputs = inventory.get('inputs', [])
    if not required.issubset({Path(item['path']).name for item in inputs}):
        raise ValueError('native inventory is incomplete')
    if not re.fullmatch('[0-9a-f]{40}', inventory.get('source_commit', '')) or not re.fullmatch('[0-9a-f]{64}', inventory.get('source_sha256', '')):
        raise ValueError('native source identity is invalid')
    if len({item['path'] for item in inputs}) != len(inputs):
        raise ValueError('duplicate native linker input')
    for item in inputs:
        if not item['path'].startswith('/usr/') or not re.fullmatch('[0-9a-f]{64}', item.get('sha256', '')):
            raise ValueError('invalid native linker input identity')
    components = bom['components']
    dependencies = bom.setdefault('dependencies', [])
    validator_ref = 'bpfcompat:static-validator:' + inventory['validator_sha256']
    if any(c.get('bom-ref', '').startswith('bpfcompat:static-validator:') for c in components):
        raise ValueError('native inventory was already supplemented')
    components.append({'type': 'file', 'name': Path(validator).name, 'bom-ref': validator_ref,
                       'hashes': [{'alg': 'SHA-256', 'content': inventory['validator_sha256']}],
                       'properties': [{'name': 'bpfcompat:source-commit', 'value': inventory['source_commit']},
                                      {'name': 'bpfcompat:source-sha256', 'value': inventory['source_sha256']}]})
    packages = {}
    files = []
    for item in inputs:
        package, arch = item['package'].rsplit(':', 1)
        purl = ('pkg:deb/ubuntu/' + quote(package, safe='') + '@' + quote(item['version'], safe='')
                + '?arch=' + quote(arch, safe='') + '&distro=ubuntu-24.04')
        if purl not in packages:
            packages[purl] = True
            components.append({'type': 'library', 'name': package, 'version': item['version'],
                               'bom-ref': purl, 'purl': purl,
                               'supplier': {'name': 'Ubuntu'}})
            dependencies.append({'ref': purl, 'dependsOn': []})
        file_ref = 'bpfcompat:native-file:' + item['path']
        files.append(file_ref)
        components.append({'type': 'file', 'name': Path(item['path']).name, 'bom-ref': file_ref,
                           'hashes': [{'alg': 'SHA-256', 'content': item['sha256']}],
                           'properties': [{'name': 'bpfcompat:linker-input', 'value': item['path']}]})
        dependencies.append({'ref': file_ref, 'dependsOn': [purl]})
    dependencies.append({'ref': validator_ref, 'dependsOn': files})
    return bom


def main():
    mode, *args = sys.argv[1:]
    if mode == 'collect' and len(args) == 3:
        trace, validator, output = args
        value = collect(trace, validator)
    elif mode == 'supplement' and len(args) == 3:
        output, inventory, validator = args
        value = supplement(json.loads(Path(output).read_text()), json.loads(Path(inventory).read_text()), validator)
    else:
        raise ValueError('usage: native-validator-sbom.py collect TRACE VALIDATOR OUTPUT | supplement BOM INVENTORY VALIDATOR')
    Path(output).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
