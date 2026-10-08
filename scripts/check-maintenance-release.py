#!/usr/bin/env python3
"""Maintenance metadata guard: published pins never point at a future tag."""
import os
import re
import subprocess
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent

def require(condition, message='invalid maintenance release metadata'):
    if not condition:
        raise ValueError(message)

def validate(metadata, ref, head, baseline):
    require(metadata['stable_version'] == '0.3.7', 'published stable version changed prematurely')
    require(metadata['stable_commit'] == baseline, 'stable SHA changed')
    require(re.fullmatch(r'0\.3\.8(?:-rc\.[1-9][0-9]*)?', metadata['release_version']))
    channel = 'prerelease' if '-rc.' in metadata['release_version'] else 'stable'
    require(metadata['release_channel'] == channel)
    require(metadata['minimum_go'] == '1.25.14')
    require(metadata['report_schema'] == 'v0.1')
    require(metadata['release_operator'] == 'ErenAri')
    require(metadata['approval_mode'] == 'solo-maintainer')
    require(re.fullmatch(r'[0-9a-f]{40}', head))
    if ref.startswith('refs/tags/'):
        require(ref == 'refs/tags/v' + metadata['release_version'], 'tag does not match candidate metadata')

def main():
    source = (ROOT / 'release.yaml').read_text()
    keys = [key.value for key, _ in yaml.compose(source).value]
    require(len(keys) == len(set(keys)), 'duplicate release metadata keys')
    metadata = yaml.safe_load(source)
    baseline = '179ff612ed2b5d1afb16dd9c282752028d47c415'
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    validate(metadata, os.environ.get('GITHUB_REF', ''), head, baseline)
    subprocess.run(['git', 'merge-base', '--is-ancestor', baseline, head], cwd=ROOT, check=True)
    stable = subprocess.check_output(['git', 'rev-parse', 'v0.3.7^{commit}'], cwd=ROOT, text=True).strip()
    require(stable == baseline, 'published stable tag identity mismatch')
    canary = (ROOT / '.github/workflows/consumer-canary.yml').read_text()
    pins = re.findall(r'uses: Kernel-Guard/bpfcompat@([0-9a-f]{40}) # v0\.3\.7; bpfcompat-pin: stable', canary)
    require(pins == [baseline], 'published stable consumer pin mismatch')
    if os.environ.get('GITHUB_REF', '').startswith('refs/tags/'):
        require(os.environ['GITHUB_SHA'] == head, 'candidate checkout identity mismatch')
    print('[maintenance-release] metadata, ancestry and published stable identity PASS')

if __name__ == '__main__':
    main()
