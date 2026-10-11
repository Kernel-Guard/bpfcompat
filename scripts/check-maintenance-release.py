#!/usr/bin/env python3
"""Maintenance metadata guard: published pins never point at a future tag.

Generalized (no version constants). release.yaml carries two kinds of facts:

  * PUBLISHED stable identity -- stable_version / stable_commit. These must
    describe a release that already exists: tag v<stable_version> must resolve
    (peeled) to exactly stable_commit, and stable_commit must be an ancestor of
    the checkout. They advance only in a separate commit AFTER publication.
  * The maintenance TARGET -- release_version / release_channel. A maintenance
    release is the next patch of the published stable release, optionally as
    an -rc.N prerelease. Anything else (same version, a skipped patch, a minor
    or major bump, a downgrade) is not a maintenance release.

The consumer canary must pin exactly one stable action reference, at
stable_commit, labelled v<stable_version>.
"""
import os
import re
import subprocess
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')
TARGET = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.([1-9][0-9]*))?')
SHA = re.compile(r'[0-9a-f]{40}')


def require(condition, message='invalid maintenance release metadata'):
    if not condition:
        raise ValueError(message)


def validate(metadata, ref, head, resolve_tag, is_ancestor):
    """resolve_tag(name) -> peeled commit SHA or None; is_ancestor(a, d) -> bool."""
    stable_version = str(metadata.get('stable_version', ''))
    stable_commit = str(metadata.get('stable_commit', ''))
    release_version = str(metadata.get('release_version', ''))

    stable = SEMVER.fullmatch(stable_version)
    require(stable, 'stable_version must be a published X.Y.Z release')
    require(SHA.fullmatch(stable_commit), 'stable_commit must be a full commit SHA')
    require(SHA.fullmatch(head), 'checkout HEAD must be a full commit SHA')

    published = resolve_tag('v' + stable_version)
    require(published is not None, 'stable release v%s is not published' % stable_version)
    require(published == stable_commit,
            'published stable tag v%s resolves to %s, not stable_commit %s'
            % (stable_version, published, stable_commit))
    require(is_ancestor(stable_commit, head), 'stable_commit is not an ancestor of the checkout')

    target = TARGET.fullmatch(release_version)
    require(target, 'release_version must be X.Y.Z or X.Y.Z-rc.N')
    major, minor, patch = (int(x) for x in stable.groups())
    t_major, t_minor, t_patch = (int(x) for x in target.groups()[:3])
    require((t_major, t_minor, t_patch) == (major, minor, patch + 1),
            'maintenance release must be the next patch of v%s, got %s' % (stable_version, release_version))
    channel = 'prerelease' if target.group(4) else 'stable'
    require(metadata.get('release_channel') == channel, 'release_channel does not match release_version')

    # Go 1.25 is unpatched for the 2026-10-08 stdlib advisories (fixed only in
    # go1.26.9 / go1.27.2); maintenance builds use the patched toolchain.
    require(metadata.get('minimum_go') == '1.26.9', 'minimum_go must be the patched toolchain 1.26.9')
    require(metadata.get('report_schema') == 'v0.1')
    require(metadata.get('release_operator') == 'ErenAri')
    require(metadata.get('approval_mode') == 'solo-maintainer')
    if ref.startswith('refs/tags/'):
        require(ref == 'refs/tags/v' + release_version, 'tag does not match candidate metadata')


def check_canary_pin(canary_text, stable_version, stable_commit):
    pins = re.findall(r'uses: Kernel-Guard/bpfcompat@([0-9a-f]{40}) # v([^;\s]+); bpfcompat-pin: stable',
                      canary_text)
    require(pins == [(stable_commit, stable_version)], 'published stable consumer pin mismatch')


def git_resolve_tag(name):
    result = subprocess.run(['git', 'rev-parse', '--verify', '--quiet', 'refs/tags/%s^{commit}' % name],
                            cwd=ROOT, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else None


def git_is_ancestor(ancestor, descendant):
    return subprocess.run(['git', 'merge-base', '--is-ancestor', ancestor, descendant], cwd=ROOT).returncode == 0


def main():
    source = (ROOT / 'release.yaml').read_text()
    keys = [key.value for key, _ in yaml.compose(source).value]
    require(len(keys) == len(set(keys)), 'duplicate release metadata keys')
    metadata = yaml.safe_load(source)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    validate(metadata, os.environ.get('GITHUB_REF', ''), head, git_resolve_tag, git_is_ancestor)
    canary = (ROOT / '.github/workflows/consumer-canary.yml').read_text()
    check_canary_pin(canary, str(metadata['stable_version']), str(metadata['stable_commit']))
    if os.environ.get('GITHUB_REF', '').startswith('refs/tags/'):
        require(os.environ['GITHUB_SHA'] == head, 'candidate checkout identity mismatch')
    print('[maintenance-release] metadata, ancestry and published stable identity PASS')


if __name__ == '__main__':
    main()
