#!/usr/bin/env python3
"""Summarize one maintenance-evidence run (R3) into its attested subject.

Input is a JSON document the maintenance-evidence workflow assembles from its
own jobs: run identity, the published candidate's identity, the
machine-verified scope result, the VM gate reports and the candidate canary
checks. Output is maintenance-evidence.json, which the workflow attests with
actions/attest-build-provenance. Readiness accepts it only through that
producer attestation; nothing here is evidence by itself.

The summary is written only when every acceptance criterion holds. A rejected
run produces no file, so there is no "failed" evidence a later step could
mistake for a pass.

Usage: maintenance-evidence-summary.py INPUT.json OUTPUT.json
Exit 0 written, 1 rejected, 2 usage error.
"""
import json
import re
import sys
from datetime import datetime
from pathlib import Path

MARKER = '[bpfcompat-maintenance-evidence:v1]'
REPOSITORY = 'Kernel-Guard/bpfcompat'
WORKFLOW = REPOSITORY + '/.github/workflows/maintenance-evidence.yml@refs/tags/'
RC_TAG = re.compile(r'v\d+\.\d+\.\d+-rc\.[1-9]\d*')
SHA1 = re.compile(r'[0-9a-f]{40}')
SHA256 = re.compile(r'[0-9a-f]{64}')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
K725_PROFILE = 'centos-stream-9-5.14-k5.14.0-725.el9'
K725_KERNEL = '5.14.0-725.el9.x86_64'
CANARY_CHECKS = ('clean-install', 'candidate-action', 'container')


def _time(value):
    return datetime.strptime(str(value), '%Y-%m-%dT%H:%M:%SZ')


def _infra(target):
    return target.get('status') == 'infra_error' or bool(target.get('infra_error'))


def build(data):
    """Return (evidence, []) when accepted, (None, violations) otherwise."""
    v = []
    candidate = data.get('candidate') or {}
    tag = str(candidate.get('tag', ''))
    commit = str(candidate.get('commit_sha', ''))
    digest = str(candidate.get('image_digest', ''))

    if data.get('milestone') not in ('e0', 'e1'):
        v.append('milestone must be e0 or e1')
    if data.get('repository') != REPOSITORY:
        v.append('repository must be %s: third-party runs are corroboration, not evidence' % REPOSITORY)
    if not RC_TAG.fullmatch(tag):
        v.append('candidate tag must be a vX.Y.Z-rc.N prerelease tag')
    if data.get('workflow_ref') != WORKFLOW + tag:
        v.append('workflow_ref must be maintenance-evidence.yml at the candidate tag')
    if not SHA1.fullmatch(commit):
        v.append('candidate commit must be a full SHA-1')
    if not DIGEST.fullmatch(digest):
        v.append('candidate image digest must be sha256:<64 hex>')
    for key in ('checksums_sha256', 'evidence_sha256'):
        if not SHA256.fullmatch(str(candidate.get(key, ''))):
            v.append('candidate %s must be a SHA-256' % key)
    for key in ('run_id', 'run_attempt'):
        if not isinstance(data.get(key), int) or data.get(key) <= 0:
            v.append('%s must be a positive integer' % key)
    try:
        if _time(data.get('completed_at')) < _time(data.get('started_at')):
            v.append('completed_at precedes started_at')
    except ValueError:
        v.append('started_at/completed_at must be UTC RFC 3339 timestamps')

    scope = data.get('scope') or {}
    if scope.get('eligible') is not True or scope.get('violations'):
        v.append('maintenance scope is not eligible')
    if not SHA1.fullmatch(str(scope.get('baseline', ''))):
        v.append('maintenance scope has no stable baseline commit')

    identity = data.get('identity') or {}
    if identity.get('source_commit') != commit:
        v.append('VM gate ran on commit %s, not the candidate commit' % identity.get('source_commit'))
    if identity.get('positive_exit') != 0 or identity.get('negative_exit') != 2:
        v.append('VM gate exit codes must be positive=0 and negative=2')
    for key in ('cli_sha256', 'validator_sha256'):
        if not SHA256.fullmatch(str(identity.get(key, ''))):
            v.append('VM gate %s must be a SHA-256' % key)

    positive = data.get('positive') or {}
    ptargets = positive.get('targets') or []
    if positive.get('schema_version') != 'v0.1' or (positive.get('summary') or {}).get('status') != 'pass' \
            or not ptargets or any(t.get('required') and t.get('status') != 'pass' for t in ptargets):
        v.append('positive VM report has a required target that is not COMPATIBLE')
    if any(_infra(t) for t in ptargets):
        v.append('positive VM report contains an infra error')
    if not any(t.get('profile_id') == K725_PROFILE and (t.get('host') or {}).get('kernel') == K725_KERNEL
               and t.get('status') == 'pass' for t in ptargets):
        v.append('positive VM report lacks a passing exact kernel 725 boot')

    negative = data.get('negative') or {}
    ntargets = negative.get('targets') or []
    if negative.get('schema_version') != 'v0.1' or (negative.get('summary') or {}).get('status') != 'fail' \
            or not ntargets or len(ntargets) != len(ptargets) or any(
                t.get('status') != 'fail' or (t.get('validation') or {}).get('load_status') != 'fail'
                for t in ntargets):
        v.append('negative control is not INCOMPATIBLE on every target')
    if any(_infra(t) for t in ntargets):
        v.append('negative VM report contains an infra error')

    canary = data.get('canary') or {}
    for name in CANARY_CHECKS:
        check = canary.get(name)
        if not isinstance(check, dict) or check.get('check') != name or check.get('status') != 'pass':
            v.append('candidate canary %s did not pass' % name)
            continue
        if check.get('version') != tag or check.get('commit') != commit:
            v.append('candidate canary %s is bound to another candidate' % name)
        if name == 'container' and check.get('digest') != digest:
            v.append('candidate canary container digest does not match the candidate')

    if v:
        return None, v
    return {
        'schema_version': 'v0.1',
        'marker': MARKER,
        'repository': REPOSITORY,
        'workflow_ref': data['workflow_ref'],
        'milestone': data['milestone'],
        'workflow_run_id': data['run_id'],
        'workflow_run_attempt': data['run_attempt'],
        'started_at': data['started_at'],
        'completed_at': data['completed_at'],
        'tag': tag,
        'commit_sha': commit,
        'image_digest': digest,
        'checksums_sha256': candidate['checksums_sha256'],
        'candidate_evidence_sha256': candidate['evidence_sha256'],
        'cli_sha256': identity['cli_sha256'],
        'validator_sha256': identity['validator_sha256'],
        'scope': {'eligible': True, 'baseline': scope['baseline']},
        'vm': {'profiles': sorted(t['profile_id'] for t in ptargets),
               'positive': 'pass', 'negative': 'expected-incompatible',
               'exact_kernel': K725_KERNEL},
        'canary': {name: 'pass' for name in CANARY_CHECKS},
        'acceptance': {'status': 'pass', 'required_infra_errors': 0},
    }, []


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    evidence, violations = build(json.loads(Path(argv[0]).read_text()))
    if violations:
        print('[maintenance-evidence] REJECTED', file=sys.stderr)
        for item in violations:
            print('  - ' + item, file=sys.stderr)
        return 1
    Path(argv[1]).write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    print('[maintenance-evidence] accepted %s %s' % (evidence['milestone'], evidence['tag']))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
