# Production Release Process

This process applies only to the CLI, GitHub Action, and disposable QEMU/KVM
validation boundary in
[production-support-boundary.md](production-support-boundary.md).

## Roles

- Release operator: the active project maintainer.
- Independent release reviewer: the GitHub login recorded as
  `release_reviewer` in `release.yaml`.

The selected reviewer is not active until they accept the responsibility in a
public issue or pull-request comment containing:

```text
[bpfcompat-release-reviewer-acceptance:v1]
```

Acceptance covers reviewing candidate evidence, approving or rejecting the
protected environment, acting as incident backup, and confirming rollback
evidence. It does not by itself grant maintainer status.

## Repository Controls

Before creating a release tag:

1. `main` requires one non-author approval, dismisses stale approvals, requires
   an up-to-date branch and production checks, and enforces those rules for
   administrators.
2. The `production-release` environment requires the recorded reviewer,
   prevents self-review, disables administrator bypass, and permits only `v*`
   tag deployments.
3. `scripts/check-production-environment.sh` passes against the live GitHub
   configuration. The tag workflow runs this check before building release
   artifacts.
4. Required CI and the tagged-release workflow enforce at least 50.0% total Go
   statement coverage. Raise this floor as sustained coverage improvements
   land; never lower it to make a release pass.

## Release Candidate

1. Keep stable documentation and installer defaults on the current stable
   version.
2. Set `release_version` to `X.Y.Z-rc.N` and `release_channel` to
   `prerelease`.
3. Tag the reviewed commit as `vX.Y.Z-rc.N`.
4. Inspect the draft assets and attested
   `release-candidate-evidence.json`.
5. Approve the protected deployment only if the candidate VM, native ARM64,
   multi-architecture image, checksum, signature, SBOM, and provenance checks
   pass.
6. Verify the release is a GitHub prerelease and only the exact
   `X.Y.Z-rc.N` image tag was created.

## Graduation Evidence

Download four chronological scheduled campaign artifacts, one expanded Falco
artifact, the attested candidate evidence, the rollback drill note, and the
reviewer's written approval into one private working directory. Create an
input manifest with paths relative to that directory:

```json
{
  "schema_version": "v0.1",
  "release_version": "0.4.0",
  "campaigns": [
    {
      "metadata": "campaign-1/production-campaign.json",
      "report": "campaign-1/functional-execve-latest-kernel.json"
    }
  ],
  "falco": {
    "workflow_run_id": 123456789,
    "commit_sha": "<40-character commit SHA>",
    "started_at": "2026-08-03T06:00:00Z",
    "report": "falco/modern-bpf-compat.json",
    "report_sha256": "<sha256>"
  },
  "candidate": {
    "evidence": "candidate/release-candidate-evidence.json",
    "evidence_sha256": "<sha256>"
  },
  "rollback": {
    "completed": true,
    "evidence": "rollback/evidence.md",
    "evidence_sha256": "<sha256>"
  },
  "reviewer": {
    "login": "yusuf-demirel4",
    "approved": true,
    "evidence": "reviewer/evidence.md",
    "evidence_sha256": "<sha256>"
  }
}
```

The real manifest contains exactly four campaign entries. Run:

```bash
scripts/production-readiness-report.sh \
  readiness/input.json readiness/bpfcompat-0.4.0-readiness.md
```

The command writes both Markdown and JSON. Add the reviewed outputs to
`docs/releases/bpfcompat-0.4.0-readiness.{md,json}` in the final release pull
request. The stable release workflow validates, checksums, attests, and
publishes those files; a stable tag fails if they are absent or not `ready`.

Do not use `BPFCOMPAT_SKIP_READINESS_ATTESTATION=1` outside the regression
test; production evidence must verify the candidate attestation online.

## Stable Release

After every operational gate passes, set both `stable_version` and
`release_version` to `X.Y.Z`, set `release_channel` to `stable`, update stable
documentation, and tag the reviewed merge commit. The reviewer checks the
graduation report and draft assets before approving promotion. Only this path
may update the `X.Y` and `latest` image aliases or GitHub's latest release.
