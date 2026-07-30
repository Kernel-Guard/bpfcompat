# Production Release Process

This process applies only to the CLI, GitHub Action, and disposable QEMU/KVM
validation boundary in
[production-support-boundary.md](production-support-boundary.md).

## Roles

- Release operator: the GitHub login recorded as `release_operator` in
  `release.yaml`.
- Approval mode: `solo-maintainer`.

This mode deliberately has no independent human approval. The same maintainer
can author, merge, tag, and promote a release. Compromise of that maintainer's
GitHub account can therefore cross every human boundary. The compensating
controls are mandatory PR checks, immutable release tags, a separate manual
promotion dispatch, a 15-minute production wait, exact evidence binding, and
re-verification immediately before publication.

## Repository Controls

Before creating a release tag:

1. `main` requires a pull request, an up-to-date branch, conversation
   resolution, and all production checks, and enforces those rules for
   administrators. It requires zero human approvals.
2. An active tag ruleset prevents updates or deletion of `v*` release tags.
3. The `production-release` environment has no required reviewers, imposes a
   15-minute wait, disables administrator bypass, and permits only `v*` tag
   deployments.
4. `scripts/check-production-environment.sh` passes against the live GitHub
   configuration. The tag workflow runs this check before building release
   artifacts.
5. Required CI and the tagged-release workflow enforce at least 50.0% total Go
   statement coverage. Raise this floor as sustained coverage improvements
   land; never lower it to make a release pass.

## Release Candidate

1. Keep stable documentation and installer defaults on the current stable
   version.
2. Set `release_version` to `X.Y.Z-rc.N` and `release_channel` to
   `prerelease`.
3. Tag the reviewed commit as `vX.Y.Z-rc.N`.
4. Wait for `release-artifacts` to finish successfully. It may build, verify,
   sign, attest, and stage a private draft, but it cannot publish.
5. Inspect the draft assets and attested
   `release-candidate-evidence.json`.
6. Dispatch `promote-release` with `--ref vX.Y.Z-rc.N` and the exact release
   tag, candidate run ID, full commit SHA, image digest, and confirmation text
   `promote vX.Y.Z-rc.N`. Running on the tag is required by the environment's
   `v*`-only deployment policy.
7. The promotion workflow re-verifies the candidate run identity, tag, commit,
   artifact checksums and attestations, Sigstore signatures, draft state,
   channel, image signature, digest, and embedded version. Publication occurs
   only after the environment wait completes.
8. Verify the release is a GitHub prerelease and only the exact
   `X.Y.Z-rc.N` image tag was created.

## Graduation Evidence

For the active release candidate, the temporary
`release-candidate-canary` workflow validates five exact-artifact paths:
verified clean installation, clean source build, the published Action pinned
to the immutable RC commit, the signed multiarchitecture container pinned by
digest, and the external Inspektor Gadget/KubeArmor/Falco workflow dispatched
at the immutable RC tag. Run it once immediately after publication. Its two
dated schedules run just after T+24 hours and T+72 hours and emit
`[bpfcompat-rc-canary:v1]` evidence; any out-of-window invocation exits after
the planning job. Remove or retarget these temporary schedules after
graduation.

Before assembling the graduation directory, run the protected
`rollback-drill` workflow from `main`. Supply a dedicated
`rollback-drill-vX.Y.Z-rc.N` alias, the immutable known-good and candidate
digests, their embedded versions, their exact Sigstore workflow identities,
and confirmation text `rollback drill rollback-drill-vX.Y.Z-rc.N`.
`production-drill` adds a five-minute wait and permits only `main`.

The workflow verifies both signatures, SLSA v1 provenance records, and
embedded versions before moving the drill-only alias known-good → candidate →
known-good. It records the promotion and recovery times, proves `latest` was
unchanged, leaves the drill alias on the known-good digest, and uploads
`evidence.{md,json}` containing `[bpfcompat-rollback-drill:v1]`. Download that
artifact as the rollback drill note.

Download four chronological scheduled campaign artifacts, one expanded Falco
artifact, the attested candidate evidence, the rollback drill note, and the
operator's written promotion confirmation into one private working directory.
Create an
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
  "operator": {
    "login": "ErenAri",
    "approval_mode": "solo-maintainer",
    "confirmed": true,
    "evidence": "operator/evidence.md",
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
documentation, and tag the checked merge commit. The operator checks the
graduation report and draft assets, records
`[bpfcompat-solo-promotion:v1]`, and dispatches the exact promotion inputs.
Only this path may update the `X.Y` and `latest` image aliases or GitHub's
latest release.
