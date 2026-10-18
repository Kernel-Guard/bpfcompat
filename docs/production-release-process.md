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

Every job in `release-candidate-canary`, `external-consumer-canary`, and
`consumer-canary` runs on the pinned `ubuntu-24.04` image, not the moving
`ubuntu-latest` label (GitHub migrates it to Ubuntu 26.04 between 2026-10-19
and 2026-11-19), so the manual, T+24h, and T+72h observations of one candidate
run on the same Ubuntu release (`scripts/canary-runner-pin_test.sh`). The
external-consumer workflow is dispatched at the RC tag, so its runner labels
come from the tagged commit: the pin must be on `main` before the candidate is
tagged. Change the pin only between candidates.

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
artifact, the attested candidate evidence, all three complete RC canary
artifacts (each `release-candidate-canary.json` together with the
`components/` directory uploaded beside it), the rollback drill note, the
fail-closed promotion incident note, and the operator's written promotion
confirmation into one private working directory. Create an input manifest with
paths relative to that directory:

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
    "started_at": "<the report's run.started_at, e.g. 2026-08-03T06:15:35Z>",
    "report": "falco/modern-bpf-compat.json",
    "report_sha256": "<sha256>"
  },
  "candidate": {
    "evidence": "candidate/release-candidate-evidence.json",
    "evidence_sha256": "<sha256>",
    "checksums": "candidate/SHA256SUMS"
  },
  "canaries": [
    {
      "milestone": "manual",
      "evidence": "canary-manual/release-candidate-canary.json",
      "evidence_sha256": "<sha256>"
    },
    {
      "milestone": "t-plus-24h",
      "evidence": "canary-t-plus-24h/release-candidate-canary.json",
      "evidence_sha256": "<sha256>"
    },
    {
      "milestone": "t-plus-72h",
      "evidence": "canary-t-plus-72h/release-candidate-canary.json",
      "evidence_sha256": "<sha256>"
    }
  ],
  "rollback": {
    "completed": true,
    "evidence": "rollback/evidence.md",
    "evidence_sha256": "<sha256>"
  },
  "incident": {
    "completed": true,
    "evidence": "incident/evidence.md",
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

The real manifest contains exactly four campaign entries and exactly three
canary entries in `manual`, `t-plus-24h`, and `t-plus-72h` order. The
aggregator binds every piece of evidence to the attested candidate
(`generated_at`, tag, commit, image digest, evidence SHA-256):

- **Falco.** `falco.started_at` must equal the report's own `run.started_at`,
  and the run must start after the candidate's `generated_at`: evidence must
  postdate the candidate it graduates. The runner writes `run.started_at` when
  it assembles the report, so the run's start is the earliest of that and every
  target's `started_at`; a required or passing target without `started_at` is
  refused, while an optional profile the runner never booted does not count.
  `workflow_run_id` and `commit_sha` are not recorded in the report and remain
  operator-asserted (`falco.run_identity` in the output). Written policy does
  not require the Falco lane to run the candidate's own bpfcompat, so this is
  not enforced; the output records `falco.validator_sha256` and
  `falco.candidate_bound` (true only when the report names the candidate's
  validator).
- **Canaries.** The two timed canaries must come from `schedule` events, and
  every canary must bind the same RC tag, commit, and image digest as the
  attested candidate. Completion times must be in milestone order and at least
  0, 20, and 68 hours after `generated_at`. These are floors derived from the
  plan job's 20-30h and 68-78h windows after publication: publication time is
  not in the attested evidence, but it never precedes `generated_at`. The plan
  job itself enforces the upper bounds. Each canary's components must be
  artifacts of that canary's own run (`*canary-component-<check>-<run ID>/`),
  and the `<check>.json` record of each of the five checks must be present,
  match its recorded SHA-256, pass, and name the candidate tag and commit; the
  container record must name the candidate digest and the external-consumers
  record the canary's `external_consumer_run_id`.
- **Rollback drill.** The note must be the `evidence.md` written by
  `rollback-drill.yml` for this candidate: `- Drill alias:` is
  `ghcr.io/kernel-guard/bpfcompat:rollback-drill-vX.Y.Z-rc.N`,
  `- Candidate digest:` is the candidate image digest, `- Final digest:` equals
  a distinct `- Known-good digest:`, and `- Completed:` is after
  `generated_at`. A drill of an earlier candidate is refused.
- **Incident.** The note must contain `[bpfcompat-promotion-incident:v1]`,
  name `promote-release`, and link the deliberately rejected run, and only
  that run, as
  `https://github.com/Kernel-Guard/bpfcompat/actions/runs/<run ID>`. With
  attestation verification on, that run must be a completed `promote-release.yml`
  run that did not succeed, and the rollback evidence's workflow run must be a
  successful `rollback-drill.yml` run on `main`; both are looked up on GitHub.
  Written policy does not require the incident drill to target the current
  candidate,
  so an earlier candidate's fail-closed drill is accepted; the output records
  `incident.promotion_run_id` and `incident.candidate_bound`.
- **Operator.** The confirmation must contain
  `[bpfcompat-solo-promotion:v1]`, the operator login, and, as a whole token,
  the SHA-256 of the attested `release-candidate-evidence.json` it confirms.

Every JSON input (the manifest, candidate evidence, campaign metadata and
reports, the Falco report, canary manifests and component records) must be
exactly one JSON object; a concatenated multi-document file is refused.

Run:

```bash
scripts/production-readiness-report.sh \
  readiness/input.json readiness/bpfcompat-0.4.0-readiness.md
```

The command writes both Markdown and JSON. Add the reviewed outputs to
`docs/releases/bpfcompat-0.4.0-readiness.{md,json}` in the final release pull
request. The stable release workflow validates, checksums, attests, and
publishes those files; a stable tag fails if they are absent or not `ready`.
The online candidate check requires an authenticated GitHub CLI version that
provides `gh attestation`; an older CLI fails closed.

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

Once the new stable tag exists, repin the `# bpfcompat-pin: stable` step in
`.github/workflows/consumer-canary.yml` to its commit SHA and update the
`# vX.Y.Z` comment beside it. `scripts/check-canary-pins.sh` runs inside the
release-consistency gate and fails the build until that is done, because a
canary left on the previous release stops testing the path the documentation
now sends every reader down. The `# bpfcompat-pin: candidate` step is not
enforced while `release_channel` is `stable`; repin it with the next
`X.Y.Z-rc.1`.
