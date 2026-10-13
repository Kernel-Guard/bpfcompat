# Production SLO Runbook

This runbook defines technical service objectives for the supported
CI-validation boundary of `bpfcompat`.

## Scope

- VM-backed compatibility validation (`bpfcompat test`)
- GitHub Action artifact, suite, and command-mode validation
- release-candidate and supported scheduled VM campaigns

Runtime selection, host execution, the agent, registry, API, and SaaS are
experimental and excluded from this production SLO.

## SLOs

1. Validation success-path reliability:
   - SLO: zero `infra_error` targets in the four-campaign graduation window.
   - After graduation: >= 99% of scheduled target executions complete without
     `infra_error` over the trailing 30 days.
2. Report generation latency:
   - SLO: target-duration p95 <= the configured 12-minute per-target budget and
     each scheduled campaign completes within its 120-minute workflow budget.
3. Release safety:
   - SLO: 100% of published releases pass the candidate positive and classified-negative VM gate.

## SLI Signals

- `summary.status` and per-target `status` from report JSON
- `infra_error` count per run
- duration metrics from run metadata (`started_at`, `finished_at`)
- `reports/production-campaign.json` (v0.2, attested by the workflow), which
  records the scheduled run, the workflow source commit, the tested release
  candidate, the executables that ran, and the report's SHA-256, run ID and
  start time

## Alert Triggers

1. A release-candidate VM gate fails: freeze promotion.
2. Scheduled campaign has >1% `infra_error` over trailing 24h: page.
3. Two consecutive production-tech checks not-ready: page and freeze rollout.

## Daily Operator Checklist

1. Run `make production-tech-check`.
2. Review newest `evidence/production-tech/production-tech-check-*.md`.
3. Review newest `evidence/production-tech/tech-stability-*.md`.
4. If any gate is not-ready, pause promotion and follow incident runbook.

## Graduation Window

Only `schedule` events from `latest-kernel-compatibility.yml` count. Manual
dispatches are shakeouts and cannot satisfy the four-campaign requirement.
Campaigns must be unique, chronological, and 6-8 days apart. A supported-
boundary behavior change requires a new release candidate and restarts the
window; documentation-only changes do not.

### Campaign-to-candidate binding

A scheduled run always executes the workflow from `main`, so its
`GITHUB_SHA` identifies the *workflow source*, never the *tested candidate*.
The two are recorded separately:

1. **Designation.** `.github/campaign-candidate.json`, changed only by a
   reviewed PR, names the release candidate under qualification: its tag,
   commit, `SHA256SUMS` SHA-256 and `release-candidate-evidence.json` SHA-256.
   Without it the sweep still runs, but its evidence says `candidate: null`
   and can never qualify a release.
2. **Verification before testing** (`scripts/campaign-candidate-bind.sh`,
   fails closed):
   - the tag peels to the pinned commit;
   - the release is a published prerelease;
   - `SHA256SUMS` and the candidate evidence are byte-identical to the pin, and
     the evidence names that tag and commit;
   - the released CLI and static validator match `SHA256SUMS`, and they and the
     evidence carry `release-artifacts.yml` attestations for exactly that
     commit and `refs/tags/<tag>`;
   - the CLI reports that tag and commit;
   - the candidate source checkout is that commit, unmodified.
3. **Execution of the candidate.** The campaign runs the candidate's own
   action from its source tree with the candidate's *released* CLI, and the
   released validator pinned by `BPFCOMPAT_VALIDATOR_SHA256`. The report
   records that validator's digest itself.
4. **Attested evidence.** `production-campaign.json` v0.2 holds
   `workflow_sha`, `candidate`, `executed` (CLI and validator digests) and the
   report's run ID. It is attested by
   `latest-kernel-compatibility.yml@refs/heads/main`.

`scripts/production-readiness-report.sh` then requires, for each of the four
campaigns:
- v0.2 evidence from the default-branch workflow;
- a `candidate` block equal to the manifest's attested candidate (tag, commit,
  `SHA256SUMS`, evidence digest);
- `executed` digests equal to the candidate's `SHA256SUMS` entries, and the
  report's own `validator.sha256` equal to the candidate validator;
- a report run ID and start time matching the metadata;
- a start after the candidate's `generated_at`;
- an attestation whose source is the recorded `workflow_sha` on
  `refs/heads/main` and whose invocation is that exact run and attempt.

Campaign evidence recorded before this contract (v0.1) names only the
workflow commit and is never accepted.

Run the evidence aggregator after downloading the four campaign artifacts,
the expanded Falco report, candidate evidence, manual/T+24h/T+72h canary
manifests, rollback and fail-closed incident notes, and solo-maintainer
promotion confirmation:

```bash
scripts/production-readiness-report.sh \
  readiness/input.json readiness/bpfcompat-0.4.0-readiness.md
```
