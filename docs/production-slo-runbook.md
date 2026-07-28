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
- `reports/production-campaign.json`, which binds the scheduled workflow run,
  commit SHA, report name, report SHA-256, and start time

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

Run the evidence aggregator after downloading the four campaign artifacts,
the expanded Falco report, candidate evidence, rollback note, and reviewer
approval:

```bash
scripts/production-readiness-report.sh \
  readiness/input.json readiness/bpfcompat-0.4.0-readiness.md
```
