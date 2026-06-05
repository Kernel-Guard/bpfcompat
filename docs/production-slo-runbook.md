# Production SLO Runbook

This runbook defines technical service objectives for production operation of `bpfcompat`.

## Scope

- VM-backed compatibility validation (`bpfcompat test`)
- Runtime selection/fetch/execute control plane (`bpfcompat runtime *`)
- Registry/history integrity verification (`bpfcompat history verify`)

## SLOs

1. Validation success-path reliability:
   - SLO: >= 99% of scheduled production validation jobs complete without `infra_error`.
2. Registry integrity check:
   - SLO: 100% of daily `history verify` runs pass.
3. Report generation latency:
   - SLO: p95 end-to-end report generation within configured timeout budget for selected matrix.
4. Deployment safety:
   - SLO: 0 unsigned/tampered history records accepted as valid.

## SLI Signals

- `summary.status` and per-target `status` from report JSON
- `infra_error` count per run
- `history verify` pass/fail count
- duration metrics from run metadata (`started_at`, `finished_at`)

## Alert Triggers

1. `history verify` fails any record: page immediately.
2. Scheduled campaign has >1% `infra_error` over trailing 24h: page.
3. Two consecutive production-tech checks not-ready: page and freeze rollout.

## Daily Operator Checklist

1. Run `make production-tech-check`.
2. Review newest `evidence/production-tech/production-tech-check-*.md`.
3. Review newest `evidence/production-tech/tech-stability-*.md`.
4. If any gate is not-ready, pause promotion and follow incident runbook.

