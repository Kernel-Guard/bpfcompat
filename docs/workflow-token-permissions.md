# Workflow token permissions

Every workflow in `.github/workflows` declares read-only top-level
`permissions`. Write access to `GITHUB_TOKEN` is granted only at the job that
uses it. `scripts/check-workflow-permissions.sh` enforces both rules in CI
(`scripts/check-workflow-permissions_test.sh`):

- a top-level write, `write-all`, or a missing top-level block fails;
- a job-level write must be listed, with a justification, in
  `scripts/workflow-write-permissions.allow`;
- an allowlist entry that no longer matches a grant fails.

## How OpenSSF Scorecard scores this (v5.5.0)

The `Token-Permissions` check (`checks/evaluation/permissions.go`) treats the
two levels differently:

- A **top-level** `contents`, `packages` or `actions` write lowers the check
  score by 10, i.e. to 0.
- A **job-level** write is logged as a warning. It lowers the score only when
  the same workflow also has a top-level write, or declares no top-level
  permissions.

The SARIF output that becomes code-scanning alerts (`pkg/scorecard/sarif.go`)
skips a check whose score meets the policy minimum, or is inconclusive.
Below the minimum, with details enabled, each warning that has a file location
becomes an alert carrying the check score (`shouldAddLocation`). That is why
one top-level grant in
`scholarly-release-v1.yml` (alert #178) also turned the five required
job-level grants into "score is 0" alerts (#173–#177).

The same v5.5.0 binary was run locally (`--local`, `--checks
Token-Permissions`, policy minimum 10):
- on main `802d515` it reproduces exactly alerts #173–#178;
- on the read-only-top-level tree it scores 10 and emits no SARIF results.

The job-level warnings are still present in `--show-details` output. They
describe the required grants below.

## Required job-level write grants

These are the five write grants Scorecard reported (#173–#177). Each is
limited to the one job that uses it and is not dismissed.

| Alert | Workflow / job | Grant | Used by | Gate |
|---|---|---|---|---|
| #173 | `promote-release.yml` / `promote` | `contents: write` | `scripts/promote-release.sh` `gh release edit` publishes the verified draft | `production-release` environment: `v*` tags only, 15-minute wait, no admin bypass; exact candidate run, commit and digest inputs plus typed confirmation |
| #174 | `promote-release.yml` / `promote` | `packages: write` | `scripts/promote-release.sh` `docker buildx imagetools create` writes the promoted image tag | same environment and inputs as #173; digest verified by cosign before promotion |
| #175 | `release-artifacts.yml` / `stage-draft-release` | `contents: write` | `softprops/action-gh-release` creates a **draft** release (`draft: true`, `make_latest: false`) | `if: startsWith(github.ref, 'refs/tags/v')`; tags are immutable (ruleset); publication still requires #173 |
| #176 | `release-candidate-canary.yml` / `external-consumers` | `actions: write` | `gh workflow run external-consumer-canary.yml` at the immutable RC tag | needs the planning job's observation window; dispatch only, no contents or packages write |
| #177 | `rollback-drill.yml` / `rollback` | `packages: write` | `docker buildx imagetools create` moves the drill-only `rollback-drill-*` alias | `production-drill` environment; `GITHUB_REF` must be `refs/heads/main`; `latest` proven unchanged |

`release-candidate-canary.yml` (#176) produces the v0.4.0 release-candidate
evidence, so it is not changed while a qualification window is open. A
reusable-workflow call could replace the dispatch and drop `actions: write`.
That would change the evidence contract (`external_consumer_run_id`), so it
belongs after graduation.

## research-v1

`scholarly-release-v1.yml` runs on every push that changes its own file.
`research-v1` was published once, from `141c491`, and is immutable.

A read-only `state` job (`scripts/research-v1-release-state.sh`)
decides whether the write-scoped `publish` job may run:
- **publish** only for the original first publication from the pinned commit;
- **skip, green** only when the published tag, release, assets, lock,
  checksums and attestations all verify;
- **fail** in every other case, never a silent skip.
