# External CI Proof (B-04)

As of: 2026-06-03
Blocker: `B-04` (External CI Proof)

## Objective

Prove the composite GitHub Action works in a clean third-party repository and
that compatibility failures block CI with `rc=2`.

## Reference Repository

- Repo: `ErenAri/bpfcompat-external-ci-proof`
- URL: <https://github.com/ErenAri/bpfcompat-external-ci-proof>
- Workflows:
  - <https://github.com/ErenAri/bpfcompat-external-ci-proof/blob/main/.github/workflows/external-positive.yml>
  - <https://github.com/ErenAri/bpfcompat-external-ci-proof/blob/main/.github/workflows/external-negative.yml>
  - <https://github.com/ErenAri/bpfcompat-external-ci-proof/blob/main/.github/workflows/external-suite.yml>

Public repositories can reference `Kernel-Guard/bpfcompat@v0.2.0` directly.

## Source Refs Validated

- Single-artifact gate ref: `4cd803381b65db2101c8dca8e9cf885fec6c9563`
- Suite-mode gate ref: `a29df687ae54be9db0ac3ba04495f14311b40968`

## Runner Context

- Self-hosted Linux x64 runner with KVM (`/dev/kvm`) on 2026-05-15.
- Ephemeral self-hosted Linux x64 KVM runner
  `bpfcompat-external-kvm-1780512645` on 2026-06-03.

## Executed Proof Runs

### 1) Positive Gate (expected `rc=0`)

- Workflow: `bpfcompat-external-positive`
- Run ID: `25920734163`
- URL: <https://github.com/ErenAri/bpfcompat-external-ci-proof/actions/runs/25920734163>
- Started (UTC): `2026-05-15T13:35:23Z`
- Conclusion: `success`
- Log evidence:
  - `Run ID: 20260515T133558Z-ee5bc2`
  - `Status: pass`
  - `All required profiles passed validator load checks.`

### 2) Negative Gate (expected `rc=2`)

- Workflow: `bpfcompat-external-negative`
- Run ID: `25920799978`
- URL: <https://github.com/ErenAri/bpfcompat-external-ci-proof/actions/runs/25920799978>
- Started (UTC): `2026-05-15T13:36:46Z`
- Conclusion: `failure` (expected for gate enforcement)
- Log evidence:
  - `Run ID: 20260515T133732Z-475986`
  - `Status: fail`
  - `Compatibility check failed on at least one required profile.`
  - `Process completed with exit code 2.`

### 3) Suite Mode Gate (expected `rc=0`)

- Workflow: `bpfcompat-external-suite`
- External proof repo ref: `3394a5bfa0e082ffd98eb89fa37073208bec4af4`
- Source ref requested: `a29df687ae54be9db0ac3ba04495f14311b40968`
- Run ID: `26905445798`
- URL: <https://github.com/ErenAri/bpfcompat-external-ci-proof/actions/runs/26905445798>
- Started (UTC): `2026-06-03T18:40:19Z`
- Conclusion: `success`
- Job duration: `6m55s`
- Log evidence:
  - `Status: pass`
  - `simple-pass: pass run=20260603T185700Z-630fcf`
  - `functional-execve: pass run=20260603T185725Z-9b107b`
  - Uploaded `reports/external-suite.json` and `reports/external-suite.md`.

## Conclusion

External third-party single-artifact CI integration is demonstrated with both:

1. pass path (`rc=0`) and successful workflow conclusion, and
2. required-failure path (`rc=2`) that fails the workflow as a gate.

Suite-mode external CI integration is also demonstrated in the clean reference
repository with two artifacts running through one suite file on a self-hosted
Linux/KVM runner.

## Current Action Shape

The action now supports two integration modes:

1. single-artifact mode with `artifact`, `manifest`, `matrix`, `out`, and
   `markdown` inputs, and
2. suite mode with a `suite` YAML file that lists multiple artifact/manifest
   cases.

Suite mode is intended for projects with several `.bpf.o` outputs, matching the
common maintainer request for a CI input that accepts a VM/kernel list, a list
of artifacts, and manifest-described test steps.
