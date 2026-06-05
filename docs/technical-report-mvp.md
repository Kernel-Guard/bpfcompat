# Technical Report: MVP Compatibility Validation

Date: 2026-05-15  
Scope: Adaptive BPF Compatibility Runtime Delivery Platform MVP (`bpfcompat`)

## Executive Summary

This report demonstrates VM-backed compatibility validation of compiled eBPF artifacts across multiple Linux kernel/distro targets, with per-target logs, failure classification, and remediation guidance.

The MVP currently validates against an 8-profile matrix and produces both machine-readable (`.json`) and human-readable (`.md`) reports. It is suitable as a release-gate proof-of-concept for compatibility risk detection.

## Validation Environment

- Matrix: `matrices/mvp.yaml`
- Profiles:
  - `ubuntu-18.04-4.15`
  - `ubuntu-20.04-5.4`
  - `ubuntu-22.04-5.15`
  - `ubuntu-22.04-minimal-5.15`
  - `ubuntu-24.04-6.8`
  - `debian-11-5.10`
  - `debian-12-6.1`
  - `debian-13-6.12`
- Execution model: disposable QEMU/KVM VMs per target profile
- Validator: `validator/c-libbpf/bin/bpfcompat-validator` (guest-side libbpf load/attach attempts)

## Method

1. Build CLI, validator, and fixtures.
2. Execute `make acceptance`.
3. Run six fixture cases covering baseline pass plus representative compatibility failure patterns.
4. Enforce report assertions via `jq`/`grep`.
5. Generate aggregate evidence via `make acceptance-evidence`.

Acceptance implementation:

- `scripts/acceptance.sh`
- `docs/acceptance-tests.md`
- `docs/mvp-acceptance-evidence.md`

## Results Snapshot

From `docs/mvp-acceptance-evidence.md`:

- `simple-pass`: pass (`7/1`)
- `ringbuf-modern`: fail (`5/3`) with `UNSUPPORTED_MAP_TYPE` on older kernels
- `perfbuf-fallback`: pass (`7/1`)
- `core-relocation`: fail (`0/8`) with `MISSING_BTF` and `CORE_RELOCATION_FAILURE`
- `unsupported-attach`: fail (`0/8`) with `UNSUPPORTED_ATTACH_TYPE`
- `unknown-load-fail`: fail (`0/8`) with `UNKNOWN` (non-ELF load failure path)

Observed behavior confirms:

- Compatibility variance across kernels is real and measurable.
- Failure reasons can be normalized into actionable classes.
- Fallback artifact strategy (ringbuf -> perfbuf) is demonstrable.
- Acceptance suite now proves five deterministic failure classes.

## Evidence Artifacts

- Aggregate reports:
  - `reports/simple-pass-mvp.json`, `reports/simple-pass-mvp.md`
  - `reports/ringbuf-modern-mvp.json`, `reports/ringbuf-modern-mvp.md`
  - `reports/perfbuf-fallback-mvp.json`, `reports/perfbuf-fallback-mvp.md`
  - `reports/core-relocation-mvp.json`, `reports/core-relocation-mvp.md`
  - `reports/unsupported-attach-mvp.json`, `reports/unsupported-attach-mvp.md`
  - `reports/unknown-load-fail-mvp.json`, `reports/unknown-load-fail-mvp.md`
- OSS validation reports:
  - `evidence/oss-validation/reports/cilium-tracepoint-in-c-mvp.json`
  - `evidence/oss-validation/reports/cilium-tracepoint-in-c-mvp.md`
  - `evidence/oss-validation/reports/bcc-execsnoop-mvp.json`
  - `evidence/oss-validation/reports/bcc-execsnoop-mvp.md`
  - `evidence/oss-validation/summary.md`
- Raw runtime logs per target:
  - `.bpfcompat/runs/**/libbpf.log`
  - `.bpfcompat/runs/**/validator-result.json`
  - `.bpfcompat/runs/**/serial.log`
  - `evidence/oss-validation/raw-runs/**`

## Security and Isolation Position (MVP)

- Untrusted artifacts are validated in disposable VMs.
- Host runner path is intentionally unavailable in MVP.
- VM execution uses bounded CPU/memory and explicit orchestration networking.

Reference: `docs/security-model.md`.

## Current Limits

- Matrix depth is 8 profiles (target should be 15+ for stronger enterprise coverage).
- Optional profile behavior still needs refinement (for example `ubuntu-22.04-minimal-5.15` attach compatibility in current fixtures).
- Runtime loading and hosted-service claims remain outside the MVP scope.

## Recommendation for Pilot Use

Use the MVP as a pre-release compatibility gate for eBPF artifact families where customer kernels vary. The immediate value is faster root-cause isolation (map/BTF/attach class) before production rollout.

Recommended next technical milestones:

1. Expand profile matrix from 8 to 15+ maintained targets.
2. Keep CI action output simple: pass/fail matrix first, drill-down second.
3. Continue adding project-suite adapters for real eBPF artifact collections.

External CI gate proof has been demonstrated in `docs/external-ci-proof.md`.
