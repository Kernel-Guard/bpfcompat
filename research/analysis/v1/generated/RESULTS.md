# Pilot v1 generated results

This file is generated from the canonical v1 dataset; it is descriptive pilot analysis, not a population estimate.

## Collection

- 70/70 execution records collected.
- Overall: 50 compatible, 13 incompatible, 7 inconclusive.
- Non-calibration: 50 compatible, 4 incompatible, 6 inconclusive.

## RQ1 — kernel-version predictiveness

For the controlled BPF_MAP_TYPE_RINGBUF probe, a simple Linux 5.8 threshold agreed with 8/9 conclusive observations (88.889%). The exception was almalinux-8-4.18, whose observed 4.18 vendor kernel supported the probe.

## RQ2 — failure taxonomy

Outside calibration there were 4 incompatible observations among 54 evaluable executions: COMMAND_VALIDATION_FAILURE = 2, UNSUPPORTED_MAP_TYPE = 2.

## RQ3 — loader-path observation

The paired Cilium-derived paths had 0 verdict disagreements across 9 conclusive environments. The contracts differ (load+attach vs load-only), so this is not a pure loader-effect estimate.

## RQ4 — vendor/environment variation

The dataset contains 10 exact environments across 10 logical profiles and 2 cross-vendor version inversions. Patch-level longitudinal change is not evaluable in v1.

## Limitations

- Selected stratified x86_64 pilot; not representative of global Linux deployments.
- Controlled probes and calibration are not mixed into real-world prevalence claims.
- Cilium paths use load+attach versus load-only, so agreement is not a pure loader-effect estimate.
- Oracle requested 5.15 but booted 6.12 UEK; seven executions are inconclusive for the requested profile.
- One exact environment per logical profile prevents patch-level longitudinal inference.
