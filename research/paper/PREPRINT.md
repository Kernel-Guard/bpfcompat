# Preprint working draft — pilot v1

Status: **working research draft, not peer reviewed and not yet archival-final.**

## Candidate title

**Kernel Version Is Not a Capability Contract: Empirical eBPF Artifact
Compatibility Across Linux Vendor Kernels**

## Draft abstract

eBPF portability is commonly reasoned about using kernel version, CO-RE, and
upstream feature-introduction points. Linux distributions, however, ship vendor
kernels with backports, rebases, configuration differences, and project-specific
loader behavior that can invalidate simple version-based compatibility
assumptions. We present BPFCompat, an empirical compatibility harness that boots
real Linux distribution kernels in disposable virtual machines and executes
compiled eBPF artifacts through libbpf or project-specific loader paths.

A frozen x86_64 pilot study executed seven validation cases across ten logical
Linux profiles, producing 70/70 planned execution records. Fifty observations
were compatible, thirteen incompatible, and seven inconclusive because one
Oracle Linux logical profile requested a 5.15 kernel family but the vendor image
booted 6.12 UEK. Excluding the calibration case, the pilot contains 50 compatible,
4 incompatible, and 6 inconclusive observations. For a controlled
`BPF_MAP_TYPE_RINGBUF` probe, a simple upstream Linux 5.8 threshold agreed with
8 of 9 conclusive observations; AlmaLinux 8's observed 4.18 vendor kernel was
the below-threshold compatible exception. The dataset also contains two
cross-vendor version inversions in which an older-numbered kernel passed while a
newer-numbered kernel failed. A purposefully stratified post-collection repeat
sample then reran seven canonical tuples three times each. All 21/21 repeats
matched the canonical verdict on the same exact environment; no environment
drift or same-environment verdict instability was observed in that bounded
sample.

These results are descriptive evidence from a selected pilot, not population
estimates for Linux deployments. The study publishes normalized evidence,
exact-environment identities, checksums, provenance, and deterministic analysis
scripts so the reported findings can be reproduced from the committed versioned
repository dataset.

## Claimed contributions

1. A reproducible method for testing compiled eBPF artifacts against real
   vendor kernels instead of inferring compatibility from version strings.
2. A provenance model that separates logical kernel profiles from the exact
   environments that actually booted.
3. A frozen pilot dataset with 70 execution records and deterministic RQ1–RQ4
   analysis.
4. Empirical examples showing that kernel-version ordering is not sufficient to
   define a capability ordering when vendor backports are present.
5. Loader-path observations using both libbpf and project-specific Cilium/Falco
   execution paths, while explicitly avoiding unsupported causal claims.

## Research questions

- **RQ1:** How predictive is kernel version of observed eBPF compatibility?
- **RQ2:** Why do otherwise portable eBPF artifacts fail?
- **RQ3:** How much does the loader affect the observed compatibility verdict?
- **RQ4:** How do vendor backports and exact execution environments change the
  relationship between kernel version and compatibility?

## Pilot results to preserve verbatim

- collection: 70/70 attempts;
- overall: 50 compatible, 13 incompatible, 7 inconclusive;
- non-calibration: 60 attempts, 50 compatible, 4 incompatible, 6 inconclusive;
- RQ1 ring-buffer threshold agreement: 8/9 conclusive observations (88.889%);
- below-threshold compatible profile: `almalinux-8-4.18`;
- non-calibration incompatibility taxonomy:
  - `UNSUPPORTED_MAP_TYPE`: 2;
  - `COMMAND_VALIDATION_FAILURE`: 2;
- paired Cilium-derived paths: 0 verdict disagreements across 9 conclusive exact
  environments, with non-comparable load+attach versus load-only contracts;
- exact environments: 10;
- cross-vendor version inversions: 2;
- patch-level longitudinal change: not evaluable in pilot v1.

The source of truth for these values is
`research/analysis/v1/generated/analysis-summary.json`, not this prose.

## Generated figures and tables

The final pilot-v1 figures and tables below are generated deterministically from
committed normalized evidence by
`scripts/research/generate-paper-assets-v1.py`. Their input and output SHA-256
values are frozen in
[`generated/asset-manifest.json`](generated/asset-manifest.json). CI
regenerates the full directory and requires a byte-for-byte match.

### Figure 1 — study architecture

[`generated/figures/figure-1-study-architecture.svg`](generated/figures/figure-1-study-architecture.svg)

Artifact/source selection → deterministic materialization → exact vendor VM
environment → BPFCompat/real-loader execution → normalized evidence → RQ
analysis.

### Figure 2 — ring-buffer version prediction versus observation

[`generated/figures/figure-2-ringbuf-version.svg`](generated/figures/figure-2-ringbuf-version.svg)

The figure includes the nine conclusive ring-buffer observations, the upstream
Linux 5.8 threshold, vendor identity, observed verdict, and the AlmaLinux 8 /
4.18 below-threshold compatible exception. The Oracle logical profile is omitted
from this figure because the requested 5.15 environment was not observed.

### Figure 3 — compatibility matrix

[`generated/figures/figure-3-compatibility-matrix.svg`](generated/figures/figure-3-compatibility-matrix.svg)

Rows are the seven frozen study cases and columns are the ten logical profiles.
Cells encode compatible, incompatible, or inconclusive using both symbols and
fill. The calibration case is visually separated from primary/controlled cases.

### Table 1 — frozen corpus and validation contracts

[`generated/tables/table-1-corpus-contracts.md`](generated/tables/table-1-corpus-contracts.md)

### Table 2 — failure taxonomy

[`generated/tables/table-2-failure-taxonomy.md`](generated/tables/table-2-failure-taxonomy.md)

Calibration and non-calibration denominators are kept separate.

### Table 3 — exact environment provenance

[`generated/tables/table-3-environments.md`](generated/tables/table-3-environments.md)

### Table 4 — repeat-run stability

[`generated/tables/table-4-repeat-stability.md`](generated/tables/table-4-repeat-stability.md)

The repeat table remains a bounded post-collection stability check, not an
estimate of population-wide nondeterminism.

## Limitations

- selected, stratified x86_64 pilot; not representative of global Linux
  deployments;
- only one exact environment per logical profile in the canonical collection;
- Oracle 5.15 logical profile was not actually available in the observed run;
- the paired Cilium paths have different validation contracts, so agreement is
  not a pure loader-effect estimate;
- project-loader coverage is intentionally narrow;
- patch-level longitudinal effects are not estimable from pilot v1.

## Publication gates

Do not convert this working draft into a submission-ready manuscript until:

1. the committed 21-attempt repeat-run stability snapshot remains verifiable;
2. final figures/tables are generated from normalized data;
3. the v1 archival/redistribution manifest passes;
4. a research-tagged immutable release is created;
5. the release/data package is deposited in a DOI-granting archive;
6. the DOI and exact release version are added to `CITATION.cff`.

Academic references or university resource-page links should be added only
after they are independently verifiable, and should be described as
`referenced by` or `cited by`, not as approval or endorsement.
