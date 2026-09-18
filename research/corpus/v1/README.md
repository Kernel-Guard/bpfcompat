# Pilot Corpus v1 — Frozen Selection

This directory freezes the **selection** for BPFCompat's first prospective
research pilot. Study results are kept separately in
[`research/data/v1/`](../../data/v1/) and
[`research/analysis/v1/`](../../analysis/v1/) so the prospective selection
boundary remains distinct from post-collection evidence.

The selection was made after reviewing the repository's existing Falco,
Inspektor Gadget, Cilium/ebpf, libbpf-validator, controlled-probe, and kernel
matrix evidence. Final execution records must still satisfy
[`research/corpus/SCHEMA.md`](../SCHEMA.md), including immutable artifact,
validator/loader, exact-environment, validation-contract, raw-report, and
evidence identities.

## Freeze boundary

The following are frozen for v1:

- which artifact/project cases are eligible;
- which controlled probes are calibration cases;
- which logical kernel profiles are in scope;
- which validation semantics are intended for each case;
- inclusion/exclusion rules.

The following are **not** invented before execution:

- compiled artifact SHA-256 values;
- project-loader binary SHA-256 values;
- exact vendor image/kernel environment hashes;
- canonical validation-contract hashes that depend on materialized binaries.

Those identities are captured before the first execution and become immutable
parts of the collected dataset. If a materialized identity changes, it is a new
corpus version or a new execution identity; v1 is not silently rewritten.

## Selected strata

### Real project loader

**Falco modern_bpf / `scap-open`** is the strongest real-world case already
proven by the repository. The upstream Falco workflow builds the real static
loader and uses its exit code after loading, attaching, and capturing a bounded
number of events. v1 pins the Falco source revision rather than using a moving
branch.

### OSS-derived artifact

**cilium/ebpf `tracepoint_in_c`** is retained because the repository already
contains a minimal, documented adaptation and a manifest. The upstream source
revision that was current for the file before the recorded 2026-05-15 retrieval
date is now pinned explicitly. The local derivative is also pinned to the
BPFCompat commit from which this selection was created.

### Loader-comparison case

The repository's static **cilium/ebpf v0.22.0** example loader is paired with
selected objects so RQ3 can compare a Go loader implementation with the bundled
libbpf validation path. Load-only comparisons must be kept separate from
load+attach results.

### Controlled probes

`simple-pass`, `ringbuf-modern`, and `perfbuf-fallback` are included as
mechanism controls. `core-relocation-fail` is a calibration-only negative
control and must not be counted in real-world failure prevalence.

## Inspektor Gadget decision

Inspektor Gadget was reviewed but is **deferred from the frozen v1 primary
corpus**.

The existing BPFCompat case study invokes `trace_open:latest` and
`trace_exec:latest`. A mutable tag is not sufficient for a frozen research
corpus. The upstream Inspektor Gadget compatibility workflow now resolves OCI
manifest digests before execution, which is the correct mechanism, but v1 will
not invent a historical digest for the existing case-study runs.

`trace_open` and `trace_exec` can enter a later corpus version only after the
exact OCI manifest digest and extracted eBPF ELF SHA-256 are captured together.
`trace_dns` remains a separate framework-coupled case because standalone
validation lacks the Inspektor Gadget socket-enricher BTF/runtime contract.

See [`deferred.yaml`](deferred.yaml).

## Environment selection

The ten logical profiles in [`environments.yaml`](environments.yaml) preserve
the highest-value contrasts already demonstrated by BPFCompat:

- upstream ring-buffer boundary (5.4 vs 5.8);
- RHEL-family ring-buffer backport on an older-numbered 4.18 kernel;
- Amazon Linux 2 4.14 vs 5.10;
- Falco's 5.15 program-variant band;
- modern 6.1/6.8 kernels;
- Oracle UEK rebase behavior;
- SUSE/openSUSE vendor tier.

The selection file is not an exact-environment record. At execution time each
booted target gets an `exact_environment_id` as required by the corpus schema.

## Analysis denominator rules

- `primary_real_world` and `primary_oss_derived` cases may contribute to
  empirical compatibility summaries, with their strata reported separately.
- `controlled_probe` cases explain mechanisms and boundaries; they are not
  mixed into real-world artifact prevalence.
- `calibration` cases test the evidence/classification pipeline and are never
  used to estimate field failure rates.
- deferred/framework-coupled cases are reported as exclusions, not failures.

## Collection status

Pilot v1 has been materialized and executed. The canonical successful collection
is workflow run `35393833464` at commit
`5de550e5cc8c659872a90fc262eb0250c229bf23`, with all 70 planned
case/profile attempts captured.

The repository dataset snapshot records processed execution evidence,
exact-environment identities, execution provenance, and raw-report checksums.
Descriptive analysis is generated deterministically from that snapshot. Further
work now focuses on representative repeat-run stability, license/redistribution
review, final paper figures/tables, and durable DOI archival.
