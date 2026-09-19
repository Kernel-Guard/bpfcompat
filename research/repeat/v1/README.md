# Pilot v1 Repeat-Run Stability

This directory defines a **post-collection, purposefully stratified** repeat-run
sample for pilot v1. It is not a preregistered sample and it is not intended to
estimate a population-wide nondeterminism rate.

The sample covers seven canonical execution tuples:

- a compatible controlled baseline;
- a known ring-buffer incompatibility below the upstream boundary;
- the AlmaLinux 8 / 4.18 ring-buffer backport case;
- positive and negative Falco real-loader cases;
- a positive cilium/ebpf project-loader case;
- the Oracle logical-profile environment mismatch.

Each tuple is repeated three times in one workflow collection, for 21 planned
attempts. Frozen v1 artifacts, loaders, validation semantics, and profile
definitions are reused.

For libbpf-backed cases, the frozen v1 manifests list all ten study profiles in
`required_profiles`. The repeat study executes only one sampled profile per
tuple, so the runner creates a **repeat-only manifest projection** whose sole
change is narrowing `required_profiles` to that sampled profile. Before doing
so it verifies the frozen source manifest Git-blob identity from
`study-plan.json`. The projected manifest and a metadata record containing its
SHA-256, source Git blob, and projection rule are retained in the workflow
artifact. Program, attach, and validation semantics are not rewritten.

## Interpretation

The repeat analyzer distinguishes two failure modes:

1. **environment drift** — the repeated execution resolves to a different
   `exact_environment_id` than the canonical run. This is environmental
   change, not compatibility nondeterminism;
2. **verdict instability** — the repeated execution resolves to the same exact
   environment but produces a different compatibility verdict.

A repeat can only be called stable against the canonical observation when both
the exact environment ID and normalized verdict match.

The workflow is manual-only because it boots real vendor VMs and is intended as
a bounded research validation, not a routine CI gate.

## Run

After this protocol lands on `main`:

```bash
gh workflow run research-repeat-v1.yml --repo Kernel-Guard/bpfcompat --ref main
```

The workflow publishes raw repeat reports, logs, repeat-only manifest
projections and their provenance metadata, a repeat provenance record,
`repeat-executions.jsonl`, `stability-summary.json`, and generated
`RESULTS.md` as a staging Actions artifact.
