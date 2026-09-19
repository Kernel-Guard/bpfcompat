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

## Canonical repeat collection

The canonical successful repeat collection is GitHub Actions run
`35445834557` at commit
`d2a78e05178ea6dd82ead9684f5eedf49066903f`. Its Actions artifact is
`10584409793` with SHA-256
`895fd41dae147c592d5cdec91bbd99150f9dd14c35afadf72bc14954a192a0e5`.

The run completed all **21/21** planned attempts across the seven frozen sample
tuples. All 21 observations reproduced the canonical verdict on the same exact
environment. Environment drift was **0** and same-environment verdict
instability was **0**.

Repository evidence:

- `repeat-dataset-manifest.json` binds the canonical run and Actions artifact;
- `data/stability-summary.json` preserves the generated tuple-level result;
- `data/repeat-provenance.json` binds the runner inputs and binary identities;
- `data/raw-report-checksums.json` freezes all 21 raw report paths and hashes;
- `data/projection-metadata/` preserves the repeat-only manifest projections;
- `scripts/research/verify-repeat-snapshot-v1.py` verifies the committed hash
  and provenance chain.

The row-level `repeat-executions.jsonl`, raw reports, VM logs, and generated
projection YAMLs remain in the content-addressed workflow artifact for later DOI
archival rather than being duplicated into Git history.

The earlier manual run `35443831085` is diagnostic only: it exposed the
singleton-matrix/manifest scheduling bug and is not part of the repeat dataset.
