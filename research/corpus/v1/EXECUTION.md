# Pilot v1 Execution Protocol

This phase executes the frozen v1 inputs against the ten frozen logical kernel
profiles and converts BPFCompat reports into a research dataset.

The authoritative workflow is:

`.github/workflows/research-pilot-v1.yml`

The full study is **manual-only** through `workflow_dispatch`. Pull requests run
only preflight checks; they do not consume the 70 VM-target executions.

## Frozen execution matrix

`execution-matrix.yaml` contains ten logical profiles, all marked non-gating at
the BPFCompat matrix layer. This is deliberate: expected incompatibilities are
observations. The research normalizer, not BPFCompat's CI exit code, enforces
collection completeness.

Profile YAML identities are frozen in `profile-identities.json`. Before a run,
CI verifies the exact Git blob for each `vm/profiles/<id>.yaml` and each
research manifest.

## Study cases

The plan in `study-plan.json` defines seven cases:

1. simple-pass via libbpf load+attach;
2. ringbuf-modern via libbpf load+attach;
3. perfbuf-fallback via libbpf load+attach;
4. the CO-RE negative control via libbpf load-only;
5. Cilium-derived tracepoint via libbpf load+attach;
6. the same Cilium-derived object through cilium/ebpf v0.22.0 load-only;
7. Falco `modern_bpf` through the real `scap-open` loader.

That yields **70 target attempts** (7 cases × 10 logical profiles).

The CO-RE failure is a calibration case and must not be included in real-world
failure prevalence.

## Exact environment identity

For every target that boots far enough to report environment evidence, the
normalizer constructs a canonical record from:

- logical profile id;
- distro and distro release;
- architecture;
- requested kernel family;
- observed `uname -r`;
- vendor image source URL;
- actual base-image SHA-256 captured by BPFCompat;
- immutable profile Git-blob identity;
- kernel-family match result.

The SHA-256 of canonical JSON is the `exact_environment_id`.

The frozen execution binary is BPFCompat v0.3.7. Its `ReportV01` predates the
later top-level validator provenance, per-target verdict, and structured
environment fields. The research runner therefore writes
`execution-provenance.json` *before* any case runs, hashing the exact
BPFCompat CLI, static validator, and project loader binaries. The normalizer
binds those hashes to the frozen materialization lock.

For v0.3.7 targets, the normalizer derives the producer verdict only from the
known `status` taxonomy and derives kernel-family match from the immutable
profile/host fields. If a later report supplies those fields directly, they
must agree with the derived values or normalization fails.

A compatible/incompatible verdict without an exact environment identity is
downgraded to `inconclusive/evidence_unavailable` in the research dataset.
A kernel-family mismatch is still assigned an exact identity for the
environment that actually ran, but its execution verdict is
`inconclusive/environment_unavailable`, not a compatibility observation.

If the same logical profile resolves to more than one exact environment during a
single study collection, normalization marks environment drift and the collection
is incomplete.

## Validation-contract binding

The materialization phase froze base validation-contract identities. For
libbpf cases, execution also binds the exact research manifest by computing:

```text
SHA256(canonical_json({
  base_validation_contract_id,
  manifest_sha256
}))
```

Command-mode cases use their already-complete frozen command contract.

## Outputs

The workflow keeps raw reports and produces:

```text
reports/research-v1/
├── execution-provenance.json
├── <case>.json
├── <case>.md
├── logs/
└── normalized/
    ├── exact-environments.json
    ├── executions.jsonl
    └── collection-summary.json
```

`executions.jsonl` is the input for later RQ1–RQ4 analysis. Raw report
SHA-256 values and evidence paths are retained in every normalized execution
record.

## Completion semantics

`collection_complete: true` requires:

- every frozen case produced a report;
- every case contains exactly ten targets;
- every selected logical profile produced at least one exact environment;
- no logical profile drifted to multiple exact environments during collection.

`fully_evaluable` is stricter and is false when any execution remains
inconclusive.

This preserves infrastructure failures without silently converting them into
eBPF incompatibilities.
