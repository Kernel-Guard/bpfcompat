# Pilot Corpus v1 — Inclusion and Exclusion Criteria

These criteria were frozen before confirmatory v1 execution.

## Inclusion requirements

A case is eligible only when all applicable conditions hold:

1. **Immutable source provenance.** The source is pinned to a Git commit or the
   repository contains a frozen derivative pinned to a BPFCompat commit.
2. **Immutable executable identity before execution.** Generated objects and
   project loaders must be archived and SHA-256 recorded before their first
   research execution.
3. **Known validation contract.** Load-only, load+attach, or project-loader
   command semantics are explicit. A result from one contract is not silently
   treated as equivalent to another.
4. **Reproducible acquisition/build path.** The build or pull recipe is
   documented. Exact toolchain versions not encoded by source metadata must be
   captured in the build record.
5. **License/redistribution status is recorded.** Unknown licensing is an
   exclusion until resolved.
6. **Kernel compatibility is actually observable.** Framework/runtime failures
   that are independent of the kernel are separated from kernel compatibility
   outcomes.
7. **Raw evidence can be retained.** Every executed verdict must be backed by
   the report hash and evidence reference required by the corpus schema.

## Mutable references

Branch names and tags such as `main`, `master`, and `:latest` may be used
only to discover a candidate. They are not frozen identities.

Before execution they must resolve to one of:

- Git commit SHA;
- OCI manifest digest;
- archived binary/object SHA-256;
- another documented content-addressed identity.

## Adapted upstream source

A locally adapted upstream example may be included when:

- the exact upstream revision is known;
- adaptations are small and documented;
- the local derivative is pinned to an immutable BPFCompat revision;
- the case is labeled `primary_oss_derived`, not represented as an unmodified
  upstream artifact.

## Controlled probes

Controlled probes are included to isolate mechanisms such as ring-buffer
availability and fallback behavior. They must be reported in a separate stratum
from real-world/project artifacts.

Intentionally failing probes used to test classifier/evidence behavior are
`calibration` cases and are excluded from compatibility-prevalence
denominators.

## Framework-coupled artifacts

An artifact is deferred from the primary kernel-compatibility corpus when its
standalone result is dominated by a framework API, injected BTF, bytecode
rewrite, attach rewrite, or other runtime contract not reproduced by the
selected validator.

Such cases may form a separate future study with the real framework loader.

## Environment requirements

The v1 selection freezes logical BPFCompat profile IDs. Each actual boot must
also capture an immutable exact-environment identity after observing the real
kernel and image state.

A mutable vendor image URL is never itself an exact-environment identity.

## Change control

After the first v1 execution begins:

- changing the selected cases or logical profiles requires a new corpus version;
- rebuilding a generated object/loader with a different hash creates a new
  materialized identity;
- replacing a missing or failed result does not overwrite the original attempt;
- exclusions and deviations are documented rather than silently removed.
