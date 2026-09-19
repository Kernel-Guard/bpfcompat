# Zenodo deposit plan — BPFCompat Research Dataset v1

This file is the operator checklist for creating the DOI-bearing archival record
for the already-published GitHub research release.

Do not publish a Zenodo record with placeholder or guessed identifiers. Reserve
or mint the DOI in Zenodo first, then update repository citation metadata in a
separate commit.

## Source release

- GitHub tag: `research-v1`
- release title: **BPFCompat Research Dataset v1**
- release commit:
  `141c491bd1508600338e7bc27abbc5a117eb7508`
- GitHub release:
  `https://github.com/Kernel-Guard/bpfcompat/releases/tag/research-v1`

## Recommended deposit mode

Use a **manual Zenodo upload** for the v1 research dataset.

Reason: the GitHub release already exists, while Zenodo's GitHub integration
automatically ingests new releases only after the repository is enabled. The
research object is also a mixed evidence/data/reproducibility bundle rather than
only a software source release.

## Files

Upload these four files from the GitHub release without modification:

| File | Size | SHA-256 |
| --- | ---: | --- |
| `archive-manifest.json` | 458,992 B | `6ed6d38d57db57e75964829278a62c7bb4a12cd8fc5db97baebb05a1fdd5e927` |
| `archive-lock.json` | 1,506 B | `44e0ebe3d32c2c388002a4f44e5d0bf9a476a20ee702c137471a6be89235ddf3` |
| `bpfcompat-research-v1-payload.zip` | 12,899,271 B | `143a8e8a93e43aebbacfd73465a659ca4cb055db7a576960c9d50ed9bc90a817` |
| `RELEASE-CHECKSUMS.txt` | 272 B | `bc96087d78bdd8419189b2e51927f3e5c2908dad81155313663af3f29125fdd9` |

Verify the downloaded files against `RELEASE-CHECKSUMS.txt` before upload.

## Zenodo metadata

Use these values unless the Zenodo UI requires an equivalent normalized form.

- **Resource type:** Dataset
- **Title:** BPFCompat Research Dataset v1: Empirical eBPF Compatibility Across Linux Vendor Kernels
- **Publication date:** 2026-09-19
- **Creator:** Eren Arı
- **Version:** research-v1
- **Language:** English
- **Visibility:** Public
- **Licenses:** Apache-2.0 and MIT
- **Keywords:**
  - eBPF
  - BPF
  - Linux kernel
  - compatibility
  - vendor kernels
  - libbpf
  - BTF
  - CO-RE
  - reproducibility
  - systems research

Suggested description:

> BPFCompat Research Dataset v1 is a frozen reproducibility package for an
> empirical pilot study of compiled eBPF artifact compatibility across Linux
> vendor kernels and loader paths. The canonical pilot contains 70/70 planned
> executions: 50 compatible, 13 incompatible, and 7 inconclusive. A bounded
> post-collection stability sample contains 21/21 same-exact-environment
> observations with no observed environment drift or same-environment verdict
> instability. The archive includes normalized evidence, deterministic
> RQ1–RQ4 analysis inputs/outputs, generated paper figures/tables, provenance,
> exact environment identities, and permitted materialized study inputs.
> Third-party compiled loader binaries whose complete redistribution notice set
> was not established are excluded and represented by hashes, source revisions,
> validation-contract identities, notices, and rebuild provenance. This release
> is a reproducibility archive of pilot evidence and is not a claim of peer
> review, population representativeness, institutional approval, or
> endorsement.

### DOI field

Select **No** for "Do you already have a DOI for this upload?" and use
**Get a DOI now** if you want the version DOI before publishing.

Record both identifiers after publication:

- **Version DOI** — cite this for exact `research-v1` reproducibility.
- **Concept DOI** — use this only when intentionally referring to the evolving
  BPFCompat research dataset across versions.

## Mixed-license note

The payload contains BPFCompat-owned Apache-2.0 material and permitted
third-party-derived MIT material. File-level provenance, redistribution status,
and retained notice paths are authoritative in `archive-manifest.json`.
The excluded cilium/ebpf and Falco loader binaries are not present in the
payload.

## After Zenodo publication

Do not alter the `research-v1` GitHub release.

Create a new repository commit/PR that:

1. records the Zenodo record URL, version DOI, and concept DOI;
2. marks the DOI roadmap gate complete;
3. adds the **version DOI** to `CITATION.cff` for exact v1 citation;
4. adds DOI links to the repository/research README;
5. preserves the GitHub tag/release/archive hashes unchanged.
