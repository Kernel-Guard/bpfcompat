# BPFCompat Research Dataset v1 — Zenodo deposit checklist

This document records the **post-release** DOI workflow for the already-published
BPFCompat research dataset. It intentionally lives outside `research/**` so the
frozen `research-v1` archive payload and its committed archive lock remain
unchanged.

## Current publication state

- GitHub tag: `research-v1`
- tag type: annotated tag
- tag target commit:
  `141c491bd1508600338e7bc27abbc5a117eb7508`
- GitHub release: **BPFCompat Research Dataset v1**
- GitHub release ID: `392145710`
- published: `2026-09-19T16:58:52Z`
- DOI: **not yet minted**

The GitHub API does not mark the release object itself immutable. Project policy
for v1 is therefore **no mutation**: corrections must produce a new research
version instead of replacing published v1 evidence.

## Release assets

Upload the following release assets to Zenodo without modification.

| File | Size | GitHub SHA-256 |
| --- | ---: | --- |
| `archive-manifest.json` | 458,992 B | `6ed6d38d57db57e75964829278a62c7bb4a12cd8fc5db97baebb05a1fdd5e927` |
| `archive-lock.json` | 1,506 B | `44e0ebe3d32c2c388002a4f44e5d0bf9a476a20ee702c137471a6be89235ddf3` |
| `bpfcompat-research-v1-payload.zip` | 12,899,271 B | `143a8e8a93e43aebbacfd73465a659ca4cb055db7a576960c9d50ed9bc90a817` |
| `RELEASE-CHECKSUMS.txt` | 272 B | `bc96087d78bdd8419189b2e51927f3e5c2908dad81155313663af3f29125fdd9` |

The release workflow generated GitHub build-provenance attestations for all four
files before publishing the release.

## Recommended Zenodo deposit mode

Use a **manual Zenodo upload** for this research record.

The `research-v1` GitHub release already exists, while Zenodo's GitHub
integration is intended to ingest releases after a repository is enabled. The
research object is also primarily a reproducibility dataset/evidence bundle,
with code included as supporting material.

## Zenodo metadata

Recommended values:

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
> instability. The archive includes normalized evidence, deterministic RQ1–RQ4
> analysis inputs/outputs, generated paper figures/tables, provenance, exact
> environment identities, and permitted materialized study inputs.
> Third-party compiled loader binaries whose complete redistribution notice set
> was not established are excluded and represented by hashes, source revisions,
> validation-contract identities, notices, and rebuild provenance. This release
> is a reproducibility archive of pilot evidence and is not a claim of peer
> review, population representativeness, institutional approval, or
> endorsement.

## DOI handling

For the Zenodo DOI field:

1. choose **No** for "Do you already have a DOI for this upload?";
2. use **Get a DOI now** if the exact version DOI is needed before publication;
3. do not add the reserved/minted DOI to the frozen `research-v1` release;
4. after publication, record both:
   - the **Version DOI** for exact `research-v1` citation;
   - the **Concept DOI** for the evolving dataset family.

For reproducibility claims and the v1 manuscript, prefer the **Version DOI**.

## Mixed-license note

The archive contains BPFCompat-owned Apache-2.0 material and permitted
third-party-derived MIT material. File-level provenance, redistribution status,
and retained notice paths in `archive-manifest.json` are authoritative.

The compiled cilium/ebpf project-loader binary and Falco `scap-open` binary are
not present in the DOI payload.

## After Zenodo publication

Create a new post-release repository PR, without rewriting the `research-v1`
tag or GitHub release, that:

1. records the Zenodo record URL, Version DOI, and Concept DOI;
2. adds the Version DOI to `CITATION.cff`;
3. adds DOI links to the repository README and research-facing documentation;
4. records that the Zenodo/DOI archival gate is complete;
5. leaves the GitHub release asset hashes unchanged.

## Frozen-v1 note

The `research/**` tree is part of the archived v1 payload. Post-release
bookkeeping should therefore remain outside that frozen payload unless a new
research version and archive lock are intentionally created.
