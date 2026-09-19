# BPFCompat Research Dataset v1 — Zenodo archival record

This document records the **post-release** DOI state for the frozen
BPFCompat `research-v1` dataset. It intentionally lives outside
`research/**` so the published v1 archive payload and committed archive lock
remain unchanged.

## Published identifiers

- GitHub tag: `research-v1`
- tag type: annotated tag
- tag target commit:
  `141c491bd1508600338e7bc27abbc5a117eb7508`
- GitHub release: **BPFCompat Research Dataset v1**
- GitHub release ID: `392145710`
- GitHub release publication time: `2026-09-19T16:58:52Z`
- Zenodo record: `https://zenodo.org/records/22848155`
- **Version DOI:** `10.5281/zenodo.22848155`
- **Concept DOI:** `10.5281/zenodo.22848154`
- Zenodo resource type: Dataset
- Zenodo version: `research-v1`
- Zenodo publication date: `2026-09-19`
- visibility: Public
- licenses: Apache-2.0 and MIT

Use the **Version DOI** when citing or reproducing the exact pilot-v1 evidence.
Use the **Concept DOI** only when referring to the evolving BPFCompat research
dataset family across versions.

## Frozen release assets

The DOI record contains the same four files published by the GitHub
`research-v1` release.

| File | Size | Canonical SHA-256 |
| --- | ---: | --- |
| `archive-manifest.json` | 458,992 B | `6ed6d38d57db57e75964829278a62c7bb4a12cd8fc5db97baebb05a1fdd5e927` |
| `archive-lock.json` | 1,506 B | `44e0ebe3d32c2c388002a4f44e5d0bf9a476a20ee702c137471a6be89235ddf3` |
| `bpfcompat-research-v1-payload.zip` | 12,899,271 B | `143a8e8a93e43aebbacfd73465a659ca4cb055db7a576960c9d50ed9bc90a817` |
| `RELEASE-CHECKSUMS.txt` | 272 B | `bc96087d78bdd8419189b2e51927f3e5c2908dad81155313663af3f29125fdd9` |

### Integrity evidence

Before the Zenodo upload, all four downloaded GitHub release assets were
re-hashed locally with SHA-256 and matched the canonical values above.

After publication, the Zenodo record displayed the expected file sizes and the
following MD5 values. Those MD5 values were independently reproduced from the
canonical GitHub archival artifact:

| File | Canonical / Zenodo MD5 |
| --- | --- |
| `archive-manifest.json` | `83c5dced82021323deace2943ff00c72` |
| `archive-lock.json` | `af401a0eab7cbbe62281c412ceef0261` |
| `bpfcompat-research-v1-payload.zip` | `ea79cefe6d4a9c2f88448e786bf8dc3d` |
| `RELEASE-CHECKSUMS.txt` | `f42f8fd12ef2acc398da0e6f0a53368b` |

A strict post-publication Zenodo re-download followed by SHA-256 recomputation
was not completed in the assistant environment because direct Zenodo file
downloads were unavailable there. DOI finalization therefore proceeded with
explicit maintainer acceptance of the stronger pre-upload SHA-256 check plus
the post-publication exact-size and matching-MD5 evidence above. A later
independent Zenodo re-download may strengthen the audit trail without changing
the published v1 record.

## Zenodo metadata

- **Resource type:** Dataset
- **Title:** BPFCompat Research Dataset v1: Empirical eBPF Compatibility Across Linux Vendor Kernels
- **Creator:** Eren Arı
- **Publication date:** 2026-09-19
- **Version:** `research-v1`
- **Language:** English
- **Publisher:** Zenodo
- **Repository URL:** `https://github.com/Kernel-Guard/bpfcompat`
- **Alternate identifier:** `https://github.com/Kernel-Guard/bpfcompat/releases/tag/research-v1`
- **Programming languages:** Go, Python
- **Development status:** Active
- **Keywords:** eBPF, BPF, Linux kernel, compatibility, vendor kernels, libbpf,
  BTF, CO-RE, reproducibility, systems research

The Zenodo description intentionally bounds the evidence: the release is a
reproducibility archive of pilot evidence and is not a claim of peer review,
population representativeness, institutional approval, or endorsement.

## Citation

For exact `research-v1` reproducibility, cite:

> Arı, E. (2026). *BPFCompat Research Dataset v1: Empirical eBPF Compatibility
> Across Linux Vendor Kernels* (Version research-v1) [Dataset]. Zenodo.
> https://doi.org/10.5281/zenodo.22848155

The repository `CITATION.cff` keeps BPFCompat itself typed as **software** and
lists this Zenodo object separately as a **dataset** reference. This prevents
the dataset DOI from being misrepresented as the software project's own DOI.

## No-mutation policy

The GitHub API does not mark the release object itself immutable. Project policy
for v1 is therefore **no mutation**: corrections must produce a new research
version instead of replacing published v1 evidence.

The `research/**` tree is part of the archived v1 payload. Post-release DOI
bookkeeping must remain outside that frozen payload unless a new research
version and archive lock are intentionally created.

The `research-v1` tag, GitHub release assets, archive lock, and Zenodo record
must not be rewritten as part of DOI metadata maintenance.
