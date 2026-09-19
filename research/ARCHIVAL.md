# Pilot v1 archival and DOI policy

This document defines the release boundary for the first citable BPFCompat
research archive. It is an engineering reproducibility policy, not legal advice.

## Current canonical evidence

- canonical pilot workflow run: `35393833464`
- canonical source commit: `5de550e5cc8c659872a90fc262eb0250c229bf23`
- canonical Actions artifact: `10566859006`
- canonical artifact SHA-256:
  `7aae7b5c099739ef0bcad74fbb3731aaafb1177f1ba128020729b08803610910`
- planned/observed executions: **70/70**
- repository dataset: `research/data/v1/`
- deterministic analysis: `research/analysis/v1/`
- canonical repeat workflow run: `35445834557`
- repeat source commit: `d2a78e05178ea6dd82ead9684f5eedf49066903f`
- repeat Actions artifact: `10584409793`
- repeat artifact SHA-256:
  `895fd41dae147c592d5cdec91bbd99150f9dd14c35afadf72bc14954a192a0e5`
- repeat stability: **21/21** stable on the same exact environment,
  **0** environment drift, **0** same-environment verdict instability
- repeat repository snapshot: `research/repeat/v1/`

## Archive layers

The scholarly archive should be separable into three layers.

### 1. Repository snapshot

Include the exact tagged source tree used for the study, including:

- research protocol and corpus metadata;
- `research/data/v1/`;
- `research/analysis/v1/`;
- repeat-run results once collected and committed;
- all research scripts required to regenerate normalized analysis;
- `CITATION.cff`, license files, provenance, checksums, and this archival policy.

### 2. Canonical execution evidence

Preserve the raw evidence from the canonical successful workflow, including
raw BPFCompat reports and execution provenance. The archive must bind every
archived file to checksums already recorded in the repository dataset or to an
additional archival manifest generated before release.

The finite-retention GitHub Actions artifact is staging evidence, not the
durable scholarly archive.

### 3. Materialized study inputs

Do **not** blindly publish the complete materialization bundle.

The DOI package may include BPFCompat-owned binaries/objects and redistributable
third-party-derived material only when the required notices are packaged with
it. Third-party compiled loader binaries with unresolved transitive notice
requirements must be represented by:

- exact SHA-256;
- exact source revision;
- deterministic build recipe;
- validation-contract identity;
- upstream license/notice material and retained archive paths.

This keeps the study reproducible without making an unsupported redistribution
claim.

For the final machine-readable archival manifest, plain `include` is reserved
for BPFCompat-owned provenance. Third-party-derived rows must use
`include-with-notice` or `exclude-rebuildable`; the validator must reject a
third-party-derived row marked plain `include`. Every
`include-with-notice` row must name retained license/notice paths that exist in
the archive.

## v1 inclusion policy

| Item | DOI archive policy | Reason |
| --- | --- | --- |
| BPFCompat source, manifests, scripts, dataset, analysis | Include | Apache-2.0 repository material |
| BPFCompat v0.3.7 CLI and static validator | Include with BPFCompat license | Published BPFCompat release assets |
| BPFCompat controlled-probe `.bpf.o` files | Include with BPFCompat license | Built from BPFCompat-owned Apache-2.0 sources |
| Cilium-derived tracepoint source/object | Include only with pinned Cilium MIT notice and modification provenance | Upstream repository is MIT; the BPF program's `Dual MIT/GPL` runtime license marker is not a substitute for source-license attribution |
| custom cilium/ebpf Go loader binary | Exclude from v1 DOI bundle unless all binary-distribution notices are packaged | Binary includes external Go/cilium dependencies; reproducibility is preserved by source revision, dependency version, hash, and rebuild recipe |
| Falco `scap-open` binary | Exclude from v1 DOI bundle unless a complete transitive dependency/notice audit is finished | Built with `USE_BUNDLED_DEPS=ON`; Falco Apache-2.0 license and NOTICES are necessary but do not by themselves establish every bundled dependency obligation |
| VM/base images | Do not redistribute in the DOI bundle | Preserve exact image identities, source locations, and observed environment evidence instead |

## Generated archive bundle

The v1 archive builder is `scripts/research/archive-v1.py`, driven by
`research/archive/v1/archive-plan.json`.

It produces a release-shaped bundle containing:

- `archive-manifest.json` — one machine-readable row for every payload file;
- `archive-lock.json` — compact binding for the full manifest, payload ZIP,
  source Actions artifacts, and excluded rebuildable binaries;
- `bpfcompat-research-v1-payload.zip` — deterministic payload ZIP;
- `RELEASE-CHECKSUMS.txt` — release-level SHA-256 bindings.

The full manifest is generated deterministically in CI rather than duplicated
into Git history. The committed `research/archive/v1/archive-lock.json` is the
repository gate: CI regenerates the complete archive from the three pinned
Actions artifacts and requires the generated lock to match byte-for-byte.

The payload contains canonical pilot/repeat evidence, the research
reproducibility slice, and permitted materialized inputs. The compiled
cilium/ebpf loader and Falco `scap-open` remain physically absent and are
represented only by `exclude-rebuildable` identity/contract records.

## Published research release

The immutable research publication point for pilot v1 is:

- annotated tag: `research-v1`
- tag target commit:
  `141c491bd1508600338e7bc27abbc5a117eb7508`
- GitHub release: **BPFCompat Research Dataset v1**
- GitHub release ID: `392145710`
- published: `2026-09-19T16:58:52Z`

Published assets and GitHub-reported SHA-256 digests:

| Asset | Size | SHA-256 |
| --- | ---: | --- |
| `archive-manifest.json` | 458,992 B | `6ed6d38d57db57e75964829278a62c7bb4a12cd8fc5db97baebb05a1fdd5e927` |
| `archive-lock.json` | 1,506 B | `44e0ebe3d32c2c388002a4f44e5d0bf9a476a20ee702c137471a6be89235ddf3` |
| `bpfcompat-research-v1-payload.zip` | 12,899,271 B | `143a8e8a93e43aebbacfd73465a659ca4cb055db7a576960c9d50ed9bc90a817` |
| `RELEASE-CHECKSUMS.txt` | 272 B | `bc96087d78bdd8419189b2e51927f3e5c2908dad81155313663af3f29125fdd9` |

The scholarly release workflow rebuilt the archive from the three pinned source
Actions artifacts, verified the committed archive lock, generated GitHub
provenance attestations for all four release files, created the annotated tag,
published the release, and then verified the final tag target and asset set.

The tag is annotated but not GPG-signed; integrity for the release assets is
provided by the committed archive lock, release checksums, GitHub-reported asset
digests, and GitHub build-provenance attestations.

## Release gates

A research-tagged release and DOI should not be created until all of the
following are true:

1. the manual repeat-run stability sample has executed successfully and its
   normalized results/provenance are committed;
2. final paper tables/figures are generated deterministically from committed
   normalized data;
3. the archival file manifest and SHA-256 list are generated and verified;
4. every included third-party-derived file has the required license/notice
   material, otherwise it is excluded and represented by provenance/hash;
5. the release tag resolves to the exact source/data state used by the
   manuscript;
6. the DOI is minted only after the archive is immutable enough to cite.

After the DOI exists, add it to `CITATION.cff`, the research README, and the
repository README. Do not add a placeholder DOI.

## External-reference claims

Academic visibility claims must remain evidence-backed:

- **referenced by**: an independently maintained university/lab/course resource
  links to BPFCompat;
- **cited by**: a scholarly work includes a formal citation;
- **used by**: there is public evidence of actual use;
- **endorsed by**: use only when the institution or named person explicitly
  provides an endorsement.

A university resource-page link must never be described as approval,
certification, or endorsement.
