# Preprint submission checklist — pilot v1

This checklist applies to
[`PREPRINT-v1.md`](PREPRINT-v1.md). The frozen research dataset and
`research-v1` release must not be modified as part of manuscript editing.

## Manuscript state

- [x] Title is evidence-bounded and matches the frozen pilot.
- [x] Abstract reports only frozen generated results.
- [x] RQ1–RQ4 results are derived from committed deterministic analysis.
- [x] Calibration results are separated from non-calibration results.
- [x] Oracle environment mismatch remains inconclusive.
- [x] Cilium loader paths are explicitly marked contract-incomparable.
- [x] Repeat-run result is described as a bounded stability sample.
- [x] Threats to validity prohibit population-wide generalization.
- [x] Exact Version DOI is included for reproducibility.
- [x] Concept DOI is not used as the exact-study citation.
- [x] GitHub `research-v1` release is linked.
- [x] Generated figures/tables are referenced from the frozen archive tree.
- [x] Bibliography file exists at `references.bib`.

## Frozen identifiers

- dataset Version DOI: `10.5281/zenodo.22848155`
- dataset Concept DOI: `10.5281/zenodo.22848154`
- GitHub research tag: `research-v1`
- frozen tag target:
  `141c491bd1508600338e7bc27abbc5a117eb7508`
- canonical collection run: `35393833464`
- canonical repeat run: `35445834557`

## Before external submission

- [ ] Confirm author display name and affiliation exactly as they should appear.
- [ ] Add ORCID only if verified by the author.
- [x] Convert the Markdown manuscript into an arXiv-oriented LaTeX/PDF source package.
- [x] Bind the three frozen SVG figures by SHA-256 and convert them to PDF at build time without altering the empirical data.
- [ ] Confirm every bibliography entry against its primary publisher/source.
- [ ] Run spelling/grammar and reference-link checks.
- [x] Render the LaTeX PDF locally and visually inspect the title page, tables, figures, and references.
- [x] Confirm that the final PDF cites the exact Version DOI.
- [ ] Record the CI-built PDF and arXiv source-package SHA-256 values immediately before external submission.

## Submission-format package

The maintained arXiv-oriented source now lives under `docs/paper/latex/`.
`build.sh` verifies the frozen figure hashes, converts the exact SVG assets to
PDF, compiles the manuscript with pdfLaTeX, rejects unresolved references or
overfull boxes, and produces a minimal upload tarball.

The repository CI workflow `.github/workflows/preprint-v1.yml` independently
builds the PDF and source package and publishes them as a temporary workflow
artifact for review.

## Suggested preprint classification

For arXiv-style submission, the manuscript is primarily an operating-systems
artifact/compatibility study. A likely primary category is **cs.OS**. Any
secondary category should be chosen only if the final manuscript emphasis
supports it.

Do not claim peer review, acceptance, endorsement, or institutional approval
before such evidence exists.

## After a preprint identifier exists

Create a post-publication PR outside the frozen `research/**` payload that:

1. records the preprint URL/identifier;
2. links the preprint from the repository README;
3. adds the preprint as a related work in the Zenodo record if desired;
4. preserves the exact dataset Version DOI and frozen release hashes; and
5. distinguishes “preprint” from any later peer-reviewed publication.
