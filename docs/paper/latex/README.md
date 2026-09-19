# Pilot v1 LaTeX / arXiv package

This directory contains the submission-format source for the BPFCompat pilot-v1
preprint. It is intentionally outside `research/**`, because the archived
`research-v1` evidence payload is frozen.

## Build

Required local tools:

- `pdflatex`
- `inkscape`
- `sha256sum`
- `tar`

From the repository root:

```bash
bash docs/paper/latex/build.sh
```

Outputs are written to `docs/paper/latex/build/`:

- `bpfcompat-preprint-v1.pdf` — rendered review PDF;
- `bpfcompat-arxiv-v1.tar.gz` — minimal source package for upload;
- `preprint-v1-SHA256SUMS.txt` — source/figure/package checksums.

The arXiv package contains only:

```text
main.tex
figures/figure-1.pdf
figures/figure-2.pdf
figures/figure-3.pdf
```

The bibliography is embedded in `main.tex`, so no BibTeX/Biber step is
required.

## Frozen figure binding

The build fails unless the three source SVGs still match the SHA-256 values in
the frozen pilot-v1 paper asset manifest. It then converts those exact SVGs to
PDF for pdfLaTeX.

Ubuntu 24.04 currently ships Inkscape 1.2, which can omit SVG2
`<use href="#...">` instances during PDF conversion. The build therefore
creates a temporary conversion-only copy that rewrites that SVG presentation
syntax to the equivalent `xlink:href` form. The frozen source SVGs remain
untouched and hash-verified; Figure 3 also requires all 70 matrix-cell
`<use>` instances to survive this normalization.

The manuscript cites the exact dataset Version DOI:

`10.5281/zenodo.22848155`

Do not replace it with the Concept DOI when referring to the exact evidence used
by this manuscript.

## Evidence boundary

The LaTeX package is publication formatting, not a new dataset version. Editing
this directory must not change:

- `research/**`;
- the `research-v1` tag or GitHub release;
- the Zenodo dataset files;
- archive locks or frozen generated analysis.

If an empirical claim changes, create a new research dataset version rather than
silently updating pilot-v1 evidence.
