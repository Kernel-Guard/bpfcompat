# BPFCompat Research

This directory defines the research-facing protocol for studying eBPF
compatibility with BPFCompat. It is intentionally separate from product and CI
documentation.

**Status:** the prospective protocol is frozen and pilot corpus v1 has been
collected and published as a versioned repository dataset. This is not a
peer-reviewed publication, and the selected pilot must not be presented as a
representative study of Linux deployments.

Existing BPFCompat case studies motivated the questions below. Those earlier
observations remain exploratory rather than being relabeled as prospectively
collected evidence. Pilot v1 is tied to one canonical workflow run and immutable
checksums before descriptive RQ1–RQ4 analysis.

## Collected pilot v1

The canonical pilot collection is GitHub Actions run `35393833464` at commit
`5de550e5cc8c659872a90fc262eb0250c229bf23`. It produced all **70/70**
planned execution records: 50 compatible, 13 incompatible, and 7 inconclusive.
The collection is complete but not fully evaluable because the frozen Oracle
Linux logical profile requested kernel family 5.15 while the vendor image booted
6.12 UEK; those seven executions retain their exact observed environment and are
inconclusive for the requested profile.

Repository snapshot and integrity metadata:

- [`data/v1/`](data/v1/) — immutable processed dataset shards, provenance,
  raw-report checksums, and dataset manifest;
- [`analysis/v1/`](analysis/v1/) — deterministic descriptive RQ1–RQ4 tables
  and machine-readable analysis summary;
- `scripts/research/analyze-study-v1.py` — analysis generator;
- `scripts/research/test-analysis-v1.sh` — checksum and reproduction gate.

The full workflow artifact remains staging evidence for later DOI archival; its
artifact identity is recorded in the dataset manifest.

## Study objective

Measure how compiled eBPF artifacts and their real loader paths behave across
Linux vendor kernels, and quantify where simple compatibility assumptions
(kernel version, upstream feature introduction, or CO-RE availability) diverge
from observed load/attach behavior.

## Research questions

### RQ1 — How predictive is kernel version of observed eBPF compatibility?

Compare version-based feature expectations with observed results on real vendor
kernels. Backports and vendor rebases are first-class observations rather than
exceptions to discard.

### RQ2 — Why do otherwise portable eBPF artifacts fail?

Classify observed incompatibilities using evidence-backed failure categories,
including BTF/CO-RE relocation, map/program/attach support, verifier behavior,
kernel configuration, capabilities, architecture, and loader assumptions.
Infrastructure failures remain separate from compatibility failures.

### RQ3 — How much does the loader affect the compatibility verdict?

Where projects expose a reproducible loader path, compare generic artifact
validation with the project's actual loader. A generic libbpf result must not
be treated as equivalent to a project-specific loader result.

### RQ4 — How do vendor backports and patch-level updates change compatibility?

Track compatibility across distro families and, where reproducible, multiple
patch releases in the same logical kernel series. Preserve both logical profile
identity and exact execution-environment identity.

## Evidence rules

1. Every artifact must have immutable content identity (SHA-256 or resolved OCI
   digest) plus provenance.
2. Every environment must record distribution, distribution release,
   architecture, requested kernel family, and observed kernel release.
3. Every result must distinguish compatibility failure from infrastructure
   failure, timeout, missing evidence, and unsupported execution paths.
4. Project-specific loaders must record the exact binary identity, invocation,
   and success contract.
5. Results are append-only within a frozen dataset release. Corrections create a
   new dataset version and document the reason.
6. Conclusions must be reproducible from machine-readable evidence. Hand-edited
   summary tables are not primary evidence.
7. Negative results are retained. A kernel correctly rejecting an unsupported
   feature is evidence, not a broken experiment.
8. Thresholds, exclusion rules, and primary comparisons for a frozen study
   version are defined before confirmatory analysis.

## Planned outputs

- versioned artifact / loader / kernel corpus;
- raw BPFCompat reports and per-target evidence;
- normalized analysis dataset;
- failure taxonomy;
- reproducible figures and tables;
- a citable software release and archived research dataset;
- a research paper or technical report distinct from the software citation.

## Existing evidence

The repository already contains reproducible case studies and a curated
known-tricky-kernel library. They are useful pilot evidence and for designing
the study, but the research dataset should explicitly state which observations
are exploratory and which belong to a frozen confirmatory corpus.

Relevant starting points:

- `docs/kernel-quirk-library.md`
- `docs/case-study-enterprise-kernels.md`
- `docs/case-study-falco-modern-bpf.md`
- `docs/case-study-inspektor-gadget.md`
- `docs/command-validation.md`
- `docs/release-regression-diff.md`

See [METHODOLOGY.md](METHODOLOGY.md) for the proposed protocol and
[corpus/SCHEMA.md](corpus/SCHEMA.md) for dataset metadata.
