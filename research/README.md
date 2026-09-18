# BPFCompat Research

This directory defines the research-facing protocol for studying eBPF
compatibility with BPFCompat. It is intentionally separate from product and CI
documentation.

**Status:** protocol and reproducibility scaffold. It is not a peer-reviewed
publication and does not claim that the proposed study has been completed.

Existing BPFCompat case studies motivated the questions below. Those existing
observations must not be represented as prospectively preregistered evidence.
The study dataset should be frozen and versioned before confirmatory analysis.

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
