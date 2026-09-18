# BPFCompat Pilot Dataset v1

This is the repository snapshot of the first successful prospective
BPFCompat pilot collection: GitHub Actions run 35393833464 from commit
5de550e5cc8c659872a90fc262eb0250c229bf23.

The collection contains 70/70 planned execution records across seven
frozen cases and ten logical profiles: 50 compatible, 13 incompatible,
and 7 inconclusive. It is collection-complete but not fully evaluable
because the Oracle Linux profile requested 5.15 while the image booted
6.12 UEK. Those seven observations retain the exact environment and are
inconclusive for the requested logical profile.

The canonical executions.jsonl is stored losslessly as seven case-specific
JSONL shards under processed/executions. Concatenating them in analysis-plan
case order reproduces the canonical SHA-256 in dataset-manifest.json.

execution-provenance.json binds exact CLI, validator, loader, matrix,
profile-lock, and runner identities. raw-report-checksums.json freezes
each raw report path and SHA-256. The full successful Actions artifact is
bound by ID and digest in the manifest and is intended for the later DOI
archive rather than permanent duplication in Git.

This is a selected, stratified x86_64 pilot, not a representative sample
of Linux deployments. Calibration and controlled-probe denominator rules
are frozen in research/corpus/v1/artifacts.yaml. Corrections create a new
dataset version rather than editing v1 rows in place.
