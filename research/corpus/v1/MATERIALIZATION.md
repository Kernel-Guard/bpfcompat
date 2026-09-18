# Pilot v1 Materialization

The frozen selection in this directory is not executable research evidence until
its generated objects and project loaders have immutable identities.

The materialization path is:

```bash
bash scripts/research/materialize-v1.sh dist/research-corpus-v1
bash scripts/research/verify-materialization-v1.sh dist/research-corpus-v1
```

The canonical CI implementation is
`.github/workflows/research-materialize-v1.yml`. CI materializes the corpus twice
from clean scratch directories and compares the artifact and validation-contract
identity projection. Any byte-level drift in those identities fails the workflow.

## What the materializer does

It builds from the frozen source revisions, rather than from the moving checkout:

- BPFCompat-derived probes and the cilium/ebpf-derived example from
  `b8ef57f4e02ebecee4649f7657ea8eea6af46ca9`;
- Falco `scap-open` from
  `1800b330ce92b532456178abfcbfba3dd157f974`;
- the cilium/ebpf v0.22.0 Go loader from the frozen standalone module;
- BPFCompat v0.3.7 CLI and static validator from published release assets whose
  expected SHA-256 values are already frozen in
  `validation-contracts.yaml`.

It also records the build toolchain, source revisions, generated artifact
SHA-256 values, and canonical validation-contract hashes. The BPF compilation
uses fixed debug/source prefix mapping, the Go loader uses `-trimpath` and
`-buildvcs=false`, and the Falco build uses a stable scratch path plus
`SOURCE_DATE_EPOCH`/prefix mapping so the canonical CI can verify repeated
materialization.

## Canonical contract hashes

A validation contract ID is the SHA-256 of the canonical JSON payload **before**
the `id` field is added. Canonical payloads are serialized with sorted keys and
no insignificant whitespace using `jq -cS`.

This avoids the self-referential problem of hashing a record that contains its
own hash.

## Generated bundle

The workflow produces:

```text
research-corpus-v1/
├── artifacts/          # selected .bpf.o files
├── loaders/            # cilium/ebpf loader + Falco scap-open
├── bin/                # exact BPFCompat v0.3.7 CLI + validator
├── contracts/          # canonical contract payloads and records
├── inputs/manifests/   # frozen BPFCompat manifests used by later execution
├── licenses/           # project license/notice material retained with bundle
├── toolchain/          # compiler/build environment inventory
├── materialization.json
└── SHA256SUMS
```

The Actions artifact is a staging archive, not the final scholarly archive. It
currently has finite retention. After the materialized identities are reviewed,
the final dataset/release must be placed in a durable archival system before a
paper or DOI claims long-term reproducibility.

## Important boundary

Materialization does **not** execute the ten-kernel study matrix and does not
create compatibility results. It only creates and integrity-checks the exact
inputs that the execution phase will consume.

Inspektor Gadget remains deferred from frozen v1 as documented in
`deferred.yaml`.
