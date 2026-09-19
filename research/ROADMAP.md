# Academic Readiness Roadmap

## Phase 1 — Citation and protocol

- [x] Add `CITATION.cff`.
- [x] Define research questions and evidence rules.
- [x] Define prospective methodology and corpus metadata.
- [ ] Add maintainer ORCID only after the maintainer supplies or verifies it.
- [ ] Validate `CITATION.cff` with a CFF validator.

## Phase 2 — Frozen pilot corpus

- [x] Define explicit artifact/project inclusion criteria.
- [x] Freeze a versioned pilot artifact **selection** manifest; generated binary
      identities are captured before execution.
- [x] Freeze a versioned logical kernel-profile selection; exact environment
      identities are captured after boot as required by the corpus schema.
- [x] Record a v1 archival/redistribution policy and default exclusion rule for
      third-party compiled loader binaries whose transitive notice set is not
      fully established.
- [ ] Complete any transitive dependency/notice audit required for a
      third-party compiled binary that is ultimately included in the DOI bundle.
- [x] Capture immutable generated-artifact and loader-binary identities for the
      frozen v1 selection. The identity lock is committed and enforced by CI.
      OCI identities remain deferred with Inspektor Gadget rather than being
      retrofitted into v1.
- [x] Mark existing observations as exploratory versus newly collected evidence.

## Phase 3 — Reproducible study

- [x] Implement a versioned study runner and normalizer for captured BPFCompat reports.
- [x] Generate pilot v1 descriptive RQ1–RQ4 tables from normalized data.
- [ ] Generate every final paper table and figure from normalized data.
- [x] Define a bounded representative repeat-run protocol (PR #152).
- [x] Execute the 21-attempt repeat-run workflow from `main`, bind its
      provenance/results to the repository snapshot, and evaluate environment
      drift separately from same-environment verdict instability. Canonical run
      `35445834557`: 21/21 stable same-environment observations, 0 drift,
      0 verdict instability.
- [x] Document the v1 execution boundary, KVM/VM prerequisites, exact-environment identity, and collection completeness rules.
- [x] Publish raw/processed dataset checksums and bind the repository snapshot to
      the canonical successful workflow artifact.
- [x] Add a preprint working draft with claims constrained to generated v1 data.

## Phase 4 — Archival

- [x] Define the pilot v1 archival/DOI policy and third-party binary boundary.
- [ ] Generate and verify the final machine-readable archival manifest.
- [ ] Create a research-tagged release after repeat stability and final figures
      are frozen.
- [ ] Archive the release/dataset in a DOI-granting repository such as Zenodo.
- [ ] Add the DOI to `CITATION.cff` and the README only after it exists.
- [ ] Preserve exact code/data versions used for any manuscript.

## Phase 5 — External academic use

- [ ] Ask relevant eBPF/Linux research groups to evaluate or reuse the corpus,
      without requesting endorsement.
- [ ] Record public academic references only when independently verifiable.
- [ ] Distinguish "used by", "cited by", "referenced by", and "endorsed by".
- [ ] Prepare a software paper only after venue eligibility requirements are met.
- [ ] Prepare the empirical compatibility study as a separate research paper.

## Non-goals

- Adding university logos without permission.
- Calling a resource-page link an endorsement.
- Creating a DOI before there is a frozen artifact worth archiving.
- Treating existing exploratory case studies as prospectively preregistered.
