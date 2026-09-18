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
- [ ] Complete license/redistribution review for every materialized binary and
      archived external artifact.
- [x] Capture immutable generated-artifact and loader-binary identities for the
      frozen v1 selection. The identity lock is committed and enforced by CI.
      OCI identities remain deferred with Inspektor Gadget rather than being
      retrofitted into v1.
- [x] Mark existing observations as exploratory versus newly collected evidence.

## Phase 3 — Reproducible study

- [ ] Implement one command/script that normalizes captured BPFCompat reports.
- [ ] Generate every paper table and figure from normalized data.
- [ ] Add repeat-run checks for a representative sample.
- [ ] Document compute, KVM, image, registry, and network prerequisites.
- [ ] Publish raw/processed dataset checksums.

## Phase 4 — Archival

- [ ] Create a research-tagged release after the corpus and protocol are frozen.
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
