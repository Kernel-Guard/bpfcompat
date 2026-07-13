# Roadmap

This roadmap describes intended outcomes, not guaranteed dates. Priorities may
change in response to security findings, kernel releases, adopter evidence, and
maintainer capacity. Work is tracked through public issues and pull requests.

## Current: v0.3.x stabilization

- stabilize command-mode execution of real project loaders;
- keep the quirk-library and vendor-kernel evidence fresh;
- improve failure classification and actionable reports;
- close documentation and usability gaps discovered by external evaluations;
- validate release, SBOM, signature, and provenance workflows; and
- establish the governance, adoption, and funding records needed for
  sustainable maintenance.

## Next: v0.4 — adopter-ready CI

- complete at least one upstream project integration using its actual loader;
- make GitHub Action setup, caching, image prefetch, and evidence retention
  easier for external repositories;
- add repeatable native ARM64 execution when suitable infrastructure is
  available;
- document report-schema compatibility and deprecation rules;
- improve profile provenance and stale-image detection; and
- publish an end-to-end adopter guide based on real CI use.

## Later: v0.5 — ecosystem scale

- expand project compatibility suites without encoding project-specific logic
  into the generic validator;
- add evidence-backed coverage where adopters need additional vendor kernels or
  architectures;
- reduce matrix runtime and storage cost without weakening isolation;
- improve historical comparison and regression triage; and
- grow review and release capacity beyond a single maintainer.

## 1.0 readiness criteria

bpfcompat will not declare 1.0 based only on feature count. The project should
first demonstrate:

- stable CLI, GitHub Action, report schema, and library compatibility policies;
- reproducible validation across maintained kernel profiles;
- multiple independent projects using or evaluating their real loader paths,
  including at least one publicly confirmed CI or release-gating adopter;
- documented upgrade, support, security, governance, and release processes;
- reliable signed multi-architecture releases with SBOM and provenance; and
- no known critical design blocker in the supported CI-validation boundary.

## Candidate work

Candidate work is intentionally not a commitment. It includes additional vendor
profiles, stronger native ARM64 coverage, more loader-framework recipes,
upstream-kernel boundary sweeps, evidence-query tooling, and library hardening.
An issue should establish user demand and technical scope before implementation.

## Non-goals

- replacing CO-RE, BTFHub, libbpf, or project-specific loaders;
- claiming support from static kernel-version inference alone;
- becoming a privileged production runtime loader; or
- treating the experimental web/API surface as a production multi-tenant SaaS
  before its security and operational gates are independently satisfied.

## How work is prioritized

Maintainers weigh security impact, reproducible user evidence, ecosystem reach,
maintenance cost, and alignment with the project's CI compatibility boundary.
Sponsorship can fund work already aligned with these principles but cannot buy a
particular verdict or bypass public technical review. See
[FUNDING.md](FUNDING.md) and [GOVERNANCE.md](GOVERNANCE.md).
