# Production Support Boundary

## Status

The production candidate is the CI compatibility product:

- `bpfcompat test` and `bpfcompat suite`
- the GitHub Action
- artifact and command-mode validation inside disposable QEMU/KVM guests
- supported vendor-kernel profiles, matrices, JSON reports, Markdown reports,
  and stable classification codes

This boundary is ready for a production claim only after the release and
operational gates below have current passing evidence. Until then, call it a
production candidate.

## Excluded Surfaces

The following remain experimental and are not covered by the production
support claim:

- `bpfcompat serve` and the HTTP/Web UI surface
- cloud registry and multi-tenant behavior
- runtime probe, selection, fetch, and execute
- the host-loading library build tag
- the agent and its host load, rollback, and unload paths
- Firecracker and `virtme-ng` backends

Host loading and multi-tenant SaaS have their own fail-closed gate in
[production-runtime-saas-gate.md](production-runtime-saas-gate.md). They do
not graduate when the CI product graduates.

## Security Scan Scope

The production claim applies only to the supported boundary above. The
full-repository `gosec` baseline still contains findings in the excluded API,
agent, cloud-registry, and Firecracker code. Those findings are not accepted
for a future graduation of those surfaces; they remain blocked behind the
experimental freeze and must be resolved or explicitly risk-reviewed before
that separate gate can pass.

Required CI runs `gosec` through `golangci-lint` on production-boundary
changes. A full-repository scan is retained as audit evidence, but it is not
evidence that the excluded surfaces are production-ready.

The CodeQL workflow also runs `scripts/check-production-code-scanning.sh`
after analysis. It fails the required `Analyze (Go)` check when an open alert
lands in a supported CLI, report, runner, or QEMU path. Firecracker and
`virtme-ng` stay outside that path gate because they remain explicitly
excluded; alerts in any excluded surface still require a recorded risk review
and do not provide evidence that the surface is production-ready.

## Compatibility Claim

A passing result means the recorded artifact or command loader completed the
requested load, attach, or behavior contract on the exact guest image bytes
recorded in that report. Command-mode reports record the invocation digest and
the loader binary's name, size, and SHA-256. Artifact-mode reports record the
same identity fields for the staged libbpf validator.

A pass is not a certification of:

- every host with a similar kernel version
- different kernel configuration, BTF, LSM, lockdown, capability, or
  architecture settings
- application behavior not exercised by the manifest or loader command
- complete Falco detection or rule-engine behavior

Required profiles fail closed on compatibility failures and infrastructure
errors. Optional profiles remain informational.

## Release Gate

Every supported release must:

1. pass unit, race, vet, vulnerability, generated-doc, and release-consistency
   checks;
2. build candidate binaries once and record their checksums;
3. run the exact candidate CLI and static validator in a pinned-image positive
   VM test;
4. produce the expected classification from an incompatible artifact;
5. execute the exact ARM64 CLI candidate on a native ARM64 runner;
6. build and version-check a candidate multi-architecture container;
7. bind the release inputs and VM results into an attested candidate-evidence
   record;
8. publish signed checksums, SBOM, and build provenance;
9. finish as a private draft without an automatic publication path;
10. receive a separate exact-input manual promotion dispatch through the
    15-minute `production-release` environment; and
11. re-verify the run, tag, commit, assets, attestations, signatures, channel,
    image digest, and version before making the draft release public.

The release metadata source is [`release.yaml`](../release.yaml). It records
the current stable version separately from the release candidate and its
channel. A prerelease may publish only its exact `X.Y.Z-rc.N` image tag; only a
stable release may update `X.Y`, `latest`, or the installer's default version.
Git tags and image digests remain post-build identities.

## Operational Gate

Before the first production claim:

- four chronological, unique, scheduled VM campaigns, each 6-8 days apart,
  must complete successfully;
- the campaign must meet the SLO in
  [production-slo-runbook.md](production-slo-runbook.md);
- the Falco upstream lane must complete on the expanded vendor-kernel matrix;
- rollback and incident ownership must be exercised; and
- the release operator must record a deliberate solo-promotion confirmation
  bound to the final evidence.

There is no separation of duties in `solo-maintainer` mode. The production
claim must not describe the operator confirmation as independent review.
Account compromise remains a residual release risk.

Confirmed adoption is an ecosystem-readiness requirement for 1.0, not a
substitute for these technical controls.

`scripts/production-readiness-report.sh` validates the campaign manifests,
report hashes, Falco profile coverage, attested release-candidate evidence,
manual/T+24h/T+72h canary evidence, rollback and fail-closed incident evidence,
and solo-operator promotion confirmation before producing the graduation
report.
