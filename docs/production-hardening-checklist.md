# Production Hardening Checklist

Production-safe runtime loading and production multi-tenant SaaS require the separate gate in `docs/production-runtime-saas-gate.md` to pass. This checklist tracks operational hardening, but it is not by itself a production sign-off.

## Runtime and Isolation

- [x] Host execution (`runtime execute --allow-host-load`) disabled by default in automation contexts.
- [x] API runtime execute route disabled by default (`BPFCOMPAT_API_ENABLE_RUNTIME_EXECUTE=false`) on public demos.
- [ ] Runtime execute is performed by isolated workers/agents, not the public API process.
- [x] Runtime loading kill-switch is implemented and tested (`BPFCOMPAT_API_RUNTIME_EXECUTE_KILL_SWITCH` + API security test).
- [x] VM runner remains default execution path.
- [x] Resource bounds (CPU/RAM and per-target timeout) are enforced by profiles and workflows.

## Registry and Signing

- [ ] Daily `history verify` scheduled.
- [ ] Signing mode reviewed:
  - `local` for development only.
  - `external-cmd` for production key-management integration.
- [ ] External signer health monitored when enabled.
- [ ] KMS/HSM-backed signer integration and key rotation tested before production claims.
- [x] Build provenance generated for `bpfcompat` and validator binaries before
  production claims (`actions/attest-build-provenance` on tag releases; see
  `docs/verifying-releases.md`).
- [ ] Registry auth secret rotated on schedule (`make azure-rotate-registry-secret` when using Azure Key Vault).
- [ ] Artifact storage is private and versioned (`make azure-provision-foundation` storage account baseline).

## Cloud Operations Baseline

- [x] VM managed identity enabled and least-privilege roles applied.
- [x] Monitoring baseline configured (Log Analytics + diagnostics + CPU alert; action group is optional when `AZ_ALERT_EMAIL` is set).
- [x] Azure cloud-boundary proof command exists (`make azure-production-boundary-proof`).
- [ ] TLS endpoint configured for API/UI (`make azure-configure-tls`) when exposed publicly.
- [ ] POST API key or identity auth enforced for control-plane write actions.
- [ ] Identity-backed tenant auth replaces shared demo API key before production SaaS claims.
- [ ] Cross-tenant read/write isolation tests pass before production SaaS claims.

## Evidence and Stability

- [ ] `make beta-tech-check` executed regularly.
- [ ] `scripts/tech-stability-report.sh` shows consecutive ready reports.
- [ ] OSS validation reports refreshed on release cadence.
- [x] Primary production-smoke VM image uses an immutable URL and pinned SHA-256.
- [x] Command-mode reports identify exact loader bytes.

## Change Management

- [ ] Upgrade playbook executed before promotion.
- [ ] Rollback procedure tested in staging.
- [ ] Production-tech gate report archived per release candidate.
- [x] Release metadata consistency is checked in required CI.
- [x] Candidate binary positive and classified-negative VM tests gate publication.
- [x] Release binary, container, checksums, SBOM, signatures, and attestations share one promotion graph.
