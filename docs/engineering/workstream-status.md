# Workstream status and approval ledger

A coordination aid, **not release evidence**. GitHub checks, workflow runs,
signed provenance and readiness attestations are authoritative. Rows change
only when real evidence exists. Times are UTC.

Last updated: 2026-10-13T19:40Z (`main` = `f29c093`).

## Task board

| ID | Owner | Branch | Depends on | Status | Latest tested commit | Hosted CI | Evidence | Approval | Next action |
|---|---|---|---|---|---|---|---|---|---|
| V038-E1 | release-v038 | `release/v0.3.8-stable` | time ≥ 2026-10-14T09:20Z | BLOCKED (time) | `0b45a4c` (PR #176) | n/a | E0 [38373171801](https://github.com/Kernel-Guard/bpfcompat/actions/runs/38373171801) | YELLOW (granted once, unused) | Preflight, then the single E1 dispatch once eligible |
| V038-NOTE | release-v038 | `release/v0.3.8-stable` | V038-E1 | BACKLOG | – | – | – | RED (operator signs) | Draft an unsigned operator note after E1 |
| V040-GATE | lead | `fix/canary-pin-rc-bootstrap` (#189) | – | REVIEW | `0acdfcf` | 12/12 | review of `f00a7f3`: no blockers, one should-fix (fixed in `0acdfcf`); delta review pending | YELLOW (renewal for `0acdfcf`) | Operator approval of `0acdfcf` |
| ENG-ORCH | lead | `eng/orchestration-workstreams` (#190) | – | REVIEW | see #190 | see #190 | agent frontmatter validated; docs drift OK | operator review | Review #190 |
| V040-BUMP | release-v040 | `release/v0.4.0-rc.4-bump` | V040-GATE merged | BACKLOG | – | – | – | YELLOW (merge), then RED (tag) | Open the bump PR from the new `main` |
| V040-DESIGNATE | release-v040 | `release/v0.4.0-rc.4-designate` | rc.4 published and verified | BACKLOG | – | – | – | YELLOW | Prepare as a draft only |
| KVM-185 | kernel-vm | `fix/centos-sweep-signed-archive` (#185) | upstream CentOS metalink | BLOCKED (upstream) | `3dc44be` | 12/12 | LOCAL: key and RPM signatures OK; boot not proven | YELLOW (merge) | Retry the boots when the metalink is consistent; compose option needs security review |
| UPS-AUDIT | upstream-integrations | – | v0.3.8 stable for repins | DONE (audit 2026-10-13) | – | – | IG run 38211130316; Falco run 38211321294 | RED (open upstream PRs) | Draft the IG repin after v0.3.8 stable is verified |

## Operator approval ledger

| Date | Action | Exact scope / commit | Level | Status |
|---|---|---|---|---|
| 2026-10-13 | v0.3.8 rollback drill | one run, alias `rollback-drill-v0.3.8-rc.2`, policy restored | RED | Used: run 38379940827, success |
| 2026-10-13 | v0.3.8 E1 dispatch | exactly once, ≥ 2026-10-14T09:20Z, candidate `v0.3.8-rc.2` / `baa57a76…` / image `046effcf…` | YELLOW | **Granted, unused** |
| 2026-10-13 | Merge #184 (campaign binding) | `d9a058e`, renewed for `b8259b4` | YELLOW | Used: merged as `f29c093` |
| 2026-10-13 | Ubuntu 24.04 campaign runner | focused PR | YELLOW | Used: #188, merged as `46bb261` |
| 2026-10-13 | Merge #189 | `f00a7f3` only | YELLOW | **Lapsed, unused**: the review found the tag build's quality gate lacked `GH_TOKEN`; fixed in `0acdfcf`. Renewal needed. |
| – | v0.3.8 operator note, merge #176, v0.3.8 tag, stable promotion | – | RED | Not granted |
| – | v0.4.0-rc.4 tag, publication, designation | – | RED | Not granted |

## E1 procedure (V038-E1)

Earliest dispatch: **2026-10-14T09:20Z**. Run `date -u` first.
E0 (run 38373171801) completed at 2026-10-13T09:07:57Z. The 24-hour floor is
2026-10-14T09:07:57Z.

Preflight, repeated immediately before dispatch:
1. The tag `v0.3.8-rc.2` peels to `baa57a764d4d5071b7dd9ff255d9c6d81ec2b65d`.
2. The release assets verify: checksums, per-asset release-workflow attestations bound to the commit and tag, and cosign signatures on `SHA256SUMS` and the SBOM.
3. The candidate evidence `f7628a0e…` attestation and bindings verify.
4. The image `sha256:046effcfe3575c89663cc925042278e0da0804afe4199fff1abf9e13fea26f1d` has a valid signature and SLSA provenance, and reports `v0.3.8-rc.2`/`baa57a7`.
5. The E0 producer attestation verifies (`maintenance-evidence.yml`, run 38373171801/1), with evidence sha256 `40069e56…` equal to `docs/releases/v0.3.8-evidence/e0.json` on #176.
6. GHCR `latest` and the candidate alias are unchanged.

Dispatch, once:

```bash
gh workflow run maintenance-evidence.yml --repo Kernel-Guard/bpfcompat --ref v0.3.8-rc.2 \
  -f milestone=e1 \
  -f expected_commit=baa57a764d4d5071b7dd9ff255d9c6d81ec2b65d \
  -f expected_image_digest=sha256:046effcfe3575c89663cc925042278e0da0804afe4199fff1abf9e13fea26f1d
```

Afterwards:
1. Every job must succeed.
2. Verify the producer attestation: invocation is this run/attempt, source digest `baa57a7…`, source ref `refs/tags/v0.3.8-rc.2`.
3. Check `started_at` ≥ 2026-10-14T09:07:57Z, the VM gate (exact kernel 725) and the container, clean-install and Action canaries.
4. Copy the evidence byte-for-byte to `docs/releases/v0.3.8-evidence/e1.json` as `observations[1]`.
5. Re-run readiness on #176.

A failed or cancelled E1 is reported; it is **not** retried without a new authorization.
