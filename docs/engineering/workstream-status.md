# Workstream status and approval ledger

A coordination aid, **not release evidence**. GitHub checks, workflow runs,
signed provenance and readiness attestations are authoritative. Rows change
only when real evidence exists. Times are UTC.

Last updated: 2026-10-14T14:44Z (`main` = `5e18f44`).

## Task board

| ID | Owner | Branch | Depends on | Status | Latest tested commit | Hosted CI | Evidence | Approval | Next action |
|---|---|---|---|---|---|---|---|---|---|
| V038-E1 | release-v038 | `release/v0.3.8-stable` | – | DONE | `7c185d5` (PR #176) | n/a | E1 [38575836529](https://github.com/Kernel-Guard/bpfcompat/actions/runs/38575836529)/1: 6/6 jobs, started 13:54:48Z (103,611 s after E0), exact kernel 725, canaries pass, producer attestation verified; `e1.json` sha256 `0d9bb96f…` | YELLOW (used once; never repeat) | – |
| V038-NOTE | release-v038 | `release/v0.3.8-stable` | V038-E1 | WAITING (operator) | `7c185d5` | 5/5 | readiness input hashes all match; real gate fails closed only on the absent operator block (a check-stripped simulation is not evidence); unsigned approval package prepared off-repo | RED (operator signs) | Operator writes `operator.md` and the readiness `operator` block |
| V038-STABLE | release-v038 | `release/v0.3.8-stable` (#176, draft) | V038-NOTE | BLOCKED (approval) | `7c185d5` | – | – | RED | Final GOs: merge #176, tag `v0.3.8`, promote |
| ENG-ORCH | lead | `eng/orchestration-workstreams` (#190) | – | MERGED | `2426c53` | 12/12 | merged as `ba585fe` (tree = `2426c53`) | YELLOW (used) | – |
| V040-CITOKEN | lead | `fix/ci-gh-token-release-tests` (#192) | – | MERGED | `83e3ab9` | 12/12 | merged as `5e18f44` (tree = `83e3ab9`); effective diff = reviewed `f21b6ff`; token-scope review: mergeable as-is | YELLOW (used, renewed head) | – |
| V040-RUNNERS | release-v040 | `ci/canary-runners-ubuntu-24.04` (#193, draft) | – | REVIEW | `e99d2e2` (update-branch of reviewed `c26fc43`) | 15/15 | effective diff = `c26fc43`; KVM shakeout consumer-canary [38582079253](https://github.com/Kernel-Guard/bpfcompat/actions/runs/38582079253): 3/3 jobs `ubuntu-24.04` with `/dev/kvm`, no TCG fallback (not qualification); delta review: mergeable as-is | YELLOW (renewal needed for `e99d2e2`) | Operator approval; must merge before the rc.4 tag |
| V040-BUMP | release-v040 | `release/v0.4.0-rc.4-bump` (#191, draft) | V040-RUNNERS | BLOCKED (#193) | `c649110` | integration [38577921814](https://github.com/Kernel-Guard/bpfcompat/actions/runs/38577921814) green | integration `c6a09fe`, tree `3aa2cde1…`; open: the CHANGELOG date (rc headings use the publication date) and whether the #188/#193 runner pins need an entry | YELLOW (merge), then RED (tag) | Rebase after #193 merges; exact-head approval |
| V040-DESIGNATE | release-v040 | `release/v0.4.0-rc.4-designate` | rc.4 published and verified | BACKLOG | – | – | template patch v2 (no `runs-on` hunks) prepared off-repo | YELLOW | Prepare as a draft only |
| KVM-185 | kernel-vm | `fix/centos-sweep-signed-archive` (#185, draft) | – | REVIEW | `cb83d4c` | 12/12 | enforcing `rpm --checksig --define '_pkgverify_level signature'`; LOCAL at `cb83d4c`: exact 729 and 731 COMPATIBLE, `centos`/`9`, `distro_match=true`, signed RPMs rc=0, unsigned rejected rc=1 on EL9 rpm 4.16; delta security review: mergeable as-is | YELLOW (merge) | Operator approval of the exact head (not on the rc.4 path) |
| UPS-AUDIT | upstream-integrations | – | v0.3.8 stable for repins | WAITING (v0.3.8 stable) | – | – | 2026-10-14: IG still pins v0.3.7 `179ff612`; repin draft prepared, unsent; Falco needs no change | RED (open upstream PRs) | Open the IG repin after v0.3.8 stable is verified, with approval |

## Operator approval ledger

| Date | Action | Exact scope / commit | Level | Status |
|---|---|---|---|---|
| 2026-10-13 | v0.3.8 rollback drill | one run, alias `rollback-drill-v0.3.8-rc.2`, policy restored | RED | Used: run 38379940827, success |
| 2026-10-13 | v0.3.8 E1 dispatch | exactly once, ≥ 2026-10-14T09:20Z, candidate `v0.3.8-rc.2` / `baa57a76…` / image `046effcf…` | YELLOW | Used: run 38575836529, success |
| 2026-10-13 | Merge #184 (campaign binding) | `d9a058e`, renewed for `b8259b4` | YELLOW | Used: merged as `f29c093` |
| 2026-10-13 | Ubuntu 24.04 campaign runner | focused PR (merged head `3b7f5e1`) | YELLOW | Used: #188, merged as `46bb261` |
| 2026-10-13 | Merge #189 | `f00a7f3` only | YELLOW | Lapsed, unused (the review found the tag build's quality gate lacked `GH_TOKEN`) |
| 2026-10-13 | Merge #189 | `0acdfcf` only | YELLOW | Used: merged as `adb2006` |
| 2026-10-13 | Merge #190 | `b8689b4` only | YELLOW | Lapsed, unused (CodeRabbit findings required a head change) |
| 2026-10-14 | Merge #190 | `2426c53` only | YELLOW | Used: merged as `ba585fe` |
| 2026-10-14 | Merge #192 | `f21b6ff` only | YELLOW | Lapsed, unused (strict protection required an update after #190) |
| 2026-10-14 | Merge #192 | `83e3ab9` only | YELLOW | Used: merged as `5e18f44` |
| 2026-10-14 | Runner-pin PR | prepare, refresh after #192, request review; no merge | – | Used: #193 at `e99d2e2` |
| – | v0.3.8 operator note, merge #176, v0.3.8 tag, stable promotion | – | RED | Not granted |
| – | v0.4.0-rc.4 tag, publication, designation | – | RED | Not granted |

## E1 procedure (V038-E1)

Earliest dispatch: **2026-10-14T09:20Z**. Run `date -u` first.
E0 (run 38373171801) completed at 2026-10-13T09:07:57Z. The 24-hour floor is
2026-10-14T09:07:57Z.

Preflight, repeated immediately before dispatch:
0. **Single-dispatch guard.** No repository workflow enforces this: E1 runs
   the workflow frozen at tag `v0.3.8-rc.2`, which cannot be changed.
   Run
   `gh run list --repo Kernel-Guard/bpfcompat --workflow maintenance-evidence.yml --branch v0.3.8-rc.2 --limit 100 --json databaseId --jq '[.[].databaseId] | sort'`.
   The result must be exactly `[38372362181,38373171801]`: the failed and
   the successful E0 attempts. Repeat it with `--commit
   baa57a764d4d5071b7dd9ff255d9c6d81ec2b65d` in place of `--branch …`, which
   catches a dispatch on another ref at the same commit; the result must be
   the same set. Any other run ID means an E1 may already exist, so **stop**
   and report it. Also require `date -u` ≥ 2026-10-14T09:20Z.
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
