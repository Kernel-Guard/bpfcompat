# Engineering orchestration

How BPFCompat release and engineering work is split across Claude Code
subagents. This is a coordination convention for a single maintainer's
sessions. It deploys nothing: no daemon, bot, service, scheduler or new
workflow.

**Authoritative record.** GitHub is the system of record: PRs, issues,
required checks, workflow runs, signed provenance and readiness attestations.
`workstream-status.md` is a coordination aid only. It never replaces a
check, an attestation or a release gate, and it is updated only when real
evidence exists.

## Structure

One **lead orchestrator**, the interactive session, plans, assigns, merges
results and talks to the operator. It runs these subagents, defined in
`.claude/agents/`:

| Agent | Writes code | Isolation | Owns |
|---|---|---|---|
| `release-v038` | yes | `isolation: worktree` | `release/v0.3.8-stable`, PR #176, v0.3.8 evidence |
| `release-v040` | yes | `isolation: worktree` | v0.4.0 release metadata: the `release.yaml` bump, the RC designation and canary-retarget PRs |
| `kernel-vm` | yes | `isolation: worktree` | profiles, VM installer, PR #185, package-source research |
| `upstream-integrations` | no (policy-restricted, not sandboxed) | none | Falco and Inspektor Gadget pin and run audits |
| `security-reviewer` | no (policy-restricted, not sandboxed) | none | independent review before merging any gate, workflow, policy or installer change |

All five are ordinary Claude Code subagents (`.claude/agents/*.md`).
Experimental Agent Teams is **not** enabled
(`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` stays unset), and no user-global
configuration is changed.

**Read-only means policy, not sandbox.** The two non-coding agents have
Edit/Write/NotebookEdit removed, which is enforced. They keep `Bash` for
`gh`/`git` reads, and a shell can still write. A subagent also inherits a
parent session's permissive modes (`bypassPermissions`, `acceptEdits`,
`auto`). When an enforced boundary matters,
launch them from a non-bypass session, or review their Bash commands.

## Isolation rules
- Each coding workstream works in its own git worktree on its own branch.
  `isolation: worktree` gives each subagent run a fresh worktree; git itself
  refuses to check out a branch that another worktree already has.
- Never let two agents edit the same worktree, or push to the same remote
  branch.
- Force-push only to an unprotected branch the same agent created. Any
  force-push or rebase voids an approval of that branch's head; a new
  approval of the new exact head is required.
- Only `release-v040` edits `release.yaml`, the `CHANGELOG.md` release
  headings, `.github/campaign-candidate.json` and the canary pins.

## Parallel execution
Run in parallel only when both the files and the dependencies are disjoint.

Allowed together:
- v0.3.8 read-only preflight;
- v0.4.0 metadata preparation on its own branch;
- CentOS/package-source research;
- upstream read-only audits;
- independent security review.

Never:
- two agents editing `release.yaml` or the same release PR;
- more than one E1 dispatch;
- tag creation concurrent with release-metadata changes;
- automatic production promotion;
- designating a campaign candidate before its tag and release are verified;
- merging a policy PR whose approved head changed.

QEMU/KVM is expensive. Run one local VM job at a time, and don't run the
same kernel suite in two worktrees.

## Authorization levels
**GREEN, autonomous:**
- reading repository and GitHub state;
- research and isolated implementation;
- local and hosted tests;
- draft PRs;
- `workflow_dispatch` shakeouts on throwaway branches, which are never eligible evidence, of **only** these workflows: `ci.yml`, `latest-kernel-compatibility.yml`, and `compatibility-matrix-publish.yml` with `deploy_pages=false`. Dispatching any other workflow (for example `ghcr-image.yml`, which pushes images; `release-artifacts.yml`; `maintenance-evidence.yml`; `promote-release.yml`; `rollback-drill.yml`; or the matrix with Pages deploy) is YELLOW or RED;
- evidence collection and read-only reviews.

**YELLOW, exact scoped approval** recorded in the ledger:
- merging a release-policy or gate PR, or any change whose approval was tied to a commit, **at that exact head**;
- modifying a qualification requirement;
- executing an already authorized, time-restricted evidence dispatch (for example E1, once and only after its earliest time).

**RED, separate operator GO each time:**
- creating protected release tags;
- publishing release candidates or releases;
- promoting stable;
- changing production GHCR aliases;
- production rollback drills or production-environment changes;
- writing solo-maintainer confirmation markers.

An approval covers only its recorded action, commit and scope. If the head
moves, the base moves in a way that changes the effective diff, or the
contract changes, the approval lapses. The agent stops and the orchestrator
asks again. No agent escalates its own privileges or reuses an approval for a
different action.

## Agent output contract
Every agent ends a task with:

```
TASK_ID:
BASE_COMMIT:
HEAD_COMMIT:
FILES_CHANGED:
LOCAL_TESTS:
HOSTED_CI:            (run/check URLs and conclusions, or "none")
VM_EVIDENCE:          (LOCAL / HOSTED, exact kernel and os-release, or "none")
SECURITY_FINDINGS:
PR_URL:
BLOCKERS:
RECOMMENDED_NEXT_ACTION:
OPERATOR_APPROVAL_REQUIRED: (none / YELLOW: <action@sha> / RED: <action>)
```

Missing evidence is written as missing; it is never inferred or invented.
Time-gated work that is not yet eligible reports `BLOCKED_BY_TIME`. No agent
claims that something will run later unless a real, verified scheduler (a
GitHub workflow cron) does it.

## Statuses
`BACKLOG`, `READY`, `RUNNING`, `BLOCKED`, `REVIEW`, `MERGED`, `DONE`.
