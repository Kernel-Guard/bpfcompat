# bpfcompat v0.3.8 — fail-closed promotion incident drill (candidate v0.3.8-rc.2)

[bpfcompat-promotion-incident:v1]

- Date: 2026-10-13
- Operator: `ErenAri` (release.yaml `release_operator`, solo-maintainer)
- Workflow: `promote-release.yml` dispatched on `refs/tags/v0.3.8-rc.2` (commit `baa57a764d4d5071b7dd9ff255d9c6d81ec2b65d`)
- Rejected run: **38374219086** (https://github.com/Kernel-Guard/bpfcompat/actions/runs/38374219086), started 2026-10-13T09:08:46Z, concluded `failure` 2026-10-13T09:23:58Z
- Deliberate fault: `confirmation = "promote v0.3.8"` instead of the required `promote v0.3.8-rc.2`. All other inputs were the real candidate's:
  - candidate run 38299717810;
  - the exact commit;
  - digest `sha256:046effcfe3575c89663cc925042278e0da0804afe4199fff1abf9e13fea26f1d`.

## Observed behaviour
1. The `production-release` environment applied its 15-minute wait timer, with no bypass.
2. "Manual promotion confirmation" failed: `test "$CONFIRMATION" = "promote ${RELEASE_TAG}"`.
3. Every later step was skipped. That includes identity verification, artifact download, re-verification, the GHCR login, image promotion and the release edit.

## State verified after the run
- `v0.3.8-rc.2` release: still a published prerelease (published 2026-10-12T20:15:55Z). All 12 assets were last updated 2026-10-12T19:58:19Z, before the drill.
- GitHub "latest" release: still `v0.3.7`.
- `ghcr.io/kernel-guard/bpfcompat:latest` = `:0.3.7` = `sha256:05c028e99dd7afd10a8765a361457bbd79c51a89ca1cb62561043c52c2561fc9`, unchanged.
- `ghcr.io/kernel-guard/bpfcompat:0.3.8-rc.2` = `sha256:046effcfe3575c89663cc925042278e0da0804afe4199fff1abf9e13fea26f1d`, unchanged.

Conclusion: an incorrectly confirmed promotion of the rc.2 candidate fails closed before any registry or release write.
