# Gate Contract: Runs With No Required Target

A matrix marks each profile `required: true` or `required: false`.
`schema.RunVerdict` rolls up **required targets only**, so the run verdict
and the exit code come from required targets alone. That rule stops an
optional experimental kernel from blocking a release. It has a corollary:
**a matrix with no required target always reports `COMPATIBLE` and exits 0**,
even when every target failed.

That run is still useful. `matrices/rhcos.yaml` is optional-only on purpose,
because RHCOS images are operator-supplied and experimental. But its result
is a **diagnostic execution**, not a **satisfied compatibility gate**. This
page defines how the two are told apart.

## Three different things

| Term | Meaning | Where to read it |
|---|---|---|
| Diagnostic execution | Targets ran and produced per-target results; no gate was evaluated | `targets[].verdict`, `summary.gate: "none"` |
| Successful execution | Every target produced an answer about the environment it asked for | `summary.complete: true` |
| Satisfied compatibility gate | At least one target was required, and every required target was established `COMPATIBLE` | `summary.gate: "enforced"` **and** `summary.verdict: "COMPATIBLE"` |

## The contract

- **`summary.gate`** is an additive field (schema v0.1):
  - `"enforced"`: at least one target is required, and `summary.verdict` is a
    compatibility gate over the required targets.
  - `"none"`: no target is required. `summary.verdict` is vacuously
    `COMPATIBLE`; read `targets[].verdict`.
  - It is absent in reports written before this field existed. There it can
    be derived from `targets[].required` (`schema.RunGate`).
- **The established values are unchanged.** An optional-only run keeps
  `status: "pass"`, `verdict: "COMPATIBLE"` and exit 0. `bpfcompat diff`
  recomputes `verdict` from the targets and refuses a report that disagrees
  with itself, so redefining `verdict` would break every existing consumer
  and every stored report.
- **The run note says what kind of run it was.** A gate-`none` run no longer
  carries "All required profiles passed validator load checks." Instead it
  carries: *"no required targets: diagnostic run, not a compatibility gate.
  …"*
- **The Action job summary** (`bpfcompat report-summary`) changes for a
  gate-`none` run:
  - The title is `# bpfcompat Compatibility Run (diagnostic, no gate)`
    instead of `# bpfcompat Compatibility Gate`.
  - The `**Gate:** none — no required targets: diagnostic run, not a
    compatibility gate.` line comes **before** Status and Verdict.
  - It is derived from the targets, so older reports get it too. Gated runs
    keep the established title and layout.
- **`--require-gate`** is opt-in, on `bpfcompat test` and `test-command`.
  - A finished run with `summary.gate: "none"` exits **1** instead of 0, and
    says why on stderr.
  - Exit 1 is the "requested contract not established" class, the same as
    `INFRA_ERROR`. It is never 2, because nothing was proven about the
    artifact.
  - The report is written in full either way, so the diagnostic results are
    kept.
  - Runs with a required target are unaffected, and a required failure still
    exits 2.
- **`bpfcompat diff`** applies the same contract to comparisons.
  - Only required cells can produce `NEW_REGRESSION` / exit 2. So when no
    cell is required on either side, the diff reports `NO_NEW_REGRESSIONS`,
    exit 0, **even when an optional target went COMPATIBLE → INCOMPATIBLE**.
    That default is unchanged.
  - The diff now says what kind of comparison it was:
    - `summary.gate` is `enforced` when at least one cell is required, `none`
      when none is;
    - `summary.baseline_gate` and `summary.candidate_gate` give each input
      report's gate, derived from its targets;
    - a gate-`none` diff carries the note *"no required comparison:
      diagnostic diff, not a gate. …"*;
    - the Markdown shows `Gate: none — no required comparison: diagnostic
      diff, not a gate` and `Report gates: baseline … -> candidate …` up
      front.
  - **`bpfcompat diff --require-gate`** (opt-in) makes a gate-`none` diff
    exit **1** instead of 0. A required regression still exits 2.
  - `diff` refuses a report whose `summary.gate` contradicts its own targets,
    or holds an unknown value. That diff is `INCONCLUSIVE` with exit 1, the
    same handling as `summary.verdict` and `summary.complete`.
- **An empty matrix** (no targets at all) is rejected before any run:
  "matrix must contain at least one profile", exit 1.

A CI consumer that wants a gate should do one of the following:

- pass `--require-gate`;
- check `summary.gate == "enforced"` before trusting `summary.verdict`;
- or keep at least one `required: true` target in every matrix it gates on.
  The repository's own hand-maintained matrices are held to this by a catalog
  test in the pending profile-claims change (#255), which allowlists
  `rhcos.yaml` and `rhcos-arm64.yaml` as deliberate diagnostic matrices.

## Observed behaviour (real binary, real VMs, 2026-10-15)

Command mode on local KVM:

- *optional pass* and *optional fail*: `ubuntu-22.04-5.15` optional, command
  `true` or `false`.
- *optional infra_error*: `linux-mainline-5.6` optional, no image.
- *required pass + optional fail*: `ubuntu-22.04-5.15` required and
  `ubuntu-22.04-5.15-lockdown` optional, command
  `test "$(uname -r)" = 5.15.0-186-generic`.
- *required fail*: `ubuntu-22.04-5.15` required, command `false`.

| Case | status / verdict / complete | gate | Run note (before → after) | Exit before | Exit after | Exit after with `--require-gate` | Action summary (after) |
|---|---|---|---|---|---|---|---|
| No targets | — (matrix rejected) | — | "matrix must contain at least one profile" | 1 | 1 | 1 | no report |
| All optional, pass | pass / COMPATIBLE / true | none | "All required profiles passed…" → no-gate note | 0 | 0 | **1** | `Gate: none` line |
| All optional, fail | pass / COMPATIBLE / true | none | same | 0 | 0 | **1** | `Gate: none` line |
| All optional, infra_error | pass / COMPATIBLE / false | none | same + "coverage incomplete" | 0 | 0 | **1** | `Gate: none` + `Coverage: incomplete` |
| Required pass + optional fail | pass / COMPATIBLE / true | enforced | unchanged | 0 | 0 | 0 | unchanged |
| Required fail | fail / INCOMPATIBLE / true | enforced | unchanged | 2 | 2 | 2 | unchanged |

`status`, `verdict`, `complete` and the default exit codes are identical
before and after. Optional-only reports diffed against each other give
`NO_NEW_REGRESSIONS`, exit 0, with only optional cells. A diff over
gate-`none` reports can never show a required regression. The `bpfcompat
diff` from main reads the new reports unchanged, because unknown JSON fields
are ignored.

**Diff, real VMs.** Both reports are artifact mode on `ubuntu-22.04-5.15`,
optional:

- baseline: `simple_pass.bpf.o`, COMPATIBLE;
- candidate: a verifier-rejected XDP object, INCOMPATIBLE.

| `bpfcompat diff` | result | new optional regressions | gate / baseline_gate / candidate_gate | Exit |
|---|---|---|---|---|
| Before (no gate signal) | NO_NEW_REGRESSIONS | 1 | — | 0 |
| After | NO_NEW_REGRESSIONS | 1 | none / none / none (+ note, + Markdown lines) | 0 |
| After, `--require-gate` | NO_NEW_REGRESSIONS | 1 | none / none / none | **1** |

## Limits

- `bpfcompat suite` and the GitHub Action expose no `--require-gate` input
  yet. Action users get the job-summary wording, and can check
  `summary.gate` in the JSON report.
- The Markdown report (`--markdown`) does not yet print the gate line.
- The GitHub Action's diff mode (`baseline-report` / `candidate-report`)
  does not pass `--require-gate` yet. Its outputs and exit handling are
  unchanged.
