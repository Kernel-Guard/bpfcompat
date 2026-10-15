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
- **`--require-gate`** is opt-in, on `bpfcompat test` and `test-command` (and on `suite` and `diff`, below).
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
    - `summary.gate` is `enforced` **only when at least one profile is
      required in both reports**, that is, a baseline obligation that the
      candidate also evaluated as required. Otherwise it is `none`.
      - A diagnostic candidate (no required target) never makes a gated
        diff, whatever the baseline says. Neither does a diagnostic
        baseline, or two reports that are each gated but on different
        profiles.
      - The diff's result and default exit code still count cells required
        on either side, unchanged. Only the gate signal uses the both-sides
        rule.
    - `summary.baseline_gate` and `summary.candidate_gate` give each input
      report's gate, derived from its targets;
    - a gate-`none` diff carries the note *"no required comparison:
      diagnostic diff, not a gate. …"*;
    - the Markdown shows `Gate: none — no required comparison: diagnostic
      diff, not a gate` and `Report gates: baseline … -> candidate …` up
      front.
  - **`bpfcompat diff --require-gate`** (opt-in): a diff whose gate is not
    `enforced` exits **1**, unless it already exits 2. A proven required
    regression is never masked.
  - `diff` refuses a report whose `summary.gate` contradicts its own targets,
    or holds an unknown value. That diff is `INCONCLUSIVE` with exit 1, the
    same handling as `summary.verdict` and `summary.complete`.
- **An empty matrix** (no targets at all) is rejected before any run:
  "matrix must contain at least one profile", exit 1.
- **The `--markdown` test report** prints `- Gate: enforced` or `- Gate:
  none — no required targets: diagnostic run, not a compatibility gate` next
  to Status and Verdict.

### Suites (`bpfcompat suite`)

- **Per case:** `cases[].gate` is the case report's gate, derived from its
  targets: `enforced` or `none`. A case that produced no report (setup or
  run error, cancellation) is `unknown`. A case whose report has no targets
  is `none`.
- **In aggregate:** `summary.gate` is
  - `enforced` only when **every** case is enforced;
  - `partial` when some cases are;
  - `unknown` when no case is and at least one case has no gate evidence
    (no report), or the case list is empty;
  - `none` when every case is a diagnostic case.

  `unknown` never counts as enforced, so missing evidence cannot make a suite
  look gated.
- **Markdown:** the suite Markdown prints the suite gate next to Status and
  adds a Gate column per case. `bpfcompat suite` (text output) prints
  `Gate:` and `gate=` per case.
- **Default exit codes are unchanged.** A diagnostic case passes as before,
  and the suite keeps its existing precedence: any exit-1 case makes the
  suite exit 1, otherwise any exit-2 case makes it exit 2.
- **`bpfcompat suite --require-gate`** applies **per case**: every case must
  evaluate a gate.
  - A case whose gate is not `enforced` and that would otherwise pass becomes
    `status: error`, `exit_code: 1`, with an `error` saying why. The suite
    then exits 1.
  - A case that already failed keeps its exit code. A gated case is
    untouched, including a required failure at exit 2.
- **Suite exit precedence: existing behaviour, and a known divergence.**
  - `bpfcompat suite` has always rolled cases up with exit 1 (tool error)
    outranking exit 2 (compatibility failure) (`updateSuiteStatus`,
    unchanged here).
  - So under `--require-gate`, a suite with both a diagnostic case (now 1)
    and a required INCOMPATIBLE case (2) exits **1**. The same holds today
    for any infrastructure error next to an INCOMPATIBLE case.
  - That differs from the run-level rule (`schema.RunVerdict`), where a
    proven incompatibility outranks an inability to establish. A consumer
    keying on exit 2 loses that signal at suite level.
  - It is never a pass. The step fails, and the INCOMPATIBLE case keeps
    `status: fail` / `exit_code: 2` in the suite JSON and Markdown.
  - Aligning suite precedence with the run-level rule is a separate,
    future-targeted change.

### GitHub Action (`require-gate` input)

- **Opt-in:** `require-gate: "true"`. The default `"false"` runs the same
  command as before. All 14 in-repo invocations of the action (`uses: ./`
  and `@main`), across 10 workflows including the release, external-canary,
  consumer-canary source and latest-kernel ones, were replayed through the
  action's run step from main and from this change. They produced identical
  argv, exit codes and outputs. The only difference is the additive
  `diff-gate`, `diff-baseline-gate` and `diff-candidate-gate` outputs in diff
  mode.
- **Validation:**
  - The value must be `true` or `false`. Empty means the default, `false`,
    in every mode, as with the action's other boolean inputs (for example an
    unset `workflow_dispatch` input forwarded as `''`).
  - It reaches the shell only through the step environment
    (`INPUT_REQUIRE_GATE`), never by inline interpolation.
  - Anything else fails the step before the CLI runs. The error does **not**
    echo the value, because a newline in it could start a second workflow
    command. The diff-mode boolean inputs (`fail-on-*`) no longer echo the
    value either.
- **test and command mode:** `true` adds `--require-gate` to `bpfcompat
  test`, and the step's exit is the CLI's.
- **suite mode:** `true` adds `--require-gate` to `bpfcompat suite`
  (per-case semantics above).
- **diff mode** (`scripts/action-diff.sh`):
  - `true` fails the policy unless the diff JSON's `summary.gate`,
    `summary.baseline_gate` and `summary.candidate_gate` are all
    `enforced`.
  - This holds even with `fail-on-incomplete: false`. A gated baseline
    compared with a diagnostic candidate fails, as does an absent field (as
    from an older binary), which is no gate evidence.
  - New outputs: `diff-gate`, `diff-baseline-gate`, `diff-candidate-gate`.

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

**Suite, real VMs.** Two artifact-mode cases (`simple_pass.bpf.o`) on
`ubuntu-22.04-5.15`. `diagnostic` uses an optional-only matrix; `gated`
requires the profile.

| Binary / flag | suite status / exit / gate | `diagnostic` case | `gated` case |
|---|---|---|---|
| Before (1fe4b3e) | pass / 0 / — | pass / 0 / — | pass / 0 / — |
| After, default | pass / 0 / `partial` | pass / 0 / `none` | pass / 0 / `enforced` |
| After, `--require-gate` | **error / 1** / `partial` | **error / 1** / `none` (error names `--require-gate`) | pass / 0 / `enforced` |

## Limits

- `--require-gate` is checked after the run, so diagnostic targets still boot
  and their reports are kept.
- Suite exit precedence (1 over 2) is existing behaviour and diverges from
  the run-level rule; see "Suite exit precedence" above.
