# Release Regression Diff

`bpfcompat diff` compares two compatibility reports and answers one question:

> Did this candidate release break an environment my previous release supported?

An absolute compatibility matrix cannot answer that. A release that has always
failed on 4.14 looks identical to one that broke 4.14 yesterday — both are red.
The diff separates the two.

It is **offline and stateless**: it reads two JSON files and nothing else. No
database, no history store, no network, no service.

```
bpfcompat diff --baseline release-1.2.json --candidate release-1.3.json \
  --out diff.json --markdown diff.md
```

## Baseline and candidate

**Baseline** is trusted reference evidence — the compatibility report of a
release you already shipped and support. **Candidate** is the release being
evaluated.

Both must be bpfcompat reports with `schema_version: v0.1`. Anything else is
refused rather than guessed at.

## What gets compared

The comparison unit is a **support obligation**: one environment your matrix
promises to validate. Its key is the **`profile_id`**.

Deliberately *not* part of the key:

- **the artifact SHA-256** — release N and N+1 are supposed to contain different
  artifacts. Both are recorded for traceability, never for matching.
- **the observed kernel** — Gate 1 separates the environment that was *requested*
  from the one that actually *booted*. The obligation is the requested one.

Guards protect the key from matching things that only look alike. A
`profile_id` is a name, and a name can be pointed at a different promise:

- if the same `profile_id` requests a different **kernel family**,
  **architecture**, **distro** or **distro version** on each side, the
  obligation itself changed and the cell is inconclusive. `ubuntu-22.04-5.15`
  validated on x86_64 at baseline and on arm64 in the candidate is not one
  obligation with a changed result — it is two obligations sharing a name;
- if the two sides exercised **different amounts of the contract** (different
  `validation.attach_mode`), the cell is inconclusive. A load-only candidate
  cannot inherit an attach-tested baseline's green;
- if one report was produced by the generic validator and the other by a
  project's own loader (command mode), the loader contract changed and every
  cell is inconclusive. "Did it regress" has no meaning when the thing doing the
  loading also changed;
- in command mode, if the **command under test** (`invocation_sha256`) or the
  **exit code that counts as success** changed, every cell is inconclusive: the
  two runs answer different questions.

### What is allowed to change

Deliberately *not* guarded, because these are supposed to change between
releases:

- the **artifact** SHA-256 and OCI digest — that is the point of the comparison;
- in command mode, the **project's own loader binary** (`command.binary.sha256`).
  It *is* the thing being released. Requiring it to be byte-identical between
  release N and N+1 would make every real comparison incomparable;
- the **bpfcompat validator build** (`validator.sha256`) in artifact mode. It is
  the measuring instrument, not the subject, and its load/attach contract is
  stable across bpfcompat versions by design. A change is recorded as a **note**
  in the diff, because it is the first thing to check when a result surprises
  you — but it does not gate, since gating on it would make every bpfcompat
  upgrade report every environment as incomparable.

## Classifications

| Classification | Baseline → Candidate | Meaning |
|---|---|---|
| `UNCHANGED_COMPATIBLE` | COMPATIBLE → COMPATIBLE | supported before, supported now |
| `NEW_REGRESSION` | COMPATIBLE → INCOMPATIBLE | **the product signal.** This release broke an environment the baseline proved worked |
| `EXISTING_INCOMPATIBILITY` | INCOMPATIBLE → INCOMPATIBLE | a known limitation. Still visible, but not newly introduced |
| `FIXED` | INCOMPATIBLE → COMPATIBLE | the candidate gained support |
| `INCONCLUSIVE` | either side unproven | the change cannot be established |
| `COVERAGE_ADDED` | absent → present | the candidate tests something new. Not a regression |
| `COVERAGE_REMOVED` | present → absent | continued support cannot be established. Not the same as broken |

`NEW_REGRESSION` is the only classification that is a statement about the
candidate's software.

### When a comparison is inconclusive

A cell is inconclusive when either side failed to settle the question:

- `INFRA_ERROR` or `UNSUPPORTED` on either side;
- either side ran a kernel other than the one the profile names
  (`environment.kernel_family_match: false`) — recorded as
  `environment_evidence: "mismatch"`;
- either side **never recorded which kernel it ran** (no `environment`, or no
  `environment.kernel_family_match`) — recorded as
  `environment_evidence: "unknown"`;
- no verdict recorded, or a verdict this differ does not recognise;
- the obligation, its requiredness, the validation depth, or the loader contract
  changed between the reports;
- the candidate added a required obligation but did not establish it — a new row
  with no evidence in it is not added coverage.

`unknown` and `mismatch` are kept apart on purpose. A report that never named a
kernel is not evidence that the wrong kernel booted, and the reason text never
claims it is.

### Why "unknown" is not "established"

`schema.EstablishedRequestedEnvironment` — the Gate 1 helper — answers **true**
when the environment metadata is absent. That is correct where it is used: a
report reader must not invent a failure out of a field an older bpfcompat never
wrote, and blaming a user's software for our missing metadata would be worse
than saying nothing.

A release gate asks a different question: *do we positively know this candidate
still supports the environment we promise?* "The file does not say" is not a
yes. So `internal/regressiondiff` applies its **own, stricter** reading and
treats absent environment evidence as unknown. The shared helper is deliberately
left alone — changing it would silently restate the contract of every existing
consumer.

The practical consequence: a **pre-Gate-1 report can be read but can never be
conclusive.** It is not rejected — age is not tampering — but it cannot prove a
baseline was COMPATIBLE, so it can neither manufacture a `NEW_REGRESSION` nor
support an `UNCHANGED_COMPATIBLE`.

## Evidence that cannot be compared at all

Some inputs are rejected outright, before any cell is built, because their
comparison keys cannot be trusted. Each produces exit `1` with an explanation:

- a report with **no targets** — it establishes nothing to compare against;
- a target with an **empty `profile_id`** — the obligation it represents is
  unidentifiable;
- a **duplicated `profile_id`** within one report — which result represents that
  obligation is ambiguous, and a release gate may not resolve that by guessing;
- unreadable, malformed, or unsupported-schema evidence, **including a file
  carrying anything after the report** — a truncated or concatenated file would
  otherwise be compared from its first JSON value alone;
- a **duplicated JSON key** anywhere in the document. `encoding/json` accepts
  duplicates and keeps the last value, so
  `"verdict":"INCOMPATIBLE","verdict":"COMPATIBLE"` parses green while a human
  reading the file sees a failure. Which value a release decision came from must
  not depend on a parser's choice;
- a target that **does not state `required`** (absent, or `null`). It
  deserializes to `false`, which would silently demote a proven regression to a
  non-gating optional finding. Deleting the field is not a way to discover that
  an obligation was never required;
- a target whose **`status` and `verdict` contradict each other** — the runner
  derives one from the other, so genuine evidence always agrees. A report does
  not become conclusive because one of its fields contains the word
  `COMPATIBLE`;
- a target asserting **`kernel_family_match` without** the requested family and
  observed kernel it would have been derived from — the claim rests on nothing;
- a report whose **`summary` contradicts its own targets** (`summary.verdict`
  against the required targets, `summary.complete` against the coverage,
  `summary.status` against `summary.verdict`). The targets are the single source
  of semantic truth; a file that disagrees with itself is not trustworthy in
  either direction, and refusing is better than resolving the conflict *as*
  `INCOMPATIBLE`, which would blame a candidate for a broken input file;
- **the same run on both sides** — identical `run.id`, or literally the same
  file. It is trivially, permanently green: it proves a run equals itself and
  nothing about a candidate release. The usual cause is CI wiring that fetched
  the same artifact twice, and a gate a wiring mistake can satisfy protects
  nothing;
- a file **larger than 32 MiB**. Real reports are kilobytes; the largest this
  project has produced is ~60 KB. The bound exists because this command is
  designed to eat CI artifacts a pull-request author controls, and reading an
  attacker-sized file into memory before validating it is an OOM, not a gate.

None of these is a statement about the candidate's software. Every one is exit
`1`.

### The comparison never destroys its inputs

`--out` and `--markdown` refuse to write over the baseline or candidate report,
and refuse to be the same file as each other. The baseline is the record of what
your last release supported; it may be the only copy, and `--out "$BASELINE"` is
one unset variable away in any CI script.

The comparison is by **file identity**, not by path text: a symbolic link, a
hard link, or a second route to the same directory is the same file however
differently it is spelled.

**An unproven baseline can never manufacture a regression.** If the baseline hit
an infrastructure failure and the candidate is incompatible, that is
`INCONCLUSIVE`, not `NEW_REGRESSION` — the baseline never proved the environment
worked, so nothing can be said to have broken. The candidate's incompatibility
stays visible in the cell as evidence.

## Required versus optional

Gate 1 established that `required: false` is informational and does not gate a
release. The diff preserves that exactly:

- a **required** `NEW_REGRESSION` blocks the candidate;
- an **optional** `NEW_REGRESSION` is reported prominently and counted
  separately, but does not gate;
- a **required** `INCONCLUSIVE` or `COVERAGE_REMOVED` prevents a green result —
  the candidate's compatibility relative to the baseline was not established;
- an **optional** one is visible and non-gating.

Which side decides: **either**. A cell gates if the baseline *or* the candidate
treated the obligation as required. Letting the candidate alone decide was a
hole — a release could flip a profile to `required: false` and turn a regression
on an environment the baseline promised into a non-gating optional finding.

A change in requiredness is a change to the **support contract**, not to the
software, so such a cell is `INCONCLUSIVE` and `required_changed: true` is
recorded. Whether a candidate regressed against a promise that did not exist at
baseline — or still honours one it has since dropped — is not something this
evidence can settle, in either direction, so neither direction is reasoned about
asymmetrically.

## Coverage completeness

`summary.baseline_complete` and `summary.candidate_complete` carry Gate 1's
run-level coverage flag straight through. A diff built from incomplete evidence
is a weaker claim than it looks, and both the JSON summary and the top of the
Markdown say so. `COMPATIBLE + complete:false` is never treated as equivalent to
`COMPATIBLE + complete:true`.

## CI exit semantics

| Exit | Result | What a CI consumer should conclude |
|---:|---|---|
| `0` | `NO_NEW_REGRESSIONS` | No required environment regressed, and every required comparison was established. Known limitations may remain; optional regressions may be present and are reported. |
| `2` | `NEW_REGRESSIONS` | A required environment the baseline supported is broken in the candidate. **Do not ship.** |
| `1` | `INCONCLUSIVE` | The required comparison could not be established — infrastructure failure, an environment mismatch, removed required coverage, missing, malformed or unsupported evidence. **This is not a claim that the candidate is incompatible.** |

Exit `2` outranks exit `1`: a proven regression is a definitive fact about the
candidate and must not be buried by an inability to compare somewhere else.

## Output

`diff.json` is the machine-readable evidence, versioned
`bpfcompat.regression-diff.v0.1` — distinct from the run-report schema because
the semantics are different. The Markdown is rendered from it and is
presentation only; never parse it.

With neither `--out` nor `--markdown` set, the diff JSON is written to **stdout**
and stays parseable (`bpfcompat diff ... | jq` works); the human-readable summary
goes to stderr. With an output file selected, the summary goes to stdout.

Each cell records both sides' verdict, required flag, classification code,
requested and observed kernel, whether the environment was established, the
classification and a plain-language reason.

## Minimal example

```
$ bpfcompat diff --baseline v1.2.json --candidate v1.3.json
Result: NEW_REGRESSIONS
New required regressions: 1 | new optional: 0 | existing incompatibilities: 0 | fixed: 0 | unchanged: 1
$ echo $?
2
```

```json
{
  "schema_version": "bpfcompat.regression-diff.v0.1",
  "cells": [{
    "key": "ubuntu-20.04-5.4",
    "required": true,
    "classification": "NEW_REGRESSION",
    "reason": "the baseline proved this environment worked and the candidate proves it no longer does",
    "baseline":  {"verdict": "COMPATIBLE",   "environment_established": true},
    "candidate": {"verdict": "INCOMPATIBLE", "classification_code": "UNSUPPORTED_MAP_TYPE",
                  "environment_established": true}
  }],
  "summary": {"new_required_regressions": 1, "result": "NEW_REGRESSIONS"}
}
```

## Scope

The diff consumes evidence; it does not produce it. It never re-runs a program,
never parses a loader's stderr to decide compatibility, and never infers a
kernel capability. Every verdict it reports was recorded by the run that
produced the report — see
[compatibility-contract.md](compatibility-contract.md).

Storing evidence over time is not part of this command. Point it at two files
you already have.
