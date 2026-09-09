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

Two guards protect the key from matching things that only look alike:

- if the same `profile_id` requests a different kernel family on each side, the
  obligation itself changed and the cell is inconclusive;
- if one report was produced by the generic validator and the other by a
  project's own loader (command mode), the loader contract changed and every
  cell is inconclusive. "Did it regress" has no meaning when the thing doing the
  loading also changed.

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
  (`environment.kernel_family_match: false`);
- no verdict recorded, or a verdict this differ does not recognise;
- the obligation, its requiredness, or the loader contract changed between the
  reports.

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
  otherwise be compared from its first JSON value alone.

None of these is a statement about the candidate's software.

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
