# Runtime Selector Simulation and E2E Proof

This document covers both:

1. a lightweight report-only selector simulation (`scripts/select-artifact-variant.sh`)
2. an end-to-end runtime selector proof (`scripts/runtime-selector-proof.sh`)
3. a gated runtime delivery proof (`scripts/runtime-delivery-proof.sh`)

## 1) Report-Only Selector Simulation

Given two or more report files:

1. choose candidate with the fewest required-profile failures
2. tie-break by most required-profile passes
3. tie-break by fewest total failures

Command:

```bash
scripts/select-artifact-variant.sh \
  reports/ringbuf-modern-mvp.json \
  reports/perfbuf-fallback-mvp.json
```

Expected result:

- `perfbuf-fallback` is selected because it passes required profiles while `ringbuf-modern` fails older required profiles.

## 2) End-to-End Runtime Selector Proof

This proof exercises the runtime path:

- seed artifact version history from known reports
- sign/verify registry history
- run `runtime select`
- run `runtime fetch`
- persist runtime decision traces/events

Command:

```bash
make runtime-selector-proof
```

Outputs:

- `evidence/runtime-selector/<timestamp>/runtime-selector-proof.md`
- `evidence/runtime-selector/<timestamp>/runtime-select.json`
- `evidence/runtime-selector/<timestamp>/runtime-fetch.json`
- `evidence/runtime-selector/<timestamp>/workdir/runtime-audit/decisions/*.json`

To regenerate fresh selector evidence:

```bash
make runtime-selector-proof
```

## 3) Gated Runtime Delivery Proof

This proof extends selector coverage to include runtime probe + runtime execute:

- run `runtime probe`
- run `runtime select`
- run `runtime fetch` (strict history verification enforced)
- run `runtime execute` with explicit `--allow-host-load` gate
- persist runtime decision traces/events for select/fetch/execute
- execute step uses controlled proof execution flow (not a hosted production runtime service)

Command:

```bash
make runtime-delivery-proof
```

Outputs:

- `evidence/runtime-delivery/<timestamp>/runtime-delivery-proof.md`
- `evidence/runtime-delivery/<timestamp>/runtime-probe.json`
- `evidence/runtime-delivery/<timestamp>/runtime-select.json`
- `evidence/runtime-delivery/<timestamp>/runtime-fetch.json`
- `evidence/runtime-delivery/<timestamp>/runtime-execute.json`
- `evidence/runtime-delivery/<timestamp>/workdir/runtime-audit/decisions/*.json`
