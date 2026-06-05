# Hostile Artifact Hardening Suite

This suite provides repeatable checks for hostile/malformed artifact handling and runtime safety controls.

## What It Covers

1. Runtime fetch hardening:
   - unsupported URI schemes rejected
   - hash mismatch rejected
   - oversized remote downloads rejected via `BPFCOMPAT_FETCH_MAX_BYTES`
2. History provenance tamper detection:
   - signed metadata and chain verification fail on mutation
3. Optional VM isolation scenario:
   - malformed/non-ELF artifact executed through VM path and expected to fail without host compromise

## Automated Coverage

- Unit tests:
  - `internal/runtime/fetch_test.go`
  - `internal/registry/history_test.go`
- Script entrypoint:
  - `scripts/hostile-artifact-suite.sh`

## Run

```bash
make build
scripts/hostile-artifact-suite.sh
```

To include the VM isolation scenario:

```bash
BPFCOMPAT_RUN_VM_HOSTILE=1 scripts/hostile-artifact-suite.sh
```

The suite now writes archived evidence under:

- `evidence/hostile-suite/<timestamp>/hostile-vm-run.log`
- `evidence/hostile-suite/<timestamp>/hostile-unknown-load-dev-one.json`
- `evidence/hostile-suite/<timestamp>/hostile-unknown-load-dev-one.md`

## Evidence Expectations

- Script exits non-zero on hardening regression.
- Optional VM scenario is marked `SKIP` only when local VM prerequisites are unavailable.
- When VM scenario is enabled and prerequisites are present, missing report output is treated as a hard failure.
