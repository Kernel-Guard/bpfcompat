# Incident Response Runbook

## Severity Model

- `SEV-1`: registry integrity failure, signature verification failure, or widespread infra errors.
- `SEV-2`: repeated campaign instability, partial matrix outages, degraded but functioning validation.

## Immediate Actions

1. Freeze promotion/deployment actions.
2. Capture latest evidence artifacts:
   - `evidence/production-tech/*`
   - `.bpfcompat/runs/<latest-run-id>/`
3. Execute:
   - `./bin/bpfcompat history verify --workdir .bpfcompat`
   - `make beta-tech-check`

## Triage Paths

### A) History/Signature Failure

1. Identify first failing index from `history verify`.
2. Compare failing record with previous known-good backup.
3. If local-key mode was used, rotate signing key and re-sign only if data integrity root cause is understood.
4. If external signer mode is used, validate signer backend availability and key material.

### B) Matrix Infra Errors

1. Check VM prerequisites (`/dev/kvm`, image availability, qemu logs).
2. Re-run affected targets with `--keep-vm-on-failure`.
3. Inspect target logs: `serial.log`, `qemu.log`, `validator.stderr`.

### C) Compatibility Regressions

1. Compare latest report with previous baseline via `bpfcompat compare`.
2. Identify regression profiles and classification codes.
3. Roll back to previous artifact variant if selector policy allows.

## Exit Criteria

- Root cause identified and documented.
- Production-tech gate returns `ready`.
- A post-incident note is added under `evidence/production-tech/`.

