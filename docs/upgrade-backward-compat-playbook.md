# Upgrade and Backward Compatibility Playbook

## Objectives

1. Prevent schema/report contract breaks for downstream CI consumers.
2. Preserve artifact history integrity during upgrades.
3. Support safe rollback.

## Pre-Upgrade Checklist

1. `go test ./...` passes.
2. `make beta-tech-check` returns ready.
3. `./bin/bpfcompat history verify --workdir .bpfcompat` passes.
4. Backup `.bpfcompat/registry/` and relevant run artifacts.

## Upgrade Steps

1. Deploy new binary to staging.
2. Run one full technical gate:
   - `make production-tech-check`
3. Validate report schema version and fields against `docs/schema-stability-contract.md`.
4. Promote to production only when gate is ready.

## Rollback Steps

1. Revert binary to last known-good build.
2. Re-run `history verify`.
3. Run targeted validation on previous stable artifacts.
4. Confirm selector still chooses expected compatible variant.

## Backward Compatibility Rules

- Never remove existing report fields without schema version increment and migration notes.
- Keep `history verify` behavior stable for previously signed records.
- Keep CLI exit codes and required gate semantics stable for CI integrations.

