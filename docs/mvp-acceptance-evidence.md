# MVP Acceptance Evidence

Generated at: `2026-05-17T13:10:09Z` (UTC)

## Scope

- Matrix: `matrices/mvp.yaml`
- Profiles: `ubuntu-18.04-4.15`, `ubuntu-20.04-5.4`, `ubuntu-22.04-5.15`, `ubuntu-22.04-minimal-5.15`, `ubuntu-24.04-6.8`, `debian-11-5.10`, `debian-12-6.1`, `debian-13-6.12`
- Fixtures: simple pass, ringbuf modern, perfbuf fallback, CO-RE relocation failure, unsupported attach, unknown non-ELF load failure

## Fixture Results

| Fixture | Summary | Target Pass/Fail | Classification Codes |
|---|---|---|---|
| simple-pass | pass | 7/1 | UNSUPPORTED_ATTACH_TYPE |
| ringbuf-modern | fail | 5/3 | UNSUPPORTED_ATTACH_TYPE, UNSUPPORTED_MAP_TYPE |
| perfbuf-fallback | pass | 7/1 | UNSUPPORTED_ATTACH_TYPE |
| core-relocation | fail | 0/8 | CORE_RELOCATION_FAILURE, MISSING_BTF |
| unsupported-attach | fail | 0/8 | UNSUPPORTED_ATTACH_TYPE |
| unknown-load-fail | fail | 0/8 | UNKNOWN |

## Gate Assertions

- `simple-pass`: summary is `pass`, includes 8 targets, and has no `infra_error` targets.
- `ringbuf-modern`: includes `UNSUPPORTED_MAP_TYPE` and markdown guidance mentions perf fallback.
- `perfbuf-fallback`: summary is `pass` and markdown references `perf_event`.
- `core-relocation`: includes both `MISSING_BTF` and `CORE_RELOCATION_FAILURE` and per-target BTF fields.
- `unsupported-attach`: includes `UNSUPPORTED_ATTACH_TYPE` or `UNSUPPORTED_PROG_TYPE`.
- `unknown-load-fail`: includes `UNKNOWN` classification for non-ELF load failure.

## Raw Artifact Presence

- `libbpf.log` files under `.bpfcompat/runs/`: 445
- `*.json` files under `.bpfcompat/runs/`: 592

## Referenced Reports

- `reports/simple-pass-mvp.json` / `reports/simple-pass-mvp.md`
- `reports/ringbuf-modern-mvp.json` / `reports/ringbuf-modern-mvp.md`
- `reports/perfbuf-fallback-mvp.json` / `reports/perfbuf-fallback-mvp.md`
- `reports/core-relocation-mvp.json` / `reports/core-relocation-mvp.md`
- `reports/unsupported-attach-mvp.json` / `reports/unsupported-attach-mvp.md`
- `reports/unknown-load-fail-mvp.json` / `reports/unknown-load-fail-mvp.md`
