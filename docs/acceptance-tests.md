# Acceptance Tests

This document defines the MVP acceptance flow for Linux + KVM hosts.

## Preconditions

- Linux x86_64 host with `/dev/kvm`
- QEMU/KVM tools installed
- VM images present under `vm/cache/` (`make vm-images`)

## One-command acceptance

```bash
make acceptance
```

For a quick one-profile event-capture proof:

```bash
make acceptance-functional-dev-one
```

For a quick multi-artifact project-suite proof:

```bash
make acceptance-suite-dev-one
```

This target:

1. builds `bpfcompat`
2. builds the C/libbpf validator
3. builds all example `.bpf.o` fixtures
4. runs the MVP fixture matrix with expected exit codes
5. enforces report/log assertions with `jq` and `grep`

## What `make acceptance` validates

- `simple-pass` exits `0`, summary is `pass`, has 8 targets, and has no `infra_error` targets.
- `functional-execve` can be run with `make acceptance-functional-dev-one` to
  prove the validator keeps the BPF link alive, triggers an exec event, and
  observes the event marker in `trace_pipe`.
- `dev-functional` can be run with `make acceptance-suite-dev-one` to prove a
  suite file can drive multiple artifacts and manifests through the same
  VM-backed matrix and produce a suite summary.
- `ringbuf-modern` exits `2` and includes `UNSUPPORTED_MAP_TYPE`.
- `perfbuf-fallback` exits `0` and includes perf-buffer guidance.
- `core-relocation` exits `2` and includes both `MISSING_BTF` and `CORE_RELOCATION_FAILURE`.
- `unsupported-attach` exits `2` and includes unsupported attach/program classification.
- `unknown-load-fail` exits `2` and includes `UNKNOWN` classification for non-ELF load failure.
- Across acceptance reports, at least five classes are present:
  `UNSUPPORTED_MAP_TYPE`, `MISSING_BTF`, `CORE_RELOCATION_FAILURE`,
  `UNSUPPORTED_ATTACH_TYPE`, `UNKNOWN`.
- Raw runtime artifacts exist under `.bpfcompat/runs/` including `libbpf.log`.

## Evidence export

After a successful acceptance run:

```bash
make acceptance-evidence
```

This writes `docs/mvp-acceptance-evidence.md` from the generated reports.

## OSS validation evidence export

To generate report packs from real OSS artifacts (`cilium/ebpf`, `iovisor/bcc`):

```bash
make oss-evidence
```

This writes:

- `evidence/oss-validation/summary.md`
- `evidence/oss-validation/reports/*.json`
- `evidence/oss-validation/reports/*.md`
- `evidence/oss-validation/raw-runs/**`
