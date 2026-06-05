# Architecture (MVP)

## System boundary

The MVP is a local-first CLI pipeline:

1. Host-side orchestrator (`bpfcompat`, Go)
2. VM executor (QEMU/KVM per profile)
3. In-VM validator (`bpfcompat-validator`, C/libbpf)
4. Host-side report/classification aggregation (Go)

Default validation remains VM-backed; optional runtime host execution is behind an explicit safety gate.

## High-level flow

1. Parse CLI inputs (`artifact`, `manifest`, `matrix`, output paths).
2. Resolve profile list from matrix.
3. Stage run directory under `.bpfcompat/runs/<run-id>/`.
4. For each profile:
   - prepare overlay image from cached base image
   - boot VM with cloud-init
   - copy artifact/manifest, generated functional plan, and validator into guest
   - execute validator inside guest
   - run manifest functional commands while successful BPF links are alive
   - retrieve `validator-result.json` and logs
5. Classify failures on host from validator output.
6. Write aggregate JSON and Markdown reports.

## Why this is real-kernel validation

- BPF object open/load is done in guest kernel context via libbpf.
- Attach attempts are done in guest kernel context.
- Optional functional commands run inside the guest while libbpf links remain attached.
- Verifier/libbpf signals are captured from guest execution, not simulated.
- Capability/BTF probing reflects guest runtime environment.

## Core modules

- `cmd/bpfcompat`: CLI entrypoint and command wiring.
- `internal/runner`: run orchestration, target execution loop, result normalization.
- `internal/vm`: image handling, cloud-init seed, QEMU invocation, SSH/SCP transport.
- `internal/classifier`: failure taxonomy mapping from raw signals.
- `internal/report`: JSON/Markdown output.
- `validator/c-libbpf`: guest-side validator binary.

## Data artifacts

- Per-target:
  - `serial.log`
  - `validator-result.json`
  - `validator.stderr`
- Aggregated:
  - final JSON report (`schema v0.1`)
  - final Markdown report

## Security boundary summary

- Untrusted `.bpf.o` is validated in disposable VMs.
- Default runner policy is VM-only for MVP.
- See `docs/security-model.md` for detailed controls and non-goals.
