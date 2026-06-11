# Validator (C/libbpf) Behavior

## Purpose

`validator/c-libbpf/bin/bpfcompat-validator` is executed inside each VM target and performs real kernel-facing validation steps for one artifact.

## CLI inputs

- `--artifact <path>` (required)
- `--out <result.json>` (required)
- `--manifest <path>` (optional)
- `--functional-plan <path>` (optional, generated from manifest `functional_tests`)
- `--log-dir <dir>` (optional)
- `--attach-mode <disabled|best-effort|required>` (optional, default `best-effort`)
- `--probe-features <bool>` (optional, default `true`)
- `--set-map-max-entries <map>=<n|cpus>` (repeatable, generated from manifest `maps`)
- `--set-map-inner-ringbuf <map>=<bytes>` (repeatable, generated from manifest `maps`)

## Map fixups for runtime-sized maps

Some artifacts compile maps with `max_entries=0` and rely on their userspace
loader to size them before load — per-CPU arrays and ring buffers sized from
the CPU count are the common cases (Falco's `modern_bpf` probe does both).
Under a generic loader such objects fail with `EINVAL` on every kernel, which
is a loader-contract issue, not a kernel-compatibility signal.

Declaring the maps in the manifest makes the validator mirror the real
loader between `bpf_object` open and load:

```yaml
maps:
  - name: auxiliary_maps
    max_entries: cpus          # or a positive integer
  - name: ringbuf_maps
    max_entries: cpus
    inner_ringbuf_bytes: 8388608
```

- `max_entries: cpus` resolves to `libbpf_num_possible_cpus()` on the target
  kernel at load time.
- `inner_ringbuf_bytes` creates a `BPF_MAP_TYPE_RINGBUF` of that size and
  installs it as the inner-map prototype for an array-of-maps
  (`bpf_map__set_inner_map_fd`).

Fixups apply to the whole-object load and to isolated per-program load
probes. Per-fixup outcomes are emitted in the result JSON under
`map_fixups` and surfaced as target notes in the report.

## Execution phases

1. Capture host metadata (`uname`, timestamp).
2. Capture BTF metadata:
   - kernel BTF presence/size
   - artifact `.BTF` / `.BTF.ext` presence
3. Capability probing:
   - `bpftool feature probe` capture when available
   - custom map/program probe fallback
   - attach prerequisite checks
4. Open BPF object with libbpf.
5. Discover maps/program sections and initialize per-program attach/load state.
6. When feature probing is enabled, run isolated per-program load probes and capture bounded verifier logs.
7. Attempt whole-object load (`bpf_object__load`).
8. Attempt auto-attach for eligible sections based on attach mode.
9. If a functional plan is supplied, keep successful BPF links alive and run project-specific functional commands.
10. Emit JSON result and optional libbpf log file.


## Output contract

Primary output is a JSON document (currently `schema_version: validator.v0.4`) containing:

- `status` (`pass` / `fail`)
- `host` metadata
- `input` settings (artifact path, attach mode, probe mode)
- `btf` details
- `capabilities` details (bpftool + custom probes)
- `discovery` details (program/map counts and per-program attach status)
- per-program isolated load status (`load_status`, `load_errno`, `load_log`) when feature probing is enabled
- `load` status (`pass` / `fail`, error code/message)
- `attach` aggregate status and counters
- `functional` aggregate status and per-command result details
- `logs.libbpf` captured log stream

## Functional tests

Functional tests are declared in the manifest and converted by the Go runner into a strict validator plan. They are executed inside the VM while successful libbpf links are still alive. This lets a project supply a command such as a smoke script or event-capture harness that proves more than "the object loaded."

Example:

```yaml
functional_tests:
  - name: execve-stimulus-smoke
    command: "sh -c 'printf bpfcompat-functional-smoke'"
    timeout: 5s
    expect_exit_code: 0
    expect_stdout_contains: bpfcompat-functional-smoke
```

A required functional-test failure marks the target as `FUNCTIONAL_TEST_FAILURE`.
The `examples/functional-execve` fixture is the concrete event-capture example:
it attaches to `sys_enter_execve`, triggers `/bin/true` while the BPF link is
alive, and requires the expected marker to appear in `trace_pipe`.

## Attach behavior

- `disabled`: no attach attempts.
- `best-effort`: attach failures do not fail overall status if load passed.
- `required`: attach failures fail overall validator status.

## Failure evidence used upstream

Host-side classification consumes:

- load status/error code/message
- attach status/mode
- BTF presence signals
- libbpf/verifier text
- per-program isolated load failures and verifier log tails
- functional test status/output when supplied

This supports deterministic classification into codes such as:
`UNSUPPORTED_ATTACH_TYPE`, `UNSUPPORTED_MAP_TYPE`, `UNSUPPORTED_PROGRAM_TYPE`,
`MISSING_BTF`, `CORE_RELOCATION_FAILURE`, `POLICY_DENIED`,
`UNSUPPORTED_TRANSPORT`, and others.
