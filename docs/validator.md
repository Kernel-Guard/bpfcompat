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
