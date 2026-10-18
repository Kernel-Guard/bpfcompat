# bpfcompat Compatibility Report

- Run ID: `20261014T120000Z-ordinary`
- Started At: `2026-10-14T12:00:00Z`
- Status: `fail`
- Verdict: `INCOMPATIBLE`
- Coverage: `incomplete` (at least one target produced no compatibility answer)
- Artifact: `examples/build/fentry_unlink.bpf.o`
- Artifact Source: `oci://ghcr.io/example/probes:1.2.3`
- Artifact Source Digest: `sha256:2222222222222222222222222222222222222222222222222222222222222222`
- Artifact SHA-256: `1111111111111111111111111111111111111111111111111111111111111111`
- Validator: `bpfcompat-validator`
- Validator SHA-256: `5555555555555555555555555555555555555555555555555555555555555555`
- Command invocation SHA-256: `3333333333333333333333333333333333333333333333333333333333333333`
- Command expected exit code: `0`
- Command binary: `scap-open`
- Command binary SHA-256: `4444444444444444444444444444444444444444444444444444444444444444`
- Matrix: `matrices/ci-five.yaml`
- Profiles: `ubuntu-18.04-4.15, ubuntu-20.04-5.4, ubuntu-22.04-5.15, debian-12-6.1, rocky-9-5.14`

## Targets

| Profile | Profile Env | Host Kernel | Status | Failed Stage | Required | BTF | Functional | Classification | Confidence | Infra Error |
|---|---|---|---|---|---:|---|---|---|---|---|
| Ubuntu 18.04 (4.15) [`ubuntu-18.04-4.15`] | `ubuntu 18.04 kfamily=4.15 kernel=4.15.0-213-generic arch=x86_64` | `4.15.0-213-generic` | `fail` | `load` | `true` | `kernel_btf:no` | `-` | `UNSUPPORTED_PROGRAM_TYPE` | `high` | `` |
| Ubuntu 20.04 (5.4) [`ubuntu-20.04-5.4`] | `ubuntu 20.04 kernel=5.4.0-200-generic arch=x86_64` | `-` | `fail` | `load` | `true` | `kernel_btf:yes` | `-` | `UNSUPPORTED_MAP_TYPE` | `high` | `` |
| Ubuntu 22.04 (5.15) [`ubuntu-22.04-5.15`] | `ubuntu 22.04 kernel=5.15.0-186-generic arch=x86_64` | `5.15.0-186-generic` | `pass` | `` | `true` | `kernel_btf:yes` | `pass` | `` | `` | `` |
| Debian 12 (6.1) [`debian-12-6.1`] | `debian 12 kernel=6.1.0-25-amd64 arch=x86_64` | `-` | `fail` | `` | `false` | `` | `fail` | `FUNCTIONAL_TEST_FAILURE` | `high` | `` |
| `rocky-9-5.14` | `rocky 9 kfamily=5.14 arch=x86_64` | `-` | `error` | `` | `false` | `` | `-` | `` | `` | `vm boot timed out after 300s` |

## Target Details

### Ubuntu 18.04 (4.15) [`ubuntu-18.04-4.15`]

- Status: `fail`
- Profile Env: `ubuntu 18.04 kfamily=4.15 kernel=4.15.0-213-generic arch=x86_64`
- Host Env: `ubuntu 18.04 kernel=4.15.0-213-generic arch=x86_64`
- Failed Stage: `load`
- Load: `fail` (code=-22)
- Attach: `skipped` (mode=best-effort attempted=0 passed=0 failed=0)
- Classification: `UNSUPPORTED_PROGRAM_TYPE` (`high`)
- Reason: Program section "fentry/do_unlinkat" requires fentry/fexit-style tracing support not available on kernel 4.15.
- Validator Result: `reports/run/ubuntu-18.04-4.15/validator-result.json`
- Serial Log: `reports/run/ubuntu-18.04-4.15/serial.log`
- Notes:
  - execution transport: virtme-ng
  - capability map.ringbuf: unsupported (code=-22)
  - program load failure: name=handle_unlink section=fentry/do_unlinkat errno=-22
  - program load verifier tail (handle_unlink): 0: R1 type=ctx expected=fp processed 12 insns (limit 1000000) max_states_per_insn 0
  - program load verifier tail (handle_exec_core): ...ion <byte_off> [5] struct task_struct.pid (0:0 @ offset 0) processed 1 insns (limit 1000000) -- END PROG LOAD LOG -- libbpf: prog 'handle_exec_core': failed to load: -22
  - validator load error: code=-22 message=Invalid argument
  - classification: UNSUPPORTED_PROGRAM_TYPE (high)
  - remediation: Ship a fallback artifact using tracepoint/kprobe program sections for kernels below 5.5.

### Ubuntu 20.04 (5.4) [`ubuntu-20.04-5.4`]

- Status: `fail`
- Profile Env: `ubuntu 20.04 kernel=5.4.0-200-generic arch=x86_64`
- Failed Stage: `load`
- Load: `fail` (code=-22)
- Attach: `` (mode= attempted=0 passed=0 failed=0)
- Classification: `UNSUPPORTED_MAP_TYPE` (`high`)
- Reason: Map "events" failed to create on this kernel (-22); likely an unsupported map type.
- Notes:
  - map type hint: events uses BPF_MAP_TYPE_RINGBUF (kernel 5.8+)
  - classification: UNSUPPORTED_MAP_TYPE (high)
  - remediation: Confirm the map type used by this map is supported on this kernel/profile, or ship a fallback artifact. If the artifact's own loader sizes this map at runtime (max_entries=0 in the object), declare it under `maps:` in the manifest instead.

### Ubuntu 22.04 (5.15) [`ubuntu-22.04-5.15`]

- Status: `pass`
- Profile Env: `ubuntu 22.04 kernel=5.15.0-186-generic arch=x86_64`
- Host Env: `ubuntu 22.04 kernel=5.15.0-186-generic arch=x86_64`
- Load: `pass` (code=0)
- Attach: `pass` (mode=best-effort attempted=2 passed=2 failed=0)
- Functional: `pass`
  - `unlink-smoke`: `pass` exit=0 expected=0 timeout=30s required=true

### Debian 12 (6.1) [`debian-12-6.1`]

- Status: `fail`
- Profile Env: `debian 12 kernel=6.1.0-25-amd64 arch=x86_64`
- Functional: `fail`
  - `unlink-smoke`: `fail` exit=1 expected=0 timeout=30s required=true
    - Error: exit status 1 (expected 0)
- Classification: `FUNCTIONAL_TEST_FAILURE` (`high`)
- Reason: Functional test unlink-smoke failed with exit status 1.
- Notes:
  - functional test "unlink-smoke" failed: exit status 1 (expected 0)

### `rocky-9-5.14`

- Status: `error`
- Profile Env: `rocky 9 kfamily=5.14 arch=x86_64`


## Notes

- Compatibility check failed on at least one required profile.
- coverage incomplete: at least one optional target produced no compatibility answer; required targets were all established. See targets[].verdict and targets[].environment.
