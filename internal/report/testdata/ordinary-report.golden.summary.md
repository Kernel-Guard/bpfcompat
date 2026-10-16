# bpfcompat Compatibility Gate

**Status:** `fail`

**Verdict:** `INCOMPATIBLE`

**Coverage:** `incomplete` — at least one target produced no compatibility answer.

| Field | Value |
|---|---|
| Run ID | `20261014T120000Z-ordinary` |
| Artifact | `fentry_unlink.bpf.o` |
| Artifact source | `oci://ghcr.io/example/probes:1.2.3` |
| Artifact SHA-256 | `111111111111` |
| Validator | `bpfcompat-validator` |
| Validator SHA-256 | `555555555555` |
| Invocation SHA-256 | `333333333333` |
| Loader binary | `scap-open` |
| Loader SHA-256 | `444444444444` |
| Matrix | `ci-five` |
| Profiles | 5 total, 3 required |
| Required pass/fail | 1/2 |
| Optional pass/fail | 0/2 |

## Failure Classes

| Class | Targets |
|---|---:|
| `FUNCTIONAL_TEST_FAILURE` | 1 |
| `INFRA_ERROR` | 1 |
| `UNSUPPORTED_MAP_TYPE` | 1 |
| `UNSUPPORTED_PROGRAM_TYPE` | 1 |

## Compatibility Matrix

| Profile | Required | Status | Kernel | BTF | Functional | Class |
|---|---:|---|---|---|---|---|
| ubuntu-18.04-4.15 | true | `fail` | `4.15.0-213-generic` | `kernel:no` | `-` | `UNSUPPORTED_PROGRAM_TYPE` |
| ubuntu-20.04-5.4 | true | `fail` | `5.4.0-200-generic` | `kernel:yes` | `-` | `UNSUPPORTED_MAP_TYPE` |
| ubuntu-22.04-5.15 | true | `pass` | `5.15.0-186-generic` | `kernel:yes` | `pass` | `-` |
| debian-12-6.1 | false | `fail` | `6.1.0-25-amd64` | `-` | `fail` | `FUNCTIONAL_TEST_FAILURE` |
| rocky-9-5.14 | false | `error` | `-` | `-` | `-` | `-` |

## Failure Details

- `ubuntu-18.04-4.15`: `UNSUPPORTED_PROGRAM_TYPE` - Program section "fentry/do_unlinkat" requires fentry/fexit-style tracing support not available on kernel 4.15.
- `ubuntu-20.04-5.4`: `UNSUPPORTED_MAP_TYPE` - Map "events" failed to create on this kernel (-22); likely an unsupported map type.
- `debian-12-6.1`: `FUNCTIONAL_TEST_FAILURE` - Functional test unlink-smoke failed with exit status 1.
- `rocky-9-5.14`: `UNCLASSIFIED_FAILURE` - vm boot timed out after 300s

## Suggested Next Steps

- `FUNCTIONAL_TEST_FAILURE`: inspect the functional command output and project-specific test assets; the artifact loaded but did not satisfy the integration test.
- `UNSUPPORTED_MAP_TYPE`: use a map-compatible fallback for older kernels, for example perfbuf instead of ringbuf where needed.
- `UNSUPPORTED_PROGRAM_TYPE`: ship an older-kernel-compatible variant, for example avoid fentry/fexit on kernels before 5.5.

## Report Notes

- Compatibility check failed on at least one required profile.
- coverage incomplete: at least one optional target produced no compatibility answer; required targets were all established. See targets[].verdict and targets[].environment.
