# bpfcompat evidence schema (v0.1)

The compatibility report is bpfcompat's core artifact: a portable, machine-readable
record of whether a compiled eBPF object loads (and attaches) on each target kernel,
**with a classified reason when it does not**. The classification taxonomy and this
stable format — not the VM layer — are what make the evidence reusable across CI,
dashboards, and audits.

- Source of truth: [`pkg/schema/report_v0_1.go`](../pkg/schema/report_v0_1.go)
- `schema_version`: **`v0.1`**
- Stability policy: see [schema-stability-contract.md](schema-stability-contract.md)
  (additive within a major; breaking changes bump the major; consumers gate on
  `schema_version` and ignore unknown fields/enum values).

## Top level

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | Always present. Gate on this. |
| `run` | object | `{ id, started_at }` |
| `artifact` | object | `{ path, basename, sha256, size_bytes }` — the validated `.bpf.o` |
| `matrix` | object | `{ path, name?, profiles[] }` — the kernel set requested |
| `targets[]` | array | one entry per kernel profile (below) |
| `summary` | object | `{ status, notes[]? }` — roll-up verdict (`pass`/`fail`) |
| `paths` | object | `{ run_dir, json, markdown? }` |

## `targets[]` — per-kernel result

| Field | Type | Notes |
|---|---|---|
| `profile_id` | string | e.g. `ubuntu-22.04-5.15` |
| `required` | bool | whether a failure here fails the gate |
| `status` | string | `pass` \| `fail` \| `partial` \| `infra_error` |
| `profile` / `host` | object | `{ distro, version, kernel_family, kernel, arch }` (requested vs actual) |
| `validation` | object | `{ load_status, load_error_code, load_error, attach_mode, attach_status, attach_attempted, attach_passed, attach_failed }` |
| `functional` | object | optional behavior tests: `{ status, tests[] }` |
| `btf` | object | `{ kernel_btf_available, artifact_has_btf, artifact_has_btf_ext }` |
| `failed_stage` | string | `load` \| `attach` \| `functional` |
| `classification_code` | enum | **why it failed** — see taxonomy below |
| `classification_confidence` | string | `high` \| `medium` \| `low` |
| `classification_reason` | string | human-readable explanation |
| `started_at` / `finished_at` / `duration_ms` | — | timing |
| `validator_exit` / `notes[]` | — | validator detail |

### Sanitized (public) reports omit host internals

When `BPFCOMPAT_API_REDACT_RUNTIME_DETAILS` is set (the public demo posture), the
server strips host-revealing fields before returning a report: `vm_run_dir`,
`qemu_command`, `serial_log`, `validator_result`, and any absolute audit paths.
Self-hosted runs (your own CI, the CLI) keep the full detail locally.

## Classification taxonomy

The stable set of `classification_code` values, each with the remediation bpfcompat
suggests. This is the part that turns a raw libbpf/verifier error into an actionable
cause — and the part that compounds in value as more real-world failures are catalogued.

| Code | Meaning | Typical remediation |
|---|---|---|
| `MISSING_BTF` | Kernel has no embedded BTF for CO-RE | Non-CO-RE fallback, external BTF (BTFHub), or drop the CO-RE dependency for that band |
| `CORE_RELOCATION_FAILURE` | A CO-RE relocation could not be applied | Validate against the target BTF layout; ship a profile-specific variant where field layouts diverge |
| `UNSUPPORTED_PROGRAM_TYPE` | Program type not available on this kernel | Older-kernel-compatible variant (e.g. avoid fentry/fexit before 5.5) |
| `UNSUPPORTED_MAP_TYPE` | Map type not available (e.g. ringbuf < 5.8) | Map-compatible fallback (e.g. perfbuf instead of ringbuf) |
| `UNSUPPORTED_ATTACH_TYPE` | Attach/hook not available | Change the hook strategy, or make attach optional in the manifest |
| `POLICY_DENIED` | Host policy blocked load/attach | Check kernel lockdown, unprivileged-BPF sysctl, capabilities, runner policy |
| `CAPABILITY_FAILURE` | A probed helper/map/prog capability failed | Compare against the target profile; select a compatible variant |
| `VERIFIER_REJECTION` | The verifier rejected the program | Inspect the validator/libbpf log in the report |
| `FUNCTIONAL_TEST_FAILURE` | Loaded, but a behavior test failed | Inspect the functional command output / project test assets |

Consumers should treat unknown codes as a generic failure (forward-compatible).

## Minimal example

```json
{
  "schema_version": "v0.1",
  "run": { "id": "20260611T194515Z-33a59b", "started_at": "2026-06-11T19:46:48Z" },
  "artifact": { "basename": "bpf_probe.o", "sha256": "4895…2722", "size_bytes": 1127120 },
  "matrix": { "name": "falco-modern-bpf-proof", "profiles": ["ubuntu-20.04-5.4", "ubuntu-24.04-6.8"] },
  "summary": { "status": "pass" },
  "targets": [
    { "profile_id": "ubuntu-24.04-6.8", "required": true, "status": "pass",
      "btf": { "kernel_btf_available": true } },
    { "profile_id": "ubuntu-20.04-5.4", "required": false, "status": "fail",
      "failed_stage": "load", "classification_code": "UNSUPPORTED_MAP_TYPE",
      "classification_confidence": "high",
      "classification_reason": "map ringbuf_maps failed to create (-22); ring buffer requires kernel >= 5.8" }
  ]
}
```
