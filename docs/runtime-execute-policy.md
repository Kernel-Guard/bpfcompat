# Runtime Execute Policy (API)

`/api/runtime/execute` can enforce explicit allow/deny rules with:

- `BPFCOMPAT_API_RUNTIME_EXECUTE_POLICY_PATH`
- `BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_POLICY=true` (fail closed if path is missing)

## Policy Schema

```json
{
  "schema_version": "runtime_execute_policy.v0.1",
  "default_action": "deny",
  "rules": [
    {
      "name": "allow-acme-execsnoop",
      "action": "allow",
      "tenants": ["acme"],
      "projects": ["demo"],
      "artifacts": ["execsnoop"],
      "profiles": ["ubuntu-24.04-6.8"],
      "kernel_min": "6.8.0",
      "kernel_max": "6.9.99",
      "program_types": ["TRACING"],
      "attach_kinds": ["TRACEPOINT"],
      "require_verified_history": true
    }
  ]
}
```

## Rule Fields

- `action`: `allow` or `deny`
- `tenants`, `projects`, `artifacts`, `profiles`:
  - exact match lists
  - `*` wildcard supported
- `kernel_min`, `kernel_max`:
  - compared against probed host kernel release
  - format: `<major>.<minor>[.<patch>]`
- `program_types`, `attach_kinds`:
  - evaluated from selected manifest programs
- `require_verified_history`:
  - match against runtime history verification status

If no rule matches, `default_action` is applied.

## Notes

- Policy enforcement occurs before host load.
- Denied policy decisions are audited as `runtime_execute_denied`.
- A deny response returns `403` with policy rule metadata.
