# Agent Load Policy

`bpfcompat agent apply --approve-load` requires a local load policy by default.
This keeps the cloud/control-plane decision separate from the final host-owner
approval.

```yaml
schema_version: agent_load_policy.v0.1
default_action: deny
allowed_agents: ["host-01"]
revoked_agents: []
rules:
  - name: allow-acme-aegis-host-01
    action: allow
    agents: ["host-01"]
    tenants: ["acme"]
    projects: ["aegis-bpf"]
    artifacts: ["aegis"]
    profiles: ["ubuntu-24.04-6.8"]
    kernel_min: "6.8.0"
    kernel_max: "6.8.99"
    require_verified_history: true
```

Rule fields:

- `agents`, `tenants`, `projects`, `artifacts`, `profiles`: exact match or `*`
- `kernel_min`, `kernel_max`: compared with the probed host kernel release
- `program_types`, `attach_kinds`: require `--manifest` so the agent can inspect intended load/attach behavior
- `require_verified_history`: requires signed artifact history verification

Top-level `revoked_agents` denies before rules run. Top-level
`allowed_agents` denies any agent not listed.

Approved, denied, and failed host-load attempts are appended to:

```text
<workdir>/agent-load-ledger.jsonl
```

Inspect it with:

```bash
bpfcompat agent ledger --workdir /var/lib/bpfcompat-agent
```

The ledger records selected version/digest, policy rule, audit trace, execution
result, and previous successful load metadata for rollback planning.

Operational drills:

```bash
bpfcompat agent rollback --workdir /var/lib/bpfcompat-agent --artifact-name aegis
bpfcompat agent unload --workdir /var/lib/bpfcompat-agent --pin-path /sys/fs/bpf/aegis
bpfcompat agent revocation-drill --agent-id host-01 --load-policy /etc/bpfcompat/agent-load-policy.yaml
```

`rollback --execute` reuses the same `agent apply --approve-load` path and
therefore rechecks selection, SHA-256, signed history, and local load policy.
`unload --execute` removes only an explicitly supplied pin path and refuses
non-`/sys/fs/bpf` paths unless a lab override is provided.
