# Agent Load Policy

`bpfcompat agent apply --approve-load` requires a local load policy by default.
This keeps the cloud/control-plane decision separate from the final host-owner
approval.

For reviewed production-style loads, also pin the decision and artifact digest
that the operator approved:

```bash
bpfcompat agent apply \
  --artifact-name aegis \
  --approve-load \
  --load-policy /etc/bpfcompat/agent-load-policy.yaml \
  --expected-decision-id 20260606T120000Z-abcdef \
  --expected-sha256 <64-hex-artifact-sha256> \
  --require-approval-pins=true
```

The packaged `bpfcompat-agent-load.service` sets
`BPFCOMPAT_AGENT_REQUIRE_APPROVAL_PINS=true` by default. This denies host load
before policy evaluation if the reviewed decision id or selected artifact
SHA-256 is missing or mismatched.

The same packaged load service sets `BPFCOMPAT_AGENT_REQUIRE_MANIFEST=true` by
default. This requires `BPFCOMPAT_AGENT_MANIFEST_PATH` / `--manifest` to point
at a valid manifest before host load, so local policy and validator execution
receive explicit program and attach intent. Required manifests must declare at
least one program.

Before a reviewed host-load attempt, run:

```bash
bpfcompat agent preflight \
  --include-load \
  --load-policy /etc/bpfcompat/agent-load-policy.yaml \
  --workdir /var/lib/bpfcompat-agent \
  --out-dir /var/lib/bpfcompat-agent/selected \
  --probe-use-sudo=false
```

This checks local state, host probe readiness, policy parse/validation, and
validator binary availability without loading eBPF.

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

The ledger records selected version/digest, reviewed approval pins, manifest
intent summary, policy rule, audit trace, execution result, and previous
successful load metadata for rollback planning.

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
