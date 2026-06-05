# Production Runtime Agent Alpha

This alpha moves runtime delivery toward the production-safe shape:

`host probe -> control-plane decision -> verified fetch -> local audit`

It is intentionally **fetch-only by default**. It does not load eBPF on the
host unless an operator explicitly adds load flags after a separate review.

## Install

Build the binary:

```bash
make build
```

Install the systemd units:

```bash
sudo scripts/install-agent-systemd.sh
```

Edit `/etc/bpfcompat/agent.env`:

```bash
sudo editor /etc/bpfcompat/agent.env
sudo chmod 0600 /etc/bpfcompat/agent.env
```

Required values:

- `BPFCOMPAT_AGENT_API_URL`
- `BPFCOMPAT_AGENT_TENANT`
- `BPFCOMPAT_AGENT_PROJECT`
- `BPFCOMPAT_AGENT_ARTIFACT_NAME`
- `BPFCOMPAT_AGENT_REGISTRY_TOKEN`

## Run Once

```bash
sudo systemctl start bpfcompat-agent.service
sudo journalctl -u bpfcompat-agent.service -n 100 --no-pager
sudo cat /var/lib/bpfcompat-agent/last-apply.json
sudo -u bpfcompat-agent /usr/local/bin/bpfcompat agent status \
  --path /var/lib/bpfcompat-agent/last-apply.json
```

Expected result:

- host probe is included
- selected artifact metadata is included
- fetched artifact path is under `/var/lib/bpfcompat-agent/selected`
- SHA-256 verification succeeds
- `load_skipped` is present unless explicit load approval was configured
- `bpfcompat agent status` reports `healthy` for a fetch-only verified run

Inspect reviewed load history:

```bash
sudo -u bpfcompat-agent /usr/local/bin/bpfcompat agent ledger \
  --workdir /var/lib/bpfcompat-agent
```

## Enable Schedule

```bash
sudo systemctl enable --now bpfcompat-agent.timer
systemctl list-timers bpfcompat-agent.timer
```

Default cadence: every 5 minutes after boot.

## Security Posture

The alpha unit uses a dedicated `bpfcompat-agent` OS user and systemd
hardening:

- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `PrivateTmp=true`
- empty `CapabilityBoundingSet`
- writable state limited to `/var/lib/bpfcompat-agent`

This is suitable for fetch-only runtime delivery proof. Production host
loading still requires:

- per-host identity and revocation
- pinned trusted signing keys or KMS-backed trust root
- local runtime policy
- rollback/unload tracking
- canary and kill-switch drills
- separate reviewed host-load service/drop-in

## Host Loading

Do not enable host loading in the public demo.

Host loading is separated into `bpfcompat-agent-load.service`. It is not tied
to the timer and must be started explicitly after local policy review:

```bash
sudo cp /etc/bpfcompat/agent-load-policy.example.yaml \
  /etc/bpfcompat/agent-load-policy.yaml
sudo editor /etc/bpfcompat/agent-load-policy.yaml
sudo editor /etc/bpfcompat/agent-load.env
sudo systemctl start bpfcompat-agent-load.service
sudo /usr/local/bin/bpfcompat agent status \
  --path /var/lib/bpfcompat-agent/last-load.json
sudo /usr/local/bin/bpfcompat agent ledger \
  --workdir /var/lib/bpfcompat-agent
```

Approved host loading now requires a local agent load policy by default
(`BPFCOMPAT_AGENT_REQUIRE_LOAD_POLICY=true`). The default example policy denies
everything until the operator adds a narrow allow rule. Policy rules can match:

- agent identity (`agents`, plus top-level `allowed_agents`/`revoked_agents`)
- tenant/project/artifact
- target profile and host kernel range
- signed-history status
- optional manifest program types and attach kinds

Each approved, denied, or failed host-load attempt is appended to
`/var/lib/bpfcompat-agent/agent-load-ledger.jsonl`. The ledger records the
selected artifact digest, policy rule, audit trace, execution result, and the
previous successful load for rollback planning.

## Production Drills

Run these drills before calling a deployment production-ready.

Generate a controlled local evidence package without loading eBPF on the host:

```bash
make production-runtime-drill
```

Outputs are written under:

```text
evidence/production-runtime-drills/<timestamp>/production-runtime-drill.md
```

Rollback drill:

```bash
sudo /usr/local/bin/bpfcompat agent rollback \
  --workdir /var/lib/bpfcompat-agent \
  --artifact-name aegis \
  --record
```

If the plan is ready and the operator has approved the previous version:

```bash
sudo /usr/local/bin/bpfcompat agent rollback \
  --workdir /var/lib/bpfcompat-agent \
  --artifact-name aegis \
  --load-policy /etc/bpfcompat/agent-load-policy.yaml \
  --execute
```

Unload drill for explicitly pinned BPF objects:

```bash
sudo /usr/local/bin/bpfcompat agent unload \
  --workdir /var/lib/bpfcompat-agent \
  --artifact-name aegis \
  --pin-path /sys/fs/bpf/aegis \
  --record
```

Only add `--execute` after confirming the pin path. The command refuses paths
outside `/sys/fs/bpf` unless `--allow-non-bpffs` is supplied for tests/labs.

Revocation drill:

```bash
sudo /usr/local/bin/bpfcompat agent revocation-drill \
  --workdir /var/lib/bpfcompat-agent \
  --agent-id host-01 \
  --artifact-name aegis \
  --load-policy /etc/bpfcompat/agent-load-policy.yaml
```

The drill passes only if local policy denies the supplied host identity. This
proves per-host revocation works before an incident.

This is the Production Runtime Agent Alpha boundary: fetch-only automation is
safe to schedule; host loading is a separate reviewed action with local policy
and a rollback/audit ledger. The included rollback, unload, and revocation
drills make those controls testable. A deployment still needs customer-specific
identity issuance/rotation and real incident drills before it should be called
generally production-ready.
