#!/usr/bin/env bash
set -euo pipefail

BIN="${BPFCOMPAT_BIN:-./bin/bpfcompat}"
EVIDENCE_ROOT="${BPFCOMPAT_PRODUCTION_RUNTIME_DRILL_EVIDENCE_DIR:-evidence/production-runtime-drills}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
out_dir="${EVIDENCE_ROOT}/${timestamp}"
workdir="${out_dir}/workdir"
artifact_name="${BPFCOMPAT_DRILL_ARTIFACT_NAME:-aegis}"
agent_id="${BPFCOMPAT_DRILL_AGENT_ID:-host-01}"
policy_path="${out_dir}/agent-load-policy.yaml"
pin_path="${out_dir}/lab-pins/${artifact_name}"

if [[ ! -x "$BIN" ]]; then
  echo "[production-runtime-drill] missing binary: $BIN (run make build)" >&2
  exit 1
fi

mkdir -p "$out_dir" "$workdir" "$(dirname "$pin_path")"

cat > "${workdir}/agent-load-ledger.jsonl" <<EOF
{"schema_version":"agent_load_ledger.v0.1","entry_id":"seed-load-v1","created_at":"2026-06-03T00:00:00Z","operation":"load","status":"pass","agent_id":"${agent_id}","tenant":"acme","project":"aegis-bpf","artifact_name":"${artifact_name}","selected_version":"v1","selected_sha256":"sha-v1","artifact_path":"/var/lib/bpfcompat-agent/selected/${artifact_name}-v1.o","target_profile":"ubuntu-24.04-6.8","load_approved":true}
{"schema_version":"agent_load_ledger.v0.1","entry_id":"seed-load-v2","created_at":"2026-06-03T00:01:00Z","operation":"load","status":"pass","agent_id":"${agent_id}","tenant":"acme","project":"aegis-bpf","artifact_name":"${artifact_name}","selected_version":"v2","selected_sha256":"sha-v2","artifact_path":"/var/lib/bpfcompat-agent/selected/${artifact_name}-v2.o","target_profile":"ubuntu-24.04-6.8","load_approved":true,"previous_loaded_version":"v1","previous_loaded_sha256":"sha-v1","previous_loaded_artifact_path":"/var/lib/bpfcompat-agent/selected/${artifact_name}-v1.o","rollback_hint":"previous successful load was ${artifact_name}@v1 (sha-v1)"}
EOF

cat > "$policy_path" <<EOF
schema_version: agent_load_policy.v0.1
default_action: allow
revoked_agents:
  - ${agent_id}
EOF

printf 'lab pin for unload drill\n' > "$pin_path"

"$BIN" agent rollback \
  --workdir "$workdir" \
  --artifact-name "$artifact_name" \
  --record=true \
  --json > "${out_dir}/rollback-drill.json"

"$BIN" agent unload \
  --workdir "$workdir" \
  --artifact-name "$artifact_name" \
  --pin-path "$pin_path" \
  --allow-non-bpffs \
  --execute \
  --json > "${out_dir}/unload-drill.json"

"$BIN" agent revocation-drill \
  --workdir "$workdir" \
  --agent-id "$agent_id" \
  --artifact-name "$artifact_name" \
  --load-policy "$policy_path" \
  --json > "${out_dir}/revocation-drill.json"

"$BIN" agent ledger \
  --workdir "$workdir" \
  --artifact-name "$artifact_name" \
  --limit 20 \
  --json > "${out_dir}/agent-load-ledger.json"

rollback_status="$(jq -r '.status' "${out_dir}/rollback-drill.json")"
rollback_previous="$(jq -r '.previous.selected_version // "-"' "${out_dir}/rollback-drill.json")"
unload_status="$(jq -r '.status' "${out_dir}/unload-drill.json")"
unload_removed="$(jq -r '.removed' "${out_dir}/unload-drill.json")"
revocation_status="$(jq -r '.status' "${out_dir}/revocation-drill.json")"
revocation_action="$(jq -r '.decision.action' "${out_dir}/revocation-drill.json")"
ledger_entries="$(jq -r 'length' "${out_dir}/agent-load-ledger.json")"

cat > "${out_dir}/production-runtime-drill.md" <<EOF
# Production Runtime Loader Drill

Generated: ${timestamp}

This is a controlled local operational drill. It does not load eBPF on the
host kernel. It proves rollback planning, unload command safety, and local
host-identity revocation evidence using the production runtime agent CLI.

## Results

| Drill | Result | Evidence |
|---|---|---|
| Rollback planning | ${rollback_status}; previous=${rollback_previous} | rollback-drill.json |
| Unload execution | ${unload_status}; removed=${unload_removed}; lab pin only | unload-drill.json |
| Host identity revocation | ${revocation_status}; decision=${revocation_action} | revocation-drill.json |
| Ledger evidence | entries=${ledger_entries} | agent-load-ledger.json |

## Scope Boundary

- No production customer identity provider was configured.
- No live eBPF program was loaded on the host.
- The unload drill used a temporary lab pin with \`--allow-non-bpffs\`.
- A customer production claim still requires running the same drills with the
  customer's issued host identity, revocation process, and approved pin paths.

## Reproduce

\`\`\`bash
make production-runtime-drill
\`\`\`
EOF

echo "[production-runtime-drill] wrote ${out_dir}/production-runtime-drill.md"
